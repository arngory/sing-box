//go:build windows

package boxdd

import (
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// utf16Bytes is a REG_SZ's data: UTF-16, little-endian, its NUL included.
func utf16Bytes(text string) []byte {
	var data []byte
	for _, unit := range append(utf16.Encode([]rune(text)), 0) {
		data = binary.LittleEndian.AppendUint16(data, unit)
	}
	return data
}

// sessionChange: the owner's new session goes to the platform, which sets the proxy for it (replaceOwnerTokenLocked),
// and is kept as the owner's; the daemon neither resets nor sets anything itself.
func sessionChange(t *testing.T, d *Daemon, expect func(what string, want ...string)) {
	t.Helper()
	if err := d.handlePlatformSessionChange(windows.WTS_SESSION_LOGON, 7); err != nil {
		t.Fatal(err)
	}
	expect("a session change", "session 7 of 1000")
	if state, err := loadOwnerState(); err != nil || state.SessionID != 7 {
		t.Fatalf("the owner %+v: %v", state, err)
	}
}

// fakeSetter is a system proxy that sets nothing and notes what it was asked; failEnable: Enable fails.
type fakeSetter struct {
	on, failEnable bool
	calls          *[]string
}

func (s *fakeSetter) IsEnabled() bool { return s.on }

func (s *fakeSetter) Enable() error {
	*s.calls = append(*s.calls, "enable")
	if s.failEnable {
		return os.ErrPermission
	}
	s.on = true
	return nil
}

func (s *fakeSetter) Disable() error {
	*s.calls = append(*s.calls, "clear")
	s.on = false
	return nil
}

// The owner's own proxy settings: kept before the daemon's goes on, put back after it goes off (turned off, or the
// core stopped); kept on the disk, so a crash's are put back as the owner is set and before the next start; put back
// after an Enable that failed; kept for another try where they could not be written; the clear alone where none were
// kept.
func TestNekoOwnerProxyKept(t *testing.T) {
	previousDirectory, previousListen := workingDirectory, listenAddress
	previousRead, previousWrite, previousNotify := readProxyValues, writeProxyValues, notifyProxyChanged
	workingDirectory = t.TempDir()
	// development mode: the operations run as this process, not impersonated
	listenAddress = "127.0.0.1:1"
	t.Cleanup(func() {
		workingDirectory, listenAddress = previousDirectory, previousListen
		readProxyValues, writeProxyValues, notifyProxyChanged = previousRead, previousWrite, previousNotify
	})
	var calls []string
	// the owner's registry: their own proxy (corp), until the daemon's (ours) is on
	const corp, ours, moved, foreign = "http://corp.example:3128", "http://127.0.0.1:2080", "http://127.0.0.1:2081",
		"http://127.0.0.1:3128"
	label := map[string]string{corp: "corp", ours: "ours", moved: "moved", foreign: "foreign"}
	current := corp
	failWrite := false
	readProxyValues = func() (*savedSystemProxy, error) {
		calls = append(calls, "read "+label[current])
		var enabled uint32
		if current != corp {
			enabled = 1
		}
		return &savedSystemProxy{Values: []savedProxyValue{
			{Key: internetSettingsKey, Name: "ProxyEnable", Type: registry.DWORD, Data: binary.LittleEndian.AppendUint32(nil, enabled)},
			{Key: internetSettingsKey, Name: "ProxyServer", Type: registry.SZ, Data: utf16Bytes(current)},
		}}, nil
	}
	writeProxyValues = func(saved *savedSystemProxy) error {
		if failWrite {
			calls = append(calls, "write failed")
			return os.ErrPermission
		}
		current = utf16String(saved.Values[1].Data)
		calls = append(calls, "write "+label[current])
		return nil
	}
	notifyProxyChanged = func() error {
		calls = append(calls, "notify")
		return nil
	}
	expect := func(what string, want ...string) {
		t.Helper()
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("%s: %q, want %q", what, calls, want)
		}
		calls = nil
	}
	kept := func() bool {
		_, err := os.Stat(savedSystemProxyPath("1000"))
		return err == nil
	}
	platform := func(setter *fakeSetter) *windowsPlatformInterface {
		setter.calls = &calls
		return &windowsPlatformInterface{systemProxyEnabled: true, ownerUserID: "1000", systemProxy: setter,
			systemProxyServer: ours}
	}

	p := platform(&fakeSetter{})
	if err := p.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on", "read corp", "enable")
	if !kept() {
		t.Fatal("not kept on the disk")
	}
	current = ours
	if err := p.SetSystemProxyEnabled(false); err != nil {
		t.Fatal(err)
	}
	expect("off", "clear", "write corp", "notify")
	if kept() {
		t.Fatal("still kept after it was put back")
	}

	// on again, and the daemon crashes with it on: the owner set again puts theirs back
	if err := p.SetSystemProxyEnabled(true); err != nil {
		t.Fatal(err)
	}
	expect("on again", "read corp", "enable")
	current = ours
	// the next daemon: no system proxy yet as the owner is set
	again := &windowsPlatformInterface{systemProxyEnabled: true}
	if err := again.PrepareOwner(peerIdentity{UserID: "1000"}); err != nil {
		t.Fatal(err)
	}
	expect("the owner after a crash", "write corp", "notify")
	if kept() {
		t.Fatal("a crash's still kept")
	}

	// kept and the proxy turned on before the owner was set (a crash, the core restored): put back, then kept anew
	again.systemProxy = &fakeSetter{calls: &calls}
	if err := again.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on", "read corp", "enable")
	current = ours
	restarted := platform(&fakeSetter{})
	if err := restarted.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on after a crash", "write corp", "notify", "read corp", "enable")
	current = ours

	// a restore that fails after this call turned the proxy off: said, the settings kept
	failWrite = true
	if err := restarted.ResetPlatformOptions(); err == nil {
		t.Fatal("a failed restore said nothing")
	}
	expect("a failed restore", "clear", "write failed")
	if !kept() {
		t.Fatal("not kept for another try")
	}
	// stale ones that cannot be put back (the proxy was not on here): told, not failed, kept
	if err := restarted.ResetPlatformOptions(); err != nil {
		t.Fatal(err)
	}
	expect("a stale one failed", "write failed")
	// the next Enable with the restore failing still: the old ones stay kept, the proxy goes on
	stale := platform(&fakeSetter{})
	if err := stale.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on with a failed restore", "write failed", "enable")
	if !kept() {
		t.Fatal("the old ones not kept")
	}
	// its stop: the clear, the restore failing again is told, not failed (the core stops), the old ones still kept
	if err := stale.ResetPlatformOptions(); err != nil {
		t.Fatalf("the stop failed on old kept settings: %v", err)
	}
	expect("the stop with a failed restore", "clear", "write failed")
	if !kept() {
		t.Fatal("the old ones not kept")
	}
	failWrite = false
	if err := stale.ResetPlatformOptions(); err != nil {
		t.Fatal(err)
	}
	expect("tried again", "write corp", "notify")
	if kept() {
		t.Fatal("still kept after it was put back")
	}

	// a kept file that is not settings, after a crash (the daemon's proxy in the registry): set aside as .bad as the
	// proxy goes on, nothing kept anew (what the registry has is the daemon's), and one stop clears alone
	if err := os.WriteFile(savedSystemProxyPath("1000"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	current = ours
	broken := platform(&fakeSetter{})
	if err := broken.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on with a broken file", "read ours", "enable")
	if _, err := os.Stat(savedSystemProxyPath("1000") + ".bad"); err != nil {
		t.Fatalf("not set aside: %v", err)
	}
	if kept() {
		t.Fatal("kept anew after a broken file")
	}
	if err := broken.ResetPlatformOptions(); err != nil {
		t.Fatalf("the stop after a broken file: %v", err)
	}
	expect("the stop after a broken file", "clear")
	if err := os.Remove(savedSystemProxyPath("1000") + ".bad"); err != nil {
		t.Fatal(err)
	}

	// the same with the owner's own proxy in the registry (they set it again by hand): set aside, theirs kept anew and
	// put back
	if err := os.WriteFile(savedSystemProxyPath("1000"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	current = corp
	fixed := platform(&fakeSetter{})
	if err := fixed.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on with a broken file and theirs", "read corp", "enable")
	if !kept() {
		t.Fatal("theirs not kept anew")
	}
	current = ours
	if err := fixed.ResetPlatformOptions(); err != nil {
		t.Fatal(err)
	}
	expect("the stop after it", "clear", "write corp", "notify")

	// none kept and the daemon's own proxy in the registry (a crash's, the file lost): not kept as the owner's
	current = ours
	lost := platform(&fakeSetter{})
	if err := lost.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on over the daemon's own", "read ours", "enable")
	if kept() {
		t.Fatal("the daemon's own proxy kept as the owner's")
	}
	if err := lost.ResetPlatformOptions(); err != nil {
		t.Fatal(err)
	}
	expect("the stop over the daemon's own", "clear")
	current = corp

	// the daemon's own proxy on another port (the local proxy's changed since a crash): told by the last server set,
	// not kept either
	if err := saveLastSystemProxyServer("1000", moved); err != nil {
		t.Fatal(err)
	}
	current = moved
	movedPort := platform(&fakeSetter{})
	if err := movedPort.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on over a crash's on another port", "read moved", "enable")
	if kept() {
		t.Fatal("a daemon's proxy on another port kept as the owner's")
	}
	if last := loadLastSystemProxyServer("1000"); last != ours {
		t.Fatalf("the last server set %q", last)
	}
	if err := movedPort.ResetPlatformOptions(); err != nil {
		t.Fatal(err)
	}
	expect("its stop", "clear")

	// another local proxy of the user's (another client, an agent), not one the daemon set: kept and put back
	if err := os.Remove(lastSystemProxyServerPath("1000")); err != nil {
		t.Fatal(err)
	}
	current = foreign
	theirs := platform(&fakeSetter{})
	if err := theirs.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on over another local proxy", "read foreign", "enable")
	if !kept() {
		t.Fatal("another local proxy not kept")
	}
	current = ours
	if err := theirs.ResetPlatformOptions(); err != nil {
		t.Fatal(err)
	}
	expect("its stop", "clear", "write foreign", "notify")
	current = corp

	// a kept file the file system will not give (a lock, a denial; here a directory): an error, and it stays
	if err := os.Mkdir(savedSystemProxyPath("1000"), 0o700); err != nil {
		t.Fatal(err)
	}
	locked := platform(&fakeSetter{})
	if err := locked.restoreKeptProxyLocked(); err == nil || errors.Is(err, errKeptSetAside) {
		t.Fatalf("an unreadable file: %v", err)
	}
	if _, err := os.Stat(savedSystemProxyPath("1000")); err != nil {
		t.Fatalf("not left for the next try: %v", err)
	}
	if _, err := os.Stat(savedSystemProxyPath("1000") + ".bad"); err == nil {
		if err = os.Remove(savedSystemProxyPath("1000") + ".bad"); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(savedSystemProxyPath("1000")); err != nil {
		t.Fatal(err)
	}
	expect("an unreadable file")

	// an Enable that fails: rolled back, the settings put back and not kept
	failing := platform(&fakeSetter{failEnable: true})
	if err := failing.applySystemProxyLocked(); err == nil {
		t.Fatal("a failed Enable said nothing")
	}
	if err := failing.disableSystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("a failed Enable", "read corp", "enable", "write corp", "notify")
	if kept() {
		t.Fatal("kept after a failed Enable")
	}

	// none kept: upstream's clear alone
	plain := platform(&fakeSetter{on: true})
	if err := plain.ResetPlatformOptions(); err != nil {
		t.Fatal(err)
	}
	expect("none kept", "clear")
}

// A daemon's own proxy on, as a crash leaves it: on, and one of the servers the daemon set, on any address; another
// local proxy, or the proxy off, not.
func TestNekoDaemonsProxy(t *testing.T) {
	values := func(enabled uint32, server string) *savedSystemProxy {
		return &savedSystemProxy{Values: []savedProxyValue{
			{Key: internetSettingsKey, Name: "ProxyEnable", Type: registry.DWORD, Data: binary.LittleEndian.AppendUint32(nil, enabled)},
			{Key: internetSettingsKey, Name: "ProxyServer", Type: registry.SZ, Data: utf16Bytes(server)},
		}}
	}
	for _, c := range []struct {
		server  string
		servers []string
		want    bool
	}{
		{"http://192.168.1.5:2080", []string{"http://192.168.1.5:2080", ""}, true},
		{"http://127.0.0.1:2081", []string{"http://127.0.0.1:2080", "http://127.0.0.1:2081"}, true},
		{"http://127.0.0.1:3128", []string{"http://127.0.0.1:2080", ""}, false},
		{"http://corp.example:3128", []string{"http://127.0.0.1:2080", "http://127.0.0.1:2081"}, false},
		{"", []string{""}, false},
	} {
		if got := values(1, c.server).isDaemons(c.servers...); got != c.want {
			t.Errorf("%s on, the daemon's %q: %v, want %v", c.server, c.servers, got, c.want)
		}
	}
	if values(0, "http://127.0.0.1:2080").isDaemons("http://127.0.0.1:2080") {
		t.Error("off taken as the daemon's")
	}
}
