//go:build windows

package boxdd

import (
	"os"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
)

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
	// the owner's registry: their own proxy, until the daemon's is on
	current := "corp"
	failWrite := false
	readProxyValues = func() (*savedSystemProxy, error) {
		calls = append(calls, "read "+current)
		return &savedSystemProxy{Values: []savedProxyValue{{Key: internetSettingsKey, Name: "ProxyServer",
			Type: 1, Data: []byte(current)}}}, nil
	}
	writeProxyValues = func(saved *savedSystemProxy) error {
		if failWrite {
			calls = append(calls, "write failed")
			return os.ErrPermission
		}
		current = string(saved.Values[0].Data)
		calls = append(calls, "write "+current)
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
		return &windowsPlatformInterface{systemProxyEnabled: true, ownerUserID: "1000", systemProxy: setter}
	}

	p := platform(&fakeSetter{})
	if err := p.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on", "read corp", "enable")
	if !kept() {
		t.Fatal("not kept on the disk")
	}
	current = "ours"
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
	current = "ours"
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
	current = "ours"
	restarted := platform(&fakeSetter{})
	if err := restarted.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on after a crash", "write corp", "notify", "read corp", "enable")
	current = "ours"

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

	// a kept file that cannot be read: set aside as .bad as the proxy goes on, kept anew; one stop puts them back
	if err := os.WriteFile(savedSystemProxyPath("1000"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := platform(&fakeSetter{})
	if err := broken.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on with a broken file", "read corp", "enable")
	if _, err := os.Stat(savedSystemProxyPath("1000") + ".bad"); err != nil {
		t.Fatalf("not set aside: %v", err)
	}
	if err := broken.ResetPlatformOptions(); err != nil {
		t.Fatalf("the stop after a broken file: %v", err)
	}
	expect("the stop after a broken file", "clear", "write corp", "notify")

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
