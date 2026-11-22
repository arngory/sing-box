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

// fakeSetter is a system proxy that sets nothing and notes what it was asked.
type fakeSetter struct {
	on    bool
	calls *[]string
}

func (s *fakeSetter) IsEnabled() bool { return s.on }

func (s *fakeSetter) Enable() error {
	*s.calls = append(*s.calls, "enable")
	s.on = true
	return nil
}

func (s *fakeSetter) Disable() error {
	*s.calls = append(*s.calls, "clear")
	s.on = false
	return nil
}

// The owner's own proxy settings: kept before the daemon's goes on, put back after it goes off (turned off, or the
// core stopped), kept on the disk across a crash, and the clear alone where none were kept.
func TestNekoOwnerProxyKept(t *testing.T) {
	previousDirectory, previousListen := workingDirectory, listenAddress
	previousRead, previousWrite := readProxyValues, writeProxyValues
	workingDirectory = t.TempDir()
	// development mode: the operations run as this process, not impersonated
	listenAddress = "127.0.0.1:1"
	t.Cleanup(func() {
		workingDirectory, listenAddress = previousDirectory, previousListen
		readProxyValues, writeProxyValues = previousRead, previousWrite
	})
	var calls []string
	// what the registry has now: the user's own proxy, until the daemon's is on
	current := "corp"
	readProxyValues = func() (*savedSystemProxy, error) {
		calls = append(calls, "read "+current)
		return &savedSystemProxy{Values: []savedProxyValue{{Key: internetSettingsKey, Name: "ProxyServer",
			Type: 1, Data: []byte(current)}}}, nil
	}
	writeProxyValues = func(saved *savedSystemProxy) error {
		calls = append(calls, "write "+string(saved.Values[0].Data))
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

	p := &windowsPlatformInterface{systemProxyEnabled: true, ownerUserID: "1000", systemProxy: &fakeSetter{calls: &calls}}
	if err := p.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on", "read corp", "enable")
	if !kept() {
		t.Fatal("not kept on the disk")
	}
	if err := p.SetSystemProxyEnabled(false); err != nil {
		t.Fatal(err)
	}
	expect("off", "clear", "write corp")
	if kept() {
		t.Fatal("still kept after it was put back")
	}

	// on again, then the daemon crashes: the next one keeps what the first kept, not its own proxy, and puts that back
	if err := p.SetSystemProxyEnabled(true); err != nil {
		t.Fatal(err)
	}
	expect("on again", "read corp", "enable")
	current = "ours"
	again := &windowsPlatformInterface{systemProxyEnabled: true, ownerUserID: "1000",
		systemProxy: &fakeSetter{calls: &calls}}
	if err := again.applySystemProxyLocked(); err != nil {
		t.Fatal(err)
	}
	expect("on after a crash", "enable")
	if err := again.ResetPlatformOptions(); err != nil {
		t.Fatal(err)
	}
	expect("the core stopped", "clear", "write corp")

	// none kept (an owner the proxy went on for before this version): upstream's clear alone
	plain := &windowsPlatformInterface{systemProxyEnabled: true, ownerUserID: "1000",
		systemProxy: &fakeSetter{on: true, calls: &calls}}
	if err := plain.ResetPlatformOptions(); err != nil {
		t.Fatal(err)
	}
	expect("none kept", "clear")
}
