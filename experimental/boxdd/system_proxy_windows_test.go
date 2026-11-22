//go:build windows

package boxdd

import (
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
