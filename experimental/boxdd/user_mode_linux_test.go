//go:build linux

package boxdd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestUserModeLinuxDefaultsFlockAndPermissions(t *testing.T) {
	origWork := workingDirectory
	origSock := socketPath
	origListen := listenAddress
	origUserMode := userMode
	origNames := activeNames
	t.Cleanup(func() {
		workingDirectory = origWork
		socketPath = origSock
		listenAddress = origListen
		userMode = origUserMode
		activeNames = origNames
	})

	tmp := t.TempDir()
	dataHome := filepath.Join(tmp, "data")
	runtimeDir := filepath.Join(tmp, "run")
	_ = os.MkdirAll(runtimeDir, 0o700)
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	// Desktop launches under systemd user sessions inherit INVOCATION_ID; --user-mode must allow it.
	t.Setenv("INVOCATION_ID", "desktop-user-session-123")

	activeNames = testNikoLinuxNames()
	workingDirectory = ""
	socketPath = ""
	listenAddress = ""
	userMode = true

	unlock, err := prepareUserModeRun()
	if err != nil {
		t.Fatalf("prepareUserModeRun failed: %v", err)
	}
	defer unlock()

	wantWork := filepath.Join(dataHome, "niko", "user-daemon")
	wantSock := filepath.Join(runtimeDir, "niko", "niko-daemon.sock")
	if workingDirectory != wantWork {
		t.Fatalf("workingDirectory = %q, want %q", workingDirectory, wantWork)
	}
	if socketPath != wantSock {
		t.Fatalf("socketPath = %q, want %q", socketPath, wantSock)
	}

	// Lock file lives inside workingDirectory and records our PID.
	pidBytes, err := os.ReadFile(filepath.Join(wantWork, "niko-daemon.lock"))
	if err != nil {
		t.Fatalf("read lock file: %v", err)
	}
	if strings.TrimSpace(string(pidBytes)) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("lock PID = %q, want %d", strings.TrimSpace(string(pidBytes)), os.Getpid())
	}

	// User-mode immediately claims owner.json for the current euid so SubscribeServiceStatus works on first connect.
	if err := ensureUserModeOwner(); err != nil {
		t.Fatalf("ensureUserModeOwner failed: %v", err)
	}
	ownerID, err := loadOwner()
	if err != nil {
		t.Fatalf("loadOwner after ensureUserModeOwner failed: %v", err)
	}
	wantUID := strconv.Itoa(os.Geteuid())
	if ownerID != wantUID {
		t.Fatalf("ownerID = %q, want %q", ownerID, wantUID)
	}
	if err := (&Daemon{}).authorizeOwnerLocked(wantUID); err != nil {
		t.Fatalf("authorizeOwnerLocked(%q) failed: %v", wantUID, err)
	}

	// Second concurrent instance on the same workingDirectory must be refused even with a different socket path.
	socketPath = filepath.Join(tmp, "other-run", "other.sock")
	if _, err := prepareUserModeRun(); err == nil {
		t.Fatalf("expected second prepareUserModeRun on same workingDirectory to fail on flock")
	}
	socketPath = wantSock

	// Listen creates 0700 dir and 0600 socket.
	ln, err := listenEndpoint()
	if err != nil {
		t.Fatalf("listenEndpoint failed: %v", err)
	}
	defer ln.Close()

	dirInfo, err := os.Stat(filepath.Dir(wantSock))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("user-mode socket dir perm = %#o, want 0700", perm)
	}
	sockInfo, err := os.Stat(wantSock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := sockInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("user-mode socket perm = %#o, want 0600", perm)
	}

	// Refuses placing socket directly inside $HOME.
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		if err := validateUserOwnedDir(home); err == nil {
			t.Fatalf("expected validateUserOwnedDir($HOME) to fail")
		}
	}
}
