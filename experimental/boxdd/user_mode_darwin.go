//go:build darwin

package boxdd

// niko: unprivileged macOS user-mode daemon (minimal macOS base).

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func runSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}

func validateUserOwnedDir(dir string) error {
	clean := filepath.Clean(dir)
	if home, err := os.UserHomeDir(); err == nil && home != "" && clean == filepath.Clean(home) {
		return E.New("refusing to use home directory directly as user-mode socket directory: ", dir)
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok {
		return E.New("user-mode directory is not a regular directory: ", clean)
	}
	if int(st.Uid) != os.Geteuid() {
		return E.New("user-mode directory is not owned by the current user: ", clean)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(clean, 0o700); err != nil {
			return E.Cause(err, "secure user-mode directory ", clean)
		}
	}
	return nil
}

func prepareUserModeRun() (func(), error) {
	if os.Geteuid() == 0 {
		return nil, E.New("--user-mode refuses to run as root")
	}
	if listenAddress != "" && !activeOptions.DevelopmentListen {
		return nil, E.New("--listen is not allowed in --user-mode")
	}

	signal.Ignore(syscall.SIGPIPE)

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil, E.New("cannot determine user home directory for --user-mode")
	}

	if workingDirectory == "" {
		workingDirectory = filepath.Join(home, "Library", "Application Support", activeNames.Product, "user-daemon")
	}

	if socketPath == "" && listenAddress == "" {
		socketPath = filepath.Join(home, "Library", "Caches", activeNames.Product, activeNames.Service+".sock")
	}

	if socketPath != "" {
		if err := validateUserOwnedDir(filepath.Dir(socketPath)); err != nil {
			return nil, E.Cause(err, "validate user-mode socket directory")
		}
	}

	if err := validateUserOwnedDir(workingDirectory); err != nil {
		return nil, E.Cause(err, "validate user-mode working directory")
	}
	lockPath := filepath.Join(workingDirectory, activeNames.Service+".lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, E.Cause(err, "open user-mode lock file")
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lockFile.Close()
		return nil, E.Cause(err, "another user-mode daemon is already running")
	}
	_ = lockFile.Truncate(0)
	_, _ = lockFile.Seek(0, 0)
	_, _ = fmt.Fprintf(lockFile, "%d\n", os.Getpid())

	return func() {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		_ = lockFile.Close()
	}, nil
}

func ensureUserModeOwner() error {
	return saveOwner(strconv.Itoa(os.Geteuid()), 0)
}

func runUserModeWorker() error {
	return E.New("worker --user-mode is only used on Windows; on macOS run 'run --user-mode'")
}
