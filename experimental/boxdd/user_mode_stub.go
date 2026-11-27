//go:build !linux && !windows

package boxdd

import (
	"os"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
)

func runSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}

func prepareUserModeRun() (func(), error) {
	return nil, E.New("--user-mode is not supported on this platform")
}

func ensureUserModeOwner() error {
	return nil
}

func runUserModeWorker() error {
	return E.New("worker --user-mode is not supported on this platform")
}
