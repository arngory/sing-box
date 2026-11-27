//go:build !windows && !darwin && !(linux && !android)

package boxdd

func newPlatformInterface(daemon *Daemon) (daemonPlatform, error) {
	return nil, nil
}
