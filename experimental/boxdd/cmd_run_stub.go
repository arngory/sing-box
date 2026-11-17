//go:build !windows && !linux

package boxdd

import "os"

func runService() (bool, error) {
	return false, nil
}

func preparePlatformWorkingDirectory() error {
	return os.MkdirAll(workingDirectory, 0o700)
}
