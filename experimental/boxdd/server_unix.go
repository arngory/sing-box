//go:build !windows

package boxdd

import (
	"net"
	"os"
	"path/filepath"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
)

func listenEndpoint() (net.Listener, error) {
	path := socketPath
	if path == "" {
		path = filepath.Join(workingDirectory, activeNames.Service+".sock")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != workingDirectory {
		dirMode := os.FileMode(0o755)
		if userMode {
			dirMode = 0o700
		}
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return nil, err
		}
		if userMode {
			if home, err := os.UserHomeDir(); err == nil && home != "" && filepath.Clean(dir) == filepath.Clean(home) {
				return nil, E.New("refusing to place user-mode socket directly in home directory: ", dir)
			}
			info, err := os.Lstat(dir)
			if err != nil {
				return nil, err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || int(st.Uid) != os.Geteuid() {
				return nil, E.New("user-mode socket directory is not owned by the current user: ", dir)
			}
			if info.Mode().Perm()&0o077 != 0 {
				if err := os.Chmod(dir, 0o700); err != nil {
					return nil, err
				}
			}
		} else if os.Geteuid() == 0 {
			info, err := os.Lstat(dir)
			if err != nil {
				return nil, err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || st.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
				return nil, E.New("socket directory is not a root-owned protected directory: ", dir)
			}
		}
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, E.New("refusing to remove non-socket path at ", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	sockMode := os.FileMode(0o666)
	if userMode {
		sockMode = 0o600
	}
	err = os.Chmod(path, sockMode)
	if err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
