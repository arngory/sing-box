//go:build windows

package boxdd

import (
	"path/filepath"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

func knownProgramDataDir(name string) string {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, name)
}

func knownProgramFilesDir() (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", E.Cause(err, "resolve Program Files known folder")
	}
	if base == "" {
		return "", E.New("empty Program Files known folder")
	}
	return filepath.Clean(base), nil
}
