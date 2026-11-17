//go:build linux

package boxdd

import "path/filepath"

func normalizeRestrictedPath(path string) string {
	return filepath.Clean(path)
}
