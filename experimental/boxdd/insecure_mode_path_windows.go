//go:build windows

package boxdd

import (
	"path/filepath"
	"strings"
)

func normalizeRestrictedPath(path string) string {
	return strings.ToLower(filepath.Clean(path))
}
