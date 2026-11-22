//go:build !windows

package boxdd

import "testing"

// sessionChange: sessions are Windows'.
func sessionChange(t *testing.T, d *Daemon, expect func(what string, want ...string)) {}
