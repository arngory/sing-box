//go:build with_gvisor

package tun

import (
	"runtime"
	"slices"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"
)

// TestNekoBufConfig: Android's shape takes any packet sing-tun's would (65535 bytes), and sing-tun still reads into the
// one view of 65535 elsewhere on Linux, which bufconfig_neko_android.go replaces (if that changes, see whether it still
// has to)
func TestNekoBufConfig(t *testing.T) {
	total := 0
	for _, size := range nekoBufConfig {
		total += size
	}
	if total < 65535 {
		t.Fatalf("the views add up to %d bytes, less than a packet of 65535", total)
	}
	if runtime.GOOS == "linux" && !slices.Equal(fdbased.BufConfig, []int{65535}) {
		t.Fatalf("sing-tun reads into %v now, not one view of 65535", fdbased.BufConfig)
	}
}
