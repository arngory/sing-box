//go:build with_gvisor && android

package tun

import "github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"

// after sing-tun's own init (an imported package's init runs first), before any endpoint reads with it
func init() {
	fdbased.BufConfig = nekoBufConfig
}
