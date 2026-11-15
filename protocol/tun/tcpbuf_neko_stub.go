//go:build !with_gvisor

package tun

import (
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
)

// without gVisor there is no stack of its to hold (tcpbuf_neko.go)
func nekoTCPBuffers(tun.Stack, log.ContextLogger) {}
