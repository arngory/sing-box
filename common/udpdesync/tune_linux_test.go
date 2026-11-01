//go:build linux

package udpdesync

import (
	"testing"

	"golang.org/x/sys/unix"
)

// DF for path MTU discovery, as quic-go sets it on a socket it sees.
func checkTuned(t *testing.T, fd uintptr) {
	mode, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	if err != nil || mode != unix.IP_PMTUDISC_PROBE {
		t.Fatalf("IP_MTU_DISCOVER %d (%v), want IP_PMTUDISC_PROBE", mode, err)
	}
	size, _ := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	t.Logf("receive buffer %d bytes (capped by net.core.rmem_max without privileges)", size)
}
