//go:build !unix

package udpdesync

import (
	"net"

	E "github.com/sagernet/sing/common/exceptions"
)

func setTTL(net.Conn, int) (func(), error) {
	return func() {}, E.New("not supported on this platform")
}
