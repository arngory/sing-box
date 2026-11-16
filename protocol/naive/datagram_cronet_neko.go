//go:build with_naive_outbound

package naive

import (
	"context"
	"errors"

	"github.com/sagernet/cronet-go"
)

// The datagram API of cronet-go (arngory/cronet-go, naive-udp-v1 §8.4; its libcronet built with datagram_stream). A
// libcronet without the symbols, an old one, answers ErrDatagramUnsupported: UDP stays over TCP (neko).

var _ datagramConn = (*cronet.DatagramConn)(nil)

var (
	errDatagramQueueFull      = cronet.ErrDatagramQueueFull
	errDatagramCapsuleTimeout = cronet.ErrDatagramCapsuleTimeout
	errDatagramTooLarge       = cronet.ErrDatagramTooLarge
	errDatagramClosed         = cronet.ErrDatagramClosed
	errDatagramTruncated      = cronet.ErrDatagramTruncated
	errDatagramUnsupported    = cronet.ErrDatagramUnsupported
)

// checkDatagramSupport tells a libcronet without the datagram symbols (an old one): ErrDatagramUnsupported.
func checkDatagramSupport() error {
	return cronet.CheckDatagramSupport()
}

// openDatagram opens one connect-udp request on the client's engine; the answer comes later (WaitReady).
func openDatagram(ctx context.Context, client *cronet.NaiveClient, url string, headers map[string]string) (datagramConn, error) {
	return client.Engine().StreamEngine().CreateDatagramConn(ctx, url, headers), nil
}

// datagramBuilt: this core carries the datagram API.
const datagramBuilt = true

// datagramNever tells an end that says the node or the library cannot do datagrams at all, whatever worked before:
// a library without the symbols, a node that announces no HTTP/3 datagrams (-322, ERR_METHOD_NOT_SUPPORTED).
func datagramNever(err error) bool {
	return errors.Is(err, cronet.ErrDatagramUnsupported) || errors.Is(err, cronet.NetErrorMethodNotSupported)
}
