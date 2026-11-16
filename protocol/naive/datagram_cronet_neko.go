//go:build with_naive_outbound && with_naive_datagram

package naive

import (
	"context"

	"github.com/sagernet/cronet-go"
)

// The datagram API of cronet-go (arngory/cronet-go, naive-udp-v1 §8.4): built with with_naive_datagram, which needs
// a cronet-go whose go branch carries it and a libcronet built with datagram_stream (neko).

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
