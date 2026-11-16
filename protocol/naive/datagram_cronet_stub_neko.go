//go:build with_naive_outbound && !with_naive_datagram

package naive

import (
	"context"
	"errors"

	"github.com/sagernet/cronet-go"
)

// A core built without with_naive_datagram (a cronet-go before the datagram API): udp_datagram keeps UDP over TCP
// and says why once (neko).

var (
	errDatagramQueueFull      = errors.New("cronet: datagram queue full")
	errDatagramCapsuleTimeout = errors.New("cronet: datagram capsule timeout")
	errDatagramTooLarge       = errors.New("cronet: datagram too large")
	errDatagramClosed         = errors.New("cronet: datagram stream closed")
	errDatagramTruncated      = errors.New("cronet: datagram truncated")
	errDatagramUnsupported    = errors.New("this core is built without HTTP/3 datagrams (with_naive_datagram)")
)

func checkDatagramSupport() error {
	return errDatagramUnsupported
}

func openDatagram(ctx context.Context, client *cronet.NaiveClient, url string, headers map[string]string) (datagramConn, error) {
	return nil, errDatagramUnsupported
}
