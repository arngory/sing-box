//go:build with_gvisor

package tun

import (
	"reflect"
	"unsafe"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
)

// nekoTCPBufferMax is what a TCP connection of the gVisor stack may queue each way on Android (neko): gVisor's own
// default (1 MiB), without the growth sing-tun lets it have (to 8 MiB received, 6 MiB to send, Tailscale's values for
// a stack whose peers are far). This stack's peers are the phone's own apps over the TUN device, a few milliseconds
// away: 1 MiB is a window for gigabits there, and what it holds above that is only what waits for a slower outbound.
// Under an upload through one (naive's HTTP/2 stream) four connections kept some 20 MB of the background process's
// heap in their queues in the e2e (CI 43709895193, vpn-up-load and naive-h2-up-load).
const nekoTCPBufferMax = 1 << 20

// nekoTCPBuffers holds the TCP connections of [tunStack]'s gVisor stack (the gvisor stack's, the mixed stack's for
// what it takes) to nekoTCPBufferMax on Android, before the stack takes any connection: a connection reads the stack's
// range when it is made, and its growth reads the maximum each time. sing-tun has no option for it, so the stack is
// reached through the field it keeps it in (tcpbuf_neko_test.go fails if that changes); without it nothing is set and
// the log says so. Elsewhere, and for the system stack, nothing changes.
func nekoTCPBuffers(tunStack tun.Stack, logger log.ContextLogger) {
	if !C.IsAndroid {
		return
	}
	ipStack, err := nekoGVisorStack(tunStack)
	if err != nil {
		logger.Warn("TCP buffers left as sing-tun sets them: ", err)
		return
	}
	if ipStack == nil {
		return
	}
	if err := nekoSetTCPBuffers(ipStack); err != nil {
		logger.Warn("TCP buffers left as sing-tun sets them: ", err)
	}
}

// nekoGVisorStack is the gVisor stack of a gvisor or mixed stack, nil for another (the system stack).
func nekoGVisorStack(tunStack tun.Stack) (*stack.Stack, error) {
	value := reflect.ValueOf(tunStack)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return nil, nil
	}
	switch tunStack.(type) {
	case *tun.GVisor, *tun.Mixed:
	default:
		return nil, nil
	}
	field := value.Elem().FieldByName("stack")
	if !field.IsValid() || field.Type() != reflect.TypeOf((*stack.Stack)(nil)) {
		return nil, E.New("no gVisor stack in ", value.Type())
	}
	ipStack := *(**stack.Stack)(unsafe.Pointer(field.UnsafeAddr()))
	if ipStack == nil {
		return nil, E.New("the gVisor stack of ", value.Type(), " is not made yet")
	}
	return ipStack, nil
}

func nekoSetTCPBuffers(ipStack *stack.Stack) error {
	receive := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: min(tcp.DefaultReceiveBufferSize, nekoTCPBufferMax),
		Max:     nekoTCPBufferMax,
	}
	if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil {
		return E.New("receive: ", err)
	}
	send := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: min(tcp.DefaultSendBufferSize, nekoTCPBufferMax),
		Max:     nekoTCPBufferMax,
	}
	if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		return E.New("send: ", err)
	}
	return nil
}
