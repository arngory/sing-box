//go:build with_gvisor

package tun

import (
	"strings"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	tun "github.com/sagernet/sing-tun"
)

// TestNekoTCPBuffers: sing-tun keeps its gVisor stack where nekoTCPBuffers looks for it, for the gvisor and the mixed
// stack (a rename there fails here, not silently on the phone); another stack is none of its business; and the range
// set is the one a stack reads back.
func TestNekoTCPBuffers(t *testing.T) {
	for _, tunStack := range []tun.Stack{&tun.GVisor{}, &tun.Mixed{}} {
		if _, err := nekoGVisorStack(tunStack); err == nil {
			t.Fatalf("%T before it starts: no error, want a stack not made yet", tunStack)
		} else if want := "is not made yet"; !strings.Contains(err.Error(), want) {
			t.Fatalf("%T: %v, want the field found and %q", tunStack, err, want)
		}
	}
	for _, tunStack := range []tun.Stack{nil, &tun.System{}} {
		if ipStack, err := nekoGVisorStack(tunStack); ipStack != nil || err != nil {
			t.Fatalf("%T: %v %v, want nothing", tunStack, ipStack, err)
		}
	}

	ipStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	defer ipStack.Close()
	if err := nekoSetTCPBuffers(ipStack); err != nil {
		t.Fatal(err)
	}
	var receive tcpip.TCPReceiveBufferSizeRangeOption
	if err := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil {
		t.Fatal(err)
	}
	var send tcpip.TCPSendBufferSizeRangeOption
	if err := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		t.Fatal(err)
	}
	if receive.Max != nekoTCPBufferMax || send.Max != nekoTCPBufferMax || receive.Default > receive.Max || send.Default > send.Max {
		t.Fatalf("receive %+v, send %+v, want both at most %d", receive, send, nekoTCPBufferMax)
	}
}
