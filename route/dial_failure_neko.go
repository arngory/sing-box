package route

import (
	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// DialFailureObserver hears each connection the core could not open through an outbound (neko): the outbound's tag,
// where it was to go and why it did not. Niko registers it in the context of its running core alone, never of a
// test core, and wakes its watchdog's check of the profile when such failures pile up (libcore/dialfail.go).
type DialFailureObserver interface {
	DialFailed(outboundTag string, destination string, err error)
}

func (m *ConnectionManager) noteDialFailure(this N.Dialer, destination string, err error) {
	if m.dialFailure == nil {
		return
	}
	outbound, isOutbound := this.(adapter.Outbound)
	if !isOutbound {
		return
	}
	m.dialFailure.DialFailed(outbound.Tag(), destination, err)
}
