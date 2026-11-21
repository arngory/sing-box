package hysteria2

import (
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// A dead path (neko). The connection keeps sending into a path that no longer carries it back: the NAT's binding
// or the node's conntrack entry went away while the phone slept (its clock stops then, so quic-go's own timers do
// not see the sleep), the node restarted, a front drops short headers from an address it does not know. Salamander
// has no stateless reset, so nothing tells the client: quic-go closes the connection only at its idle timeout, 60 s
// on a raycontrol row, and every stream on it waits that long, DNS over DoH too ("no internet" in the browsers).
//
// So the client watches its own sends. A write on a stream or a UDP session arms one check; if by then the
// connection sent at least deadPathSent packets and got not one back, it is closed, and the next dial takes a new
// one. A live path answers every ack-eliciting packet within an RTT and max_ack_delay. Nothing is armed while
// nothing is written, so an idle connection costs no timer; a write blocked by flow control sends nothing and is
// no sign of a dead path.
//
// The price: a path that only goes quiet for longer (a lift, a tunnel, Wi-Fi roaming within one network) loses the
// connection with its streams and UDP sessions, which quic-go would have carried on after the gap. 10 s at least
// keeps the short gaps; a network that changes or goes away resets the connections anyway (the app's
// networkChangeResetConnections). Against that, 60 s of no DNS on every dead path.
const (
	deadPathMin  = 10 * time.Second
	deadPathMax  = 20 * time.Second
	deadPathPTOs = 3
	// the write's own packet and a probe at least: an ACK sent for a packet received just before the check began
	// expects no answer
	deadPathSent = 2
)

var errDeadPath = E.New("hysteria2: no packet back while sending, the path is gone")

type deadPathWatch struct {
	armed  atomic.Bool
	logger logger.Logger
}

// deadPathWait: three PTOs of the connection (RFC 9002 §6.2.1 with 25 ms of max_ack_delay), within the bounds.
func deadPathWait(stats quic.ConnectionStats) time.Duration {
	pto := stats.SmoothedRTT + max(4*stats.MeanDeviation, time.Millisecond) + 25*time.Millisecond
	return min(max(deadPathPTOs*pto, deadPathMin), deadPathMax)
}

// sent arms the check unless one is armed: called before a write on any of the connection's streams and sessions.
func (c *clientQUICConnection) sent() {
	if c.quicConn == nil || !c.deadPath.armed.CompareAndSwap(false, true) {
		return
	}
	before := c.quicConn.ConnectionStats()
	wait := deadPathWait(before)
	time.AfterFunc(wait, func() {
		after := c.quicConn.ConnectionStats()
		if after.PacketsReceived == before.PacketsReceived && after.PacketsSent >= before.PacketsSent+deadPathSent && c.active() {
			if c.deadPath.logger != nil {
				c.deadPath.logger.Warn("hysteria2: ", after.PacketsSent-before.PacketsSent, " packets sent and none back in ", wait, ": the connection is closed for a new one")
			}
			c.closeWithError(errDeadPath)
			return
		}
		c.deadPath.armed.Store(false)
	})
}
