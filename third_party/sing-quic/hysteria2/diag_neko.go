package hysteria2

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// Connection diagnostics (neko). Each QUIC connection of the client gets a number; its opening (where to, the
// congestion control the auth chose, the packet size) and its end (how long it lived, what it sent and got, its
// losses, the last packet in, what ended it) are logged at info, always: two lines a connection, no timer.
//
// With ClientOptions.LogConnections a sampler also looks at the connection every second and logs every ten a line of
// what went each way, and the moments it stalls:
//   - one way: packets go out and none come back for diagStall (a path that drops what comes back, or what goes out
//     before the node);
//   - both ways quiet while streams or UDP sessions are open (above QUIC: flow control, the node's side);
//
// and when packets come back again. One timer a connection while it lives: a debug switch, not for every day.
const (
	diagTick    = time.Second
	diagSummary = 10 * time.Second
	diagStall   = 3 * time.Second
)

var diagSeq atomic.Uint64

type connDiag struct {
	id      uint64
	opened  time.Time
	remote  string
	streams atomic.Int64 // opened in all
	lastIn  atomic.Int64 // unix nanoseconds of the last tick that saw a packet come in, 0 for none yet
	done    chan struct{}
}

func (c *Client) diagOpen(conn *clientQUICConnection, rawConn any, cc string) {
	d := &connDiag{id: diagSeq.Add(1), opened: time.Now(), remote: c.serverAddr.String(), done: make(chan struct{})}
	if nc, ok := rawConn.(net.Conn); ok && nc.RemoteAddr() != nil {
		d.remote = nc.RemoteAddr().String()
	}
	if len(c.serverPorts) > 0 {
		d.remote += fmt.Sprint(" (hopping over ", len(c.serverPorts), " ports)")
	}
	conn.diag = d
	if c.logger == nil {
		return
	}
	stats := conn.quicConn.ConnectionStats()
	c.logger.Info(fmt.Sprint("hysteria2 conn #", d.id, " open to ", d.remote, ": ", cc, ", packet ", conn.quicConn.InitialPacketSize(),
		" B, parrot ", c.quicConfig.ChromeParrot, ", path MTU discovery ", !c.quicConfig.DisablePathMTUDiscovery,
		", rtt ", stats.SmoothedRTT.Round(time.Millisecond), ", udp ", !conn.udpDisabled))
	if c.logConnections {
		go c.diagSample(conn, d)
	}
}

// diagClose logs the end of the connection once, with the first error that closed it.
func (c *Client) diagClose(conn *clientQUICConnection) {
	d := conn.diag
	if d == nil {
		return
	}
	close(d.done)
	if c.logger == nil {
		return
	}
	conn.access.RLock()
	cause := conn.connErr
	conn.access.RUnlock()
	why := "closed"
	switch {
	case cause == os.ErrClosed:
		why = "closed when idle"
	case cause != nil:
		why = cause.Error()
	}
	s := conn.quicConn.ConnectionStats()
	last := "none in"
	if at := d.lastIn.Load(); at != 0 {
		last = fmt.Sprint("last in ", time.Since(time.Unix(0, at)).Round(time.Second), " before")
	} else if s.PacketsReceived > 0 {
		last = "packets in"
	}
	c.logger.Info(fmt.Sprint("hysteria2 conn #", d.id, " ended after ", time.Since(d.opened).Round(time.Second), ": ",
		diagBytes(s.BytesSent), "/", s.PacketsSent, " pkts out, ", diagBytes(s.BytesReceived), "/", s.PacketsReceived, " pkts in, ",
		s.PacketsLost, " lost, rtt ", s.MinRTT.Round(time.Millisecond), "/", s.SmoothedRTT.Round(time.Millisecond), ", ",
		d.streams.Load(), " streams, ", last, ": ", why))
}

func (c *Client) diagSample(conn *clientQUICConnection, d *connDiag) {
	ticker := time.NewTicker(diagTick)
	defer ticker.Stop()
	prev := conn.quicConn.ConnectionStats()
	sum := prev
	sumAt := time.Now()
	inAt := sumAt // the last tick packets came in (or the start)
	var stalled, quiet bool
	for {
		select {
		case <-d.done:
			return
		case now := <-ticker.C:
			s := conn.quicConn.ConnectionStats()
			conn.access.RLock()
			streams, sessions := conn.streams, len(conn.udpConnMap)
			conn.access.RUnlock()
			in, out := s.PacketsReceived > prev.PacketsReceived, s.PacketsSent > prev.PacketsSent
			if in {
				d.lastIn.Store(now.UnixNano())
				if stalled || quiet {
					c.logger.Info(fmt.Sprint("hysteria2 conn #", d.id, ": packets in again after ", now.Sub(inAt).Round(time.Second)))
				}
				inAt, stalled, quiet = now, false, false
			} else if gap := now.Sub(inAt); gap >= diagStall {
				switch {
				case out && !stalled:
					stalled = true
					c.logger.Warn(fmt.Sprint("hysteria2 conn #", d.id, ": stall, packets out and none in for ", gap.Round(time.Second),
						" (", s.PacketsSent-sum.PacketsSent, " out since the last line, ", streams, " streams, ", sessions, " udp)"))
				case !out && !quiet && !stalled && streams+sessions > 0:
					quiet = true
					c.logger.Info(fmt.Sprint("hysteria2 conn #", d.id, ": quiet both ways for ", gap.Round(time.Second), " with ",
						streams, " streams and ", sessions, " udp open"))
				}
			}
			prev = s
			if now.Sub(sumAt) >= diagSummary {
				c.logger.Info(fmt.Sprint("hysteria2 conn #", d.id, ": ", now.Sub(sumAt).Round(time.Second), " out ",
					diagBytes(s.BytesSent-sum.BytesSent), "/", s.PacketsSent-sum.PacketsSent, " pkts, in ",
					diagBytes(s.BytesReceived-sum.BytesReceived), "/", s.PacketsReceived-sum.PacketsReceived, " pkts, lost ",
					s.PacketsLost-sum.PacketsLost, ", rtt ", s.SmoothedRTT.Round(time.Millisecond), ", ", streams, " streams, ",
					sessions, " udp"))
				sum, sumAt = s, now
			}
		}
	}
}

func diagBytes(n uint64) string {
	switch {
	case n >= 10<<20:
		return fmt.Sprint(n>>20, " MiB")
	case n >= 10<<10:
		return fmt.Sprint(n>>10, " KiB")
	default:
		return fmt.Sprint(n, " B")
	}
}
