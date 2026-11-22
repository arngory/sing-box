package tcpdesync

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

const (
	// sentTimeout bounds the wait for a piece to leave the send queue. With TCP_NODELAY and an open window it
	// leaves within the send call itself.
	sentTimeout = 100 * time.Millisecond
	// legacyAckTimeout bounds the wait for an ACK on kernels without tcpi_notsent_bytes (before 4.6).
	legacyAckTimeout = 500 * time.Millisecond
	// disorderAckTimeout bounds the wait, after a low-TTL piece, for the kernel to send it again and the server to
	// acknowledge everything: a retransmission timeout or a tail loss probe.
	disorderAckTimeout = 2 * time.Second
	pollInterval       = 500 * time.Microsecond
	ackPollInterval    = 2 * time.Millisecond
)

type socket struct {
	conn     *net.TCPConn
	raw      syscall.RawConn
	ttlLevel int
	ttlName  int
	notSent  bool
}

func newSocket(conn *net.TCPConn) (*socket, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	s := &socket{conn: conn, raw: raw, ttlLevel: unix.IPPROTO_IP, ttlName: unix.IP_TTL}
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && addr.IP.To4() == nil {
		s.ttlLevel, s.ttlName = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
	}
	// tcpi_notsent_bytes came in Linux 4.6 together with tcpi_min_rtt, which is never 0 on a kernel that fills
	// it (no sample yet reads ~0): a 0 means a shorter tcp_info without either
	info, err := s.tcpInfo()
	s.notSent = err == nil && info.Min_rtt != 0
	return s, nil
}

func (s *socket) getInt(level, name int) (int, error) {
	var value int
	var opErr error
	err := s.raw.Control(func(fd uintptr) {
		value, opErr = unix.GetsockoptInt(int(fd), level, name)
	})
	if err != nil {
		return 0, err
	}
	return value, opErr
}

func (s *socket) setInt(level, name, value int) error {
	var opErr error
	err := s.raw.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), level, name, value)
	})
	if err != nil {
		return err
	}
	return opErr
}

func (s *socket) tcpInfo() (*unix.TCPInfo, error) {
	var info *unix.TCPInfo
	var opErr error
	err := s.raw.Control(func(fd uintptr) {
		info, opErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	if err != nil {
		return nil, err
	}
	return info, opErr
}

func (s *socket) setTTL(ttl int) error {
	if testHookTTL != nil {
		testHookTTL(ttl)
	}
	return s.setInt(s.ttlLevel, s.ttlName, ttl)
}

// sendOOB sends data and then the byte oob with MSG_OOB in one send: the urgent pointer marks oob, and a server
// without SO_OOBINLINE keeps it out of the stream.
func (s *socket) sendOOB(data []byte, oob byte) error {
	buffer := make([]byte, len(data)+1)
	copy(buffer, data)
	buffer[len(data)] = oob
	var n int
	var sendErr error
	err := s.raw.Write(func(fd uintptr) bool {
		n, sendErr = unix.SendmsgN(int(fd), buffer, nil, nil, unix.MSG_OOB)
		return !errors.Is(sendErr, unix.EAGAIN)
	})
	if err != nil {
		return err
	}
	if sendErr != nil {
		return sendErr
	}
	if n != len(buffer) {
		// the urgent pointer now marks a stream byte: the stream is broken
		return E.New("tcp_desync: partial MSG_OOB send (", n, " of ", len(buffer), ")")
	}
	return nil
}

// waitSent waits until the send queue holds nothing unsent, so the next piece starts a new segment.
func (s *socket) waitSent(ctx context.Context, lowTTL bool, unackedBefore uint32) error {
	if !s.notSent {
		return s.waitSentLegacy(ctx, lowTTL, unackedBefore)
	}
	deadline := time.Now().Add(sentTimeout)
	for {
		info, err := s.tcpInfo()
		if err != nil {
			return err
		}
		if info.Notsent_bytes == 0 || time.Now().After(deadline) {
			return nil
		}
		if err = sleep(ctx, pollInterval); err != nil {
			return err
		}
	}
}

// waitSentLegacy stands in for tcpi_notsent_bytes on old kernels: a piece has left when the count of segments in
// flight grows (a low-TTL piece is never acknowledged), or when everything is acknowledged.
func (s *socket) waitSentLegacy(ctx context.Context, lowTTL bool, unackedBefore uint32) error {
	timeout := legacyAckTimeout
	if lowTTL {
		timeout = sentTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		info, err := s.tcpInfo()
		if err != nil {
			return err
		}
		if lowTTL && info.Unacked > unackedBefore || !lowTTL && info.Unacked == 0 || time.Now().After(deadline) {
			return nil
		}
		if err = sleep(ctx, pollInterval); err != nil {
			return err
		}
	}
}

// waitAcked waits until the server has acknowledged everything sent.
func (s *socket) waitAcked(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		info, err := s.tcpInfo()
		if err != nil {
			return err
		}
		if info.Unacked == 0 || time.Now().After(deadline) {
			return nil
		}
		if err = sleep(ctx, ackPollInterval); err != nil {
			return err
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sendPieces(ctx context.Context, conn *net.TCPConn, pieces []Piece, _ logger.ContextLogger) error {
	s, err := newSocket(conn)
	if err != nil {
		return err
	}
	noDelay, err := s.getInt(unix.IPPROTO_TCP, unix.TCP_NODELAY)
	if err != nil {
		return E.Cause(err, "tcp_desync: get TCP_NODELAY")
	}
	if noDelay == 0 {
		if err = s.setInt(unix.IPPROTO_TCP, unix.TCP_NODELAY, 1); err != nil {
			return E.Cause(err, "tcp_desync: set TCP_NODELAY")
		}
		defer s.setInt(unix.IPPROTO_TCP, unix.TCP_NODELAY, 0)
	}
	var lowTTLSent bool
	for i, piece := range pieces {
		last := i == len(pieces)-1
		lowTTL := piece.Mode.LowTTL()
		var ttl int
		var unackedBefore uint32
		if lowTTL {
			ttl, err = s.getInt(s.ttlLevel, s.ttlName)
			if err != nil {
				return E.Cause(err, "tcp_desync: get TTL")
			}
			if !s.notSent {
				if info, infoErr := s.tcpInfo(); infoErr == nil {
					unackedBefore = info.Unacked
				}
			}
			if err = s.setTTL(1); err != nil {
				return E.Cause(err, "tcp_desync: set TTL")
			}
		}
		if piece.Mode.OutOfBand() {
			err = s.sendOOB(piece.Data, piece.OOB)
		} else {
			_, err = conn.Write(piece.Data)
		}
		if err == nil && (!last || lowTTL) {
			err = s.waitSent(ctx, lowTTL, unackedBefore)
		}
		if lowTTL {
			// the kernel sends the piece again with the TTL the socket has then
			if restoreErr := s.setTTL(ttl); err == nil && restoreErr != nil {
				err = E.Cause(restoreErr, "tcp_desync: restore TTL")
			}
			lowTTLSent = true
		}
		if err != nil {
			return err
		}
	}
	if lowTTLSent {
		return s.waitAcked(ctx, disorderAckTimeout)
	}
	return nil
}
