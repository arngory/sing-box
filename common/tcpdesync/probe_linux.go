package tcpdesync

import (
	"io"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const probeTimeout = 2 * time.Second

func probe() PlatformCapabilities {
	var result PlatformCapabilities
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer client.Close()
	server, ok := <-accepted
	if !ok {
		result.Error = "accept failed"
		return result
	}
	defer server.Close()
	s, err := newSocket(client)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.NotSent = s.notSent
	if ttl, getErr := s.getInt(s.ttlLevel, s.ttlName); getErr == nil {
		if s.setInt(s.ttlLevel, s.ttlName, 1) == nil {
			if low, _ := s.getInt(s.ttlLevel, s.ttlName); low == 1 {
				result.TTL = true
			}
			_ = s.setInt(s.ttlLevel, s.ttlName, ttl)
		}
	}
	result.OOB = probeOOB(s, client, server) == nil
	return result
}

// probeOOB sends "x" with the urgent byte "!" and then "y": a receiver without SO_OOBINLINE reads "xy".
func probeOOB(s *socket, client, server *net.TCPConn) error {
	if err := s.sendOOB([]byte("x"), '!'); err != nil {
		return err
	}
	if _, err := client.Write([]byte("y")); err != nil {
		return err
	}
	if err := server.SetReadDeadline(time.Now().Add(probeTimeout)); err != nil {
		return err
	}
	buffer := make([]byte, 2)
	if _, err := io.ReadFull(server, buffer); err != nil {
		return err
	}
	if string(buffer) != "xy" {
		return E.New("urgent byte read in the stream: ", string(buffer))
	}
	return nil
}
