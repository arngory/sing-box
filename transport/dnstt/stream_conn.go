package dnstt

// Adapted from dnstt-client/http.go and tls.go (www.bamsoftware.com/git/dnstt.git,
// public domain): DNS messages to the resolver over DoH (RFC 8484) or DoT (RFC 7858).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	dohSenders        = 32
	defaultRetryAfter = 10 * time.Second
	dialTimeout       = 30 * time.Second
)

// httpPacketConn sends each DNS message as a DoH POST and queues the answer.
type httpPacketConn struct {
	client    *http.Client
	url       string
	logger    logger.ContextLogger
	done      chan struct{}
	closeOnce sync.Once

	notBefore     time.Time
	notBeforeLock sync.RWMutex

	*turbotunnel.QueuePacketConn
}

func newHTTPPacketConn(transport http.RoundTripper, url string, logger logger.ContextLogger) *httpPacketConn {
	c := &httpPacketConn{
		client:          &http.Client{Transport: transport, Timeout: time.Minute},
		url:             url,
		logger:          logger,
		done:            make(chan struct{}),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}
	for range dohSenders {
		go c.sendLoop()
	}
	return c
}

func (c *httpPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.client.CloseIdleConnections()
		c.QueuePacketConn.Close()
	})
	return nil
}

func (c *httpPacketConn) send(p []byte) error {
	request, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(p))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("User-Agent", "") // no "Go-http-client/1.1"
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		if response.Header.Get("Content-Type") != "application/dns-message" {
			return E.New("unexpected DoH Content-Type ", response.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 64000))
		if err == nil {
			c.QueuePacketConn.QueueIncoming(body, turbotunnel.DummyAddr{})
		}
		return nil
	}
	// a rate-limited resolver says when to come back; keep quiet until then
	now := time.Now()
	retryAfter := parseRetryAfter(response.Header.Get("Retry-After"), now)
	if retryAfter.IsZero() {
		retryAfter = now.Add(defaultRetryAfter)
	}
	c.notBeforeLock.Lock()
	if retryAfter.After(c.notBefore) {
		c.notBefore = retryAfter
	}
	c.notBeforeLock.Unlock()
	c.logger.Debug("dnstt: DoH ", response.Status, ", pausing until ", retryAfter.Format(time.TimeOnly))
	return nil
}

func (c *httpPacketConn) sendLoop() {
	outgoing := c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{})
	for {
		var p []byte
		select {
		case p = <-outgoing:
		case <-c.done:
			return
		}
		c.notBeforeLock.RLock()
		notBefore := c.notBefore
		c.notBeforeLock.RUnlock()
		if time.Until(notBefore) > 0 {
			continue // dropped, KCP retransmits
		}
		if err := c.send(p); err != nil {
			c.logger.Debug("dnstt: DoH: ", err)
		}
	}
}

func parseRetryAfter(value string, now time.Time) time.Time {
	if value == "" {
		return time.Time{}
	}
	if t, err := http.ParseTime(value); err == nil {
		return t
	}
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	return time.Time{}
}

// tlsPacketConn sends DNS messages over one DoT connection, redialing when it breaks.
type tlsPacketConn struct {
	dial      func(ctx context.Context) (net.Conn, error)
	logger    logger.ContextLogger
	done      chan struct{}
	closeOnce sync.Once
	conn      net.Conn
	connLock  sync.Mutex
	*turbotunnel.QueuePacketConn
}

func newTLSPacketConn(ctx context.Context, dial func(ctx context.Context) (net.Conn, error), logger logger.ContextLogger) (*tlsPacketConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := dial(dialCtx)
	cancel()
	if err != nil {
		return nil, err
	}
	c := &tlsPacketConn{
		dial:            dial,
		logger:          logger,
		done:            make(chan struct{}),
		conn:            conn,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}
	go c.loop(conn)
	return c, nil
}

func (c *tlsPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.connLock.Lock()
		c.conn.Close()
		c.connLock.Unlock()
		c.QueuePacketConn.Close()
	})
	return nil
}

func (c *tlsPacketConn) loop(conn net.Conn) {
	defer c.Close()
	for {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := c.recvLoop(conn); err != nil {
				c.logger.Debug("dnstt: DoT receive: ", err)
			}
			conn.Close()
		}()
		go func() {
			defer wg.Done()
			if err := c.sendLoop(conn); err != nil {
				c.logger.Debug("dnstt: DoT send: ", err)
			}
			conn.Close()
		}()
		wg.Wait()
		select {
		case <-c.done:
			return
		default:
		}
		dialCtx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		newConn, err := c.dial(dialCtx)
		cancel()
		if err != nil {
			c.logger.Debug("dnstt: DoT redial: ", err)
			return
		}
		c.connLock.Lock()
		c.conn = newConn
		c.connLock.Unlock()
		conn = newConn
	}
}

func (c *tlsPacketConn) recvLoop(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	for {
		var length uint16
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		p := make([]byte, int(length))
		if _, err := io.ReadFull(reader, p); err != nil {
			return err
		}
		c.QueuePacketConn.QueueIncoming(p, turbotunnel.DummyAddr{})
	}
}

func (c *tlsPacketConn) sendLoop(conn net.Conn) error {
	writer := bufio.NewWriter(conn)
	outgoing := c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{})
	for {
		var p []byte
		select {
		case p = <-outgoing:
		case <-c.done:
			return nil
		}
		if len(p) > 0xffff {
			continue
		}
		length := uint16(len(p))
		if err := binary.Write(writer, binary.BigEndian, &length); err != nil {
			return err
		}
		if _, err := writer.Write(p); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
}
