package naive

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// statusConn gives a refused CONNECT its status. An early dial hands the stream over before the proxy's answer and
// never looks at it: a 429 (raycontrol conn-limit-v1 §3.1: the user's connection limit), a 404 or a 407 read as a
// stream that just ends. The first read that comes back checks the answer once, and a status other than 200 is the
// read's error from then on (neko).
type statusConn struct {
	net.Conn
	ctx    context.Context
	logger logger.ContextLogger
	// the answer's headers once they are there, as cronet's BidirectionalConn.WaitForHeadersContext
	headers func(ctx context.Context) (map[string]string, error)
	checked atomic.Bool
	refused atomic.Pointer[statusError]
}

type statusError struct{ error }

// statusWait bounds a look at headers a read has already passed: they are there, or the stream is over.
const statusWait = time.Second

func (c *statusConn) Read(p []byte) (int, error) {
	if refused := c.refused.Load(); refused != nil {
		return 0, refused.error
	}
	n, err := c.Conn.Read(p)
	if c.checked.Load() {
		return n, err
	}
	// a deadline or a close of this side says nothing of the answer: the next read looks again
	if err != nil && (errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed)) {
		return n, err
	}
	c.checked.Store(true)
	headers, headersErr := c.answer()
	if headersErr != nil {
		return n, err
	}
	if status := headers[":status"]; status != "200" {
		refused := &statusError{E.New("unexpected response status: ", status)}
		c.refused.Store(refused)
		c.logger.WarnContext(c.ctx, "handshake failed: ", refused.error)
		return 0, refused.error
	}
	return n, err
}

// answerTries: how often the headers are asked for. A refused stream is over by the time its read comes back, and
// the wait for headers takes either of two things that are both there, the headers or the stream's end: asked
// again, the headers are missed once in 2^32 refusals. A stream that failed before any answer says so every time.
const answerTries = 32

func (c *statusConn) answer() (headers map[string]string, err error) {
	for range answerTries {
		// not the dial's context, which may be over by now and would be a third thing there
		ctx, cancel := context.WithTimeout(context.Background(), statusWait)
		headers, err = c.headers(ctx)
		cancel()
		if err == nil {
			return headers, nil
		}
	}
	return nil, err
}

// upstreamOf looks for a T under conn, through the wrappers that name what they wrap (Upstream): the stream under
// cronet's tracked naive connection is two of them down.
func upstreamOf[T any](conn any) (found T, ok bool) {
	for range 8 {
		if found, ok = conn.(T); ok {
			return found, true
		}
		wrapper, isWrapper := conn.(interface{ Upstream() any })
		if !isWrapper {
			break
		}
		conn = wrapper.Upstream()
	}
	return found, false
}

func (c *statusConn) Upstream() any { return c.Conn }

// ReaderReplaceable: only once the answer is known to be a 200 may a copy read past this.
func (c *statusConn) ReaderReplaceable() bool { return c.checked.Load() && c.refused.Load() == nil }

func (c *statusConn) WriterReplaceable() bool { return true }
