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
	// the CONNECT asked for an answer after the server's dial (niko-ack: 1): a 502 or a 504 is the destination's
	ack bool
}

// ackHeader asks a server for its answer after it has dialed the destination, and in a 502 names why the dial
// failed: refused, unreachable or denied (raycontrol naive-uot-v1 §4.1).
const ackHeader = "niko-ack"

// awaitLimit bounds the wait for the answer of a dial without a deadline of the caller's: above the server's own
// dial timeout (rayd naive: 10 s), so its 504 arrives rather than ours.
var awaitLimit = 15 * time.Second

// awaitFallback: no answer by then, the connection goes as without the wait, its answer checked with the first
// read. A destination that is slow to take the connection is let through, without its honest refusal: as Hysteria2's
// await dial does.
var awaitFallback = 4 * time.Second

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
	if refusal := c.refusal(headers); refusal != nil {
		return 0, refusal
	}
	return n, err
}

// refusal keeps the error of an answer other than 200, nil for a 200. A server asked for its answer after the dial
// says what became of the dial: a 502 with the reason, a 504 for a destination silent to the server's timeout. Any
// other status is the proxy's own refusal (429: the user's connection limit; 404, 407: the credentials).
func (c *statusConn) refusal(headers map[string]string) error {
	status := headers[":status"]
	if status == "200" {
		return nil
	}
	var err error
	if c.ack {
		switch {
		case status == "502" && headers[ackHeader] == "refused":
			err = E.New("remote error: connection refused")
		case status == "502" && headers[ackHeader] == "unreachable":
			err = E.New("remote error: host is unreachable")
		case status == "502" && headers[ackHeader] == "denied":
			err = E.New("remote error: destination denied by the server")
		case status == "504":
			err = E.New("remote error: connect timed out")
		}
	}
	if err == nil {
		err = E.New("unexpected response status: ", status)
		c.logger.WarnContext(c.ctx, "handshake failed: ", err)
	}
	c.refused.Store(&statusError{err})
	return err
}

// await holds a dial until the proxy has answered its CONNECT (await_dial): nil for a 200, the refusal otherwise,
// and nil too when no answer came in awaitFallback, the first read checking it then. A dial with less time than
// that fails at its deadline.
func (c *statusConn) await(ctx context.Context) error {
	limit := time.Now().Add(awaitLimit)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(limit) {
		limit = deadline
	}
	wait, handOver := time.Now().Add(awaitFallback), true
	if !wait.Before(limit) {
		wait, handOver = limit, false
	}
	waitCtx, cancel := context.WithDeadline(ctx, wait)
	headers, err := c.headers(waitCtx)
	expired := waitCtx.Err() != nil
	cancel()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if expired {
			if handOver {
				return nil
			}
			return E.Cause(context.DeadlineExceeded, "no answer to the connect")
		}
		// the stream is over: a refusal ends it, and the wait may take its end before the answer that is there
		if headers, err = c.answer(); err != nil {
			return err
		}
	}
	c.checked.Store(true)
	return c.refusal(headers)
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
