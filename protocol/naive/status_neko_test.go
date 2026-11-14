package naive

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type scriptedConn struct {
	net.Conn
	reads []func(p []byte) (int, error)
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	next := c.reads[0]
	c.reads = c.reads[1:]
	return next(p)
}

func data(s string) func(p []byte) (int, error) {
	return func(p []byte) (int, error) { return copy(p, s), nil }
}

func fails(err error) func(p []byte) (int, error) {
	return func(p []byte) (int, error) { return 0, err }
}

func answered(status string, asked *int) func(ctx context.Context) (map[string]string, error) {
	return func(ctx context.Context) (map[string]string, error) {
		*asked++
		return map[string]string{":status": status}, nil
	}
}

// A CONNECT the proxy refused reads as its status, not as a stream that ends: 429 is the user's connection limit of
// a raycontrol node (conn-limit-v1 §3.1), which the app tells from a broken profile by these words.
func TestNekoNaiveStatusRefused(t *testing.T) {
	for _, status := range []string{"429", "404", "407"} {
		asked := 0
		conn := &statusConn{
			Conn: &scriptedConn{reads: []func(p []byte) (int, error){fails(io.EOF)}}, ctx: context.Background(),
			logger: logger.NOP(), headers: answered(status, &asked),
		}
		_, err := conn.Read(make([]byte, 16))
		if err == nil || !strings.HasSuffix(err.Error(), "unexpected response status: "+status) {
			t.Fatalf("%s: read gave %v", status, err)
		}
		// and again, without another read of the stream (it has none left) or look at the headers
		if _, again := conn.Read(make([]byte, 16)); again == nil || again.Error() != err.Error() || asked != 1 {
			t.Fatalf("%s: second read gave %v, headers asked %d times", status, again, asked)
		}
		if conn.ReaderReplaceable() {
			t.Fatalf("%s: a copy may read past the refusal", status)
		}
	}
	// a body with the refusal is not the destination's data
	asked := 0
	conn := &statusConn{
		Conn: &scriptedConn{reads: []func(p []byte) (int, error){data("too many")}}, ctx: context.Background(),
		logger: logger.NOP(), headers: answered("429", &asked),
	}
	if n, err := conn.Read(make([]byte, 16)); n != 0 || err == nil {
		t.Fatalf("a refusal's body: %d bytes, %v", n, err)
	}
}

// A 200 is checked once and reads go on untouched; a deadline or a close before the answer leaves the check to the
// next read; a stream that failed without an answer keeps its own error.
func TestNekoNaiveStatusAccepted(t *testing.T) {
	asked := 0
	conn := &statusConn{
		Conn: &scriptedConn{reads: []func(p []byte) (int, error){
			fails(os.ErrDeadlineExceeded), data("hello"), data("again"), fails(io.EOF),
		}}, ctx: context.Background(), logger: logger.NOP(), headers: answered("200", &asked),
	}
	p := make([]byte, 16)
	if _, err := conn.Read(p); !errors.Is(err, os.ErrDeadlineExceeded) || asked != 0 || conn.ReaderReplaceable() {
		t.Fatalf("a deadline before the answer: %v, headers asked %d times", err, asked)
	}
	if n, err := conn.Read(p); err != nil || string(p[:n]) != "hello" || asked != 1 || !conn.ReaderReplaceable() {
		t.Fatalf("the first data: %q, %v, headers asked %d times", p[:n], err, asked)
	}
	if n, err := conn.Read(p); err != nil || string(p[:n]) != "again" || asked != 1 {
		t.Fatalf("more data: %q, %v, headers asked %d times", p[:n], err, asked)
	}
	if _, err := conn.Read(p); err != io.EOF {
		t.Fatalf("the end: %v", err)
	}

	broken := errors.New("stream reset")
	conn = &statusConn{
		Conn: &scriptedConn{reads: []func(p []byte) (int, error){fails(broken)}}, ctx: context.Background(),
		logger: logger.NOP(), headers: func(ctx context.Context) (map[string]string, error) { return nil, broken },
	}
	if _, err := conn.Read(p); err != broken {
		t.Fatalf("a stream that failed before its answer: %v", err)
	}
}

// The stream's end and its headers are both there when a refused stream's read comes back, and the wait for headers
// takes either: asked again, the status is found.
func TestNekoNaiveStatusBesideTheEnd(t *testing.T) {
	asked := 0
	conn := &statusConn{
		Conn: &scriptedConn{reads: []func(p []byte) (int, error){fails(io.EOF)}}, ctx: context.Background(),
		logger: logger.NOP(), headers: func(ctx context.Context) (map[string]string, error) {
			asked++
			if asked < 7 {
				return nil, io.EOF
			}
			return map[string]string{":status": "429"}, nil
		},
	}
	if _, err := conn.Read(make([]byte, 16)); err == nil || !strings.HasSuffix(err.Error(), "unexpected response status: 429") {
		t.Fatalf("the end taken six times before the headers: read gave %v after %d looks", err, asked)
	}
	// no answer at all: the looks end, the stream's own error stays
	asked = 0
	conn = &statusConn{
		Conn: &scriptedConn{reads: []func(p []byte) (int, error){fails(io.EOF)}}, ctx: context.Background(),
		logger: logger.NOP(), headers: func(ctx context.Context) (map[string]string, error) {
			asked++
			return nil, io.EOF
		},
	}
	if _, err := conn.Read(make([]byte, 16)); err != io.EOF || asked != answerTries {
		t.Fatalf("no answer: read gave %v after %d looks", err, asked)
	}
}

type wrapsConn struct {
	net.Conn
	under any
}

func (c *wrapsConn) Upstream() any { return c.under }

// The stream is two wrappers under what cronet's early dial returns (its tracked connection, the naive one); what
// names no upstream ends the search.
func TestNekoNaiveUpstreamOf(t *testing.T) {
	stream := &scriptedConn{}
	dialed := &wrapsConn{under: &wrapsConn{under: stream}}
	if found, ok := upstreamOf[*scriptedConn](dialed); !ok || found != stream {
		t.Fatalf("the stream two wrappers down: %v, %v", found, ok)
	}
	if found, ok := upstreamOf[*scriptedConn](stream); !ok || found != stream {
		t.Fatalf("the stream itself: %v, %v", found, ok)
	}
	if _, ok := upstreamOf[*scriptedConn](&wrapsConn{under: &net.TCPConn{}}); ok {
		t.Fatal("found a stream under a connection that has none")
	}
	loop := &wrapsConn{}
	loop.under = loop
	if _, ok := upstreamOf[*scriptedConn](loop); ok {
		t.Fatal("found a stream in a wrapper of itself")
	}
}

func answeredWith(headers map[string]string) func(ctx context.Context) (map[string]string, error) {
	return func(ctx context.Context) (map[string]string, error) { return headers, nil }
}

// await_dial: the dial waits for the server's answer after its own dial (niko-ack: 1, raycontrol naive-uot-v1 §4.1).
// A 200 hands the connection out, checked; a 502 is the destination's refusal with the server's reason, a 504 a
// destination silent to the server's timeout; any other status stays the proxy's own.
func TestNekoNaiveAwaitDial(t *testing.T) {
	asked := 0
	conn := &statusConn{
		Conn: &scriptedConn{reads: []func(p []byte) (int, error){data("hello")}}, ctx: context.Background(),
		logger: logger.NOP(), headers: answered("200", &asked), ack: true,
	}
	if err := conn.await(context.Background()); err != nil {
		t.Fatalf("a 200: %v", err)
	}
	p := make([]byte, 16)
	if n, err := conn.Read(p); err != nil || string(p[:n]) != "hello" || asked != 1 || !conn.ReaderReplaceable() {
		t.Fatalf("after a 200: %q, %v, headers asked %d times", p[:n], err, asked)
	}

	for _, c := range []struct {
		headers map[string]string
		want    string
	}{
		{map[string]string{":status": "502", "niko-ack": "refused"}, "remote error: connection refused"},
		{map[string]string{":status": "502", "niko-ack": "unreachable"}, "remote error: host is unreachable"},
		{map[string]string{":status": "502", "niko-ack": "denied"}, "remote error: destination denied by the server"},
		{map[string]string{":status": "504"}, "remote error: connect timed out"},
		// not the dial's outcome: the user's limit, the credentials, a 502 of the proxy's own
		{map[string]string{":status": "429"}, "unexpected response status: 429"},
		{map[string]string{":status": "404"}, "unexpected response status: 404"},
		{map[string]string{":status": "502"}, "unexpected response status: 502"},
		{map[string]string{":status": "502", "niko-ack": "something new"}, "unexpected response status: 502"},
	} {
		conn = &statusConn{
			Conn: &scriptedConn{}, ctx: context.Background(), logger: logger.NOP(), headers: answeredWith(c.headers), ack: true,
		}
		err := conn.await(context.Background())
		if err == nil || err.Error() != c.want {
			t.Fatalf("%v: the dial gave %v, want %s", c.headers, err, c.want)
		}
		if conn.ReaderReplaceable() {
			t.Fatalf("%v: a copy may read past the refusal", c.headers)
		}
		// a connection handed out all the same (the fallback) reads the same refusal
		if _, readErr := conn.Read(p); readErr == nil || readErr.Error() != c.want {
			t.Fatalf("%v: a read gave %v", c.headers, readErr)
		}
	}

	// without the request header a 502 or a 504 is not the destination's: a server that was not asked
	conn = &statusConn{
		Conn: &scriptedConn{reads: []func(p []byte) (int, error){fails(io.EOF)}}, ctx: context.Background(),
		logger: logger.NOP(), headers: answeredWith(map[string]string{":status": "502", "niko-ack": "refused"}),
	}
	if _, err := conn.Read(p); err == nil || err.Error() != "unexpected response status: 502" {
		t.Fatalf("a 502 unasked: %v", err)
	}
}

// The waits of await_dial: no answer in awaitFallback hands the connection out, the first read checking it then; a
// dial with less time than that fails at its deadline; a canceled dial ends at once; a refusal whose stream end
// was taken before its answer is still found.
func TestNekoNaiveAwaitDialWaits(t *testing.T) {
	fallback, limit := awaitFallback, awaitLimit
	awaitFallback, awaitLimit = 50*time.Millisecond, 200*time.Millisecond
	defer func() { awaitFallback, awaitLimit = fallback, limit }()

	silent := func(ctx context.Context) (map[string]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	conn := &statusConn{Conn: &scriptedConn{}, ctx: context.Background(), logger: logger.NOP(), headers: silent, ack: true}
	started := time.Now()
	if err := conn.await(context.Background()); err != nil || time.Since(started) < awaitFallback || conn.checked.Load() {
		t.Fatalf("no answer in the fallback: %v after %v, checked %v", err, time.Since(started), conn.checked.Load())
	}
	// handed out unchecked: the answer that comes later is read with the first data
	conn.Conn = &scriptedConn{reads: []func(p []byte) (int, error){fails(io.EOF)}}
	conn.headers = answeredWith(map[string]string{":status": "504"})
	if _, err := conn.Read(make([]byte, 16)); err == nil || err.Error() != "remote error: connect timed out" {
		t.Fatalf("the answer after the fallback: %v", err)
	}

	conn = &statusConn{Conn: &scriptedConn{}, ctx: context.Background(), logger: logger.NOP(), headers: silent, ack: true}
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := conn.await(short)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a dial with less time than the fallback: %v", err)
	}

	conn = &statusConn{Conn: &scriptedConn{}, ctx: context.Background(), logger: logger.NOP(), headers: silent, ack: true}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = conn.await(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("a canceled dial: %v", err)
	}

	asked := 0
	conn = &statusConn{
		Conn: &scriptedConn{}, ctx: context.Background(), logger: logger.NOP(), ack: true,
		headers: func(ctx context.Context) (map[string]string, error) {
			asked++
			if asked < 3 {
				return nil, io.EOF
			}
			return map[string]string{":status": "502", "niko-ack": "refused"}, nil
		},
	}
	if err = conn.await(context.Background()); err == nil || err.Error() != "remote error: connection refused" {
		t.Fatalf("the end taken before the answer: %v after %d looks", err, asked)
	}
	// a stream that failed before any answer keeps its own error
	broken := errors.New("stream reset")
	conn = &statusConn{
		Conn: &scriptedConn{}, ctx: context.Background(), logger: logger.NOP(), ack: true,
		headers: func(ctx context.Context) (map[string]string, error) { return nil, broken },
	}
	if err = conn.await(context.Background()); err != broken {
		t.Fatalf("a stream that failed before its answer: %v", err)
	}
}
