package naive

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

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
