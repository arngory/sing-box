package route

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tcpdesync"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// recordingLogger keeps what is logged.
type recordingLogger struct {
	access sync.Mutex
	lines  []string
}

func (l *recordingLogger) log(level string, args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	l.lines = append(l.lines, level+" "+fmt.Sprint(args...))
}

func (l *recordingLogger) has(level string, text string) bool {
	l.access.Lock()
	defer l.access.Unlock()
	for _, line := range l.lines {
		if strings.HasPrefix(line, level+" ") && strings.Contains(line, text) {
			return true
		}
	}
	return false
}

func (l *recordingLogger) Trace(args ...any)                        { l.log("trace", args...) }
func (l *recordingLogger) Debug(args ...any)                        { l.log("debug", args...) }
func (l *recordingLogger) Info(args ...any)                         { l.log("info", args...) }
func (l *recordingLogger) Warn(args ...any)                         { l.log("warn", args...) }
func (l *recordingLogger) Error(args ...any)                        { l.log("error", args...) }
func (l *recordingLogger) Fatal(args ...any)                        { l.log("fatal", args...) }
func (l *recordingLogger) Panic(args ...any)                        { l.log("panic", args...) }
func (l *recordingLogger) TraceContext(_ context.Context, a ...any) { l.log("trace", a...) }
func (l *recordingLogger) DebugContext(_ context.Context, a ...any) { l.log("debug", a...) }
func (l *recordingLogger) InfoContext(_ context.Context, a ...any)  { l.log("info", a...) }
func (l *recordingLogger) WarnContext(_ context.Context, a ...any)  { l.log("warn", a...) }
func (l *recordingLogger) ErrorContext(_ context.Context, a ...any) { l.log("error", a...) }
func (l *recordingLogger) FatalContext(_ context.Context, a ...any) { l.log("fatal", a...) }
func (l *recordingLogger) PanicContext(_ context.Context, a ...any) { l.log("panic", a...) }

// tcpOutbound dials TCP itself, as the direct outbound does.
type tcpOutbound struct{}

func (tcpOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return new(net.Dialer).DialContext(ctx, "tcp", destination.String())
}

func (tcpOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("no UDP")
}

// opaqueConn hides the socket under it, as a proxy protocol's connection does.
type opaqueConn struct{ net.Conn }

// wrappingOutbound's connections look proxied.
type wrappingOutbound struct{ tcpOutbound }

func (o wrappingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := o.tcpOutbound.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return &opaqueConn{conn}, nil
}

type helloCapture struct {
	net.Conn
	first []byte
}

func (c *helloCapture) Write(b []byte) (int, error) {
	if c.first == nil {
		c.first = append([]byte(nil), b...)
	}
	return 0, io.ErrClosedPipe
}
func (c *helloCapture) Read([]byte) (int, error)         { return 0, io.ErrClosedPipe }
func (c *helloCapture) Close() error                     { return nil }
func (c *helloCapture) SetDeadline(time.Time) error      { return nil }
func (c *helloCapture) SetReadDeadline(time.Time) error  { return nil }
func (c *helloCapture) SetWriteDeadline(time.Time) error { return nil }

// A tcp_desync route option cuts the first write of a direct connection, and only warns for a proxied one; the
// server reads the stream whole either way.
func TestNekoTCPDesyncRouteOption(t *testing.T) {
	capture := &helloCapture{}
	_ = tls.Client(capture, &tls.Config{ServerName: "www.youtube.com"}).Handshake()
	hello := capture.first
	require.NotEmpty(t, hello)
	strategy, err := tcpdesync.Parse(&option.TCPDesyncOptions{
		Split:  []option.TCPDesyncSplitOptions{{At: "1"}, {At: "sni+1", Mode: "oob"}},
		TLSRec: []string{"sni+2"},
	})
	require.NoError(t, err)

	for _, proxied := range []bool{false, true} {
		t.Run(fmt.Sprint("proxied=", proxied), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			received := make(chan []byte, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					received <- nil
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				want := len(hello) + 5 // one record header more
				if proxied {
					want = len(hello)
				}
				buffer := make([]byte, want)
				if _, readErr := io.ReadFull(conn, buffer); readErr != nil {
					buffer = nil
				}
				received <- buffer
			}()
			logger := &recordingLogger{}
			manager := NewConnectionManager(context.Background(), logger)
			client, server := net.Pipe()
			defer client.Close()
			metadata := adapter.InboundContext{Destination: M.SocksaddrFromNet(listener.Addr()), TCPDesync: strategy}
			if proxied {
				go manager.NewConnection(context.Background(), wrappingOutbound{}, server, metadata, nil)
			} else {
				go manager.NewConnection(context.Background(), tcpOutbound{}, server, metadata, nil)
			}
			_, err = client.Write(hello)
			require.NoError(t, err)
			got := <-received
			if proxied {
				require.Equal(t, hello, got)
				require.Eventually(t, func() bool { return logger.has("warn", "tcp_desync ignored") }, time.Second, 10*time.Millisecond)
				return
			}
			require.Len(t, got, len(hello)+5)
			require.Equal(t, hello[:3], got[:3])
			require.True(t, logger.has("debug", "tcp_desync: "+fmt.Sprint(len(hello)+5)+" bytes: 1 split"), logger.lines)
			require.False(t, logger.has("warn", "tcp_desync"))
		})
	}
}
