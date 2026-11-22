package tcpdesync_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tcpdesync"
	"github.com/sagernet/sing-box/common/tls/chromehello"
	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// loopbackPair is a connected TCP pair on 127.0.0.1.
func loopbackPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := listener.AcceptTCP()
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	server := <-accepted
	require.NotNil(t, server)
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

// TestTLSServerAcceptsCuts: Go's crypto/tls server completes the handshake with ClientHellos cut into records and
// segments, from crypto/tls and from the Chrome reference.
func TestTLSServerAcceptsCuts(t *testing.T) {
	const serverName = "www.youtube.com"
	strategies := []option.TCPDesyncOptions{
		{TLSRec: []string{"sni+2"}},
		{TLSRec: []string{"sniext", "sni+2", "midsld", "-1", "8"}, Split: splits("1", "split", "sni+1", "split")},
		{Split: splits("1", "split", "midsld", "split", "-5", "split")},
	}
	if runtime.GOOS == "linux" {
		strategies = append(strategies,
			option.TCPDesyncOptions{TLSRec: []string{"sni+1"}, Split: splits("1", "split", "sni+1", "disoob")},
			option.TCPDesyncOptions{TLSRec: []string{"midsld"}, Split: splits("sni+1", "oob", "endhost", "disorder")},
		)
	}
	certificate := testCertificate(t, serverName)
	for _, options := range strategies {
		strategy := mustStrategy(t, options)
		for _, client := range []string{"go", "chrome-reference"} {
			t.Run(client+" "+strategy.String(), func(t *testing.T) {
				clientConn, serverConn := loopbackPair(t)
				serverDone := make(chan error, 1)
				go func() {
					server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
					err := server.Handshake()
					if err == nil {
						_, err = server.Write([]byte("hello"))
					}
					serverDone <- err
				}()
				conn := tcpdesync.NewConn(context.Background(), clientConn, strategy, nil)
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				var tlsConn io.ReadWriter
				switch client {
				case "go":
					goConn := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
					require.NoError(t, goConn.Handshake())
					require.Equal(t, uint16(tls.VersionTLS13), goConn.ConnectionState().Version)
					tlsConn = goConn
				default:
					spec, err := chromehello.Spec()
					require.NoError(t, err)
					uConn := utls.UClient(conn, &utls.Config{ServerName: serverName, InsecureSkipVerify: true}, utls.HelloCustom)
					require.NoError(t, uConn.ApplyPreset(spec))
					require.NoError(t, uConn.Handshake())
					tlsConn = uConn
				}
				buffer := make([]byte, 5)
				_, err := io.ReadFull(tlsConn, buffer)
				require.NoError(t, err)
				require.Equal(t, "hello", string(buffer))
				require.NoError(t, <-serverDone)
			})
		}
	}
}

// TestNoSocket: over something that is not a TCP socket only the records are cut, and the stream stays whole.
func TestNoSocket(t *testing.T) {
	t.Parallel()
	hello := chromeHello(t, "www.youtube.com")
	strategy := mustStrategy(t, option.TCPDesyncOptions{TLSRec: []string{"sni+1"}, Split: splits("1", "oob")})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := tcpdesync.NewConn(context.Background(), client, strategy, nil)
	received := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, len(hello)+5)
		_, err := io.ReadFull(server, buffer)
		if err != nil {
			buffer = nil
		}
		received <- buffer
	}()
	_, err := conn.Write(hello)
	require.NoError(t, err)
	got := <-received
	headers, payloads := records(t, got)
	require.Len(t, headers, 2)
	require.Equal(t, hello[5:], append(payloads[0], payloads[1]...))
	require.True(t, conn.WriterReplaceable())
}

// failingConn fails every write.
type failingConn struct {
	net.Conn
	written int
}

func (c *failingConn) Write(b []byte) (int, error) {
	c.written += len(b)
	return 0, io.ErrClosedPipe
}

// TestHeldHelloFlushFailureSticks: when the timer cannot send a held part of a ClientHello, the stream has a hole;
// every later write fails with that error instead of reaching the server after it.
func TestHeldHelloFlushFailureSticks(t *testing.T) {
	client, _ := loopbackPair(t)
	hello := chromeHello(t, "www.youtube.com")
	conn := &failingConn{Conn: client}
	desync := tcpdesync.NewConn(context.Background(), conn, mustStrategy(t, option.TCPDesyncOptions{TLSRec: []string{"sni+1"}}), nil)
	n, err := desync.Write(hello[:100])
	require.NoError(t, err)
	require.Equal(t, 100, n)
	time.Sleep(tcpdesync.BufferTimeout + 100*time.Millisecond)
	_, err = desync.Write(hello[100:])
	require.ErrorIs(t, err, io.ErrClosedPipe)
	_, err = desync.Write([]byte("later"))
	require.ErrorIs(t, err, io.ErrClosedPipe)
}
