//go:build with_utls

package tls

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// recordingConn keeps what the server reads.
type recordingConn struct {
	net.Conn
	access sync.Mutex
	read   []byte
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.access.Lock()
	c.read = append(c.read, b[:n]...)
	c.access.Unlock()
	return n, err
}

// desyncServer runs a TLS server for one handshake and hands back what it read.
func desyncServer(t *testing.T, serverName string) (string, <-chan []byte) {
	t.Helper()
	certificate, err := GenerateKeyPair(nil, nil, time.Now, serverName)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	read := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			read <- nil
			return
		}
		defer conn.Close()
		recorder := &recordingConn{Conn: conn}
		server := tls.Server(recorder, &tls.Config{Certificates: []tls.Certificate{*certificate}})
		if server.Handshake() != nil {
			read <- nil
			return
		}
		_, _ = server.Write([]byte("ok"))
		recorder.access.Lock()
		read <- append([]byte(nil), recorder.read...)
		recorder.access.Unlock()
	}()
	return listener.Addr().String(), read
}

// The desync option of a TLS outbound cuts the node handshake's ClientHello, for the Go and the uTLS clients.
func TestNekoOutboundDesync(t *testing.T) {
	const serverName = "node.example.com"
	desync := &option.TCPDesyncOptions{
		Split:  []option.TCPDesyncSplitOptions{{At: "1"}, {At: "sni+1", Mode: "oob"}},
		TLSRec: []string{"sni+2"},
	}
	for _, name := range []string{"go", "utls-chrome"} {
		t.Run(name, func(t *testing.T) {
			address, read := desyncServer(t, serverName)
			options := option.OutboundTLSOptions{Enabled: true, ServerName: serverName, Insecure: true, Desync: desync}
			if name == "utls-chrome" {
				options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
			}
			config, err := NewClient(context.Background(), nil, serverName, options)
			require.NoError(t, err)
			config = config.Clone()
			conn, err := net.Dial("tcp", address)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			tlsConn, err := ClientHandshake(context.Background(), conn, config)
			require.NoError(t, err)
			buffer := make([]byte, 2)
			_, err = io.ReadFull(tlsConn, buffer)
			require.NoError(t, err)
			require.Equal(t, "ok", string(buffer))
			got := <-read
			// the ClientHello came in two records: the first is shorter than the handshake message it starts
			require.Greater(t, len(got), 10)
			require.Equal(t, byte(22), got[0])
			firstRecord := int(binary.BigEndian.Uint16(got[3:5]))
			helloLength := int(got[6])<<16 | int(got[7])<<8 | int(got[8])
			require.Less(t, firstRecord, helloLength+4)
			require.Equal(t, byte(22), got[5+firstRecord])
		})
	}
}

func TestNekoOutboundDesyncConfigErrors(t *testing.T) {
	t.Parallel()
	parsed, err := json.UnmarshalExtendedContext[option.OutboundTLSOptions](context.Background(), []byte(`{"enabled":true,"server_name":"example.com","desync":{"split":[{"at":"1"},{"at":"sni+1","mode":"oob"}],"tlsrec":"sni+2"}}`))
	require.NoError(t, err)
	_, err = NewClient(context.Background(), nil, "example.com", parsed)
	require.NoError(t, err)

	for _, test := range []struct {
		options option.OutboundTLSOptions
		message string
	}{
		{option.OutboundTLSOptions{Desync: &option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "1", Mode: "disorder"}}}}, "tls.desync: split[0]: mode disorder is not allowed for outbound handshakes"},
		{option.OutboundTLSOptions{Desync: &option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "1", Mode: "disoob"}}}}, "mode disoob is not allowed"},
		{option.OutboundTLSOptions{Desync: &option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "1", Mode: "fake"}}}}, "not supported until 1.68"},
		{option.OutboundTLSOptions{Desync: &option.TCPDesyncOptions{TLSRec: []string{"sni"}, Fake: []byte(`{"ttl":5}`)}}, "tls.desync: fake is not supported until 1.68"},
		{option.OutboundTLSOptions{Desync: &option.TCPDesyncOptions{TLSRec: []string{"sni+"}}}, "bad marker offset"},
		{option.OutboundTLSOptions{Desync: &option.TCPDesyncOptions{TLSRec: []string{"sni"}}, Fragment: true}, "mutually exclusive"},
		{option.OutboundTLSOptions{Desync: &option.TCPDesyncOptions{TLSRec: []string{"sni"}}, RecordFragment: true}, "mutually exclusive"},
	} {
		for _, utls := range []bool{false, true} {
			options := test.options
			options.Enabled = true
			options.ServerName = "example.com"
			if utls {
				options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
			}
			_, err = NewClient(context.Background(), nil, "example.com", options)
			require.ErrorContains(t, err, test.message)
		}
	}
}
