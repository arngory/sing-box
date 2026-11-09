package trojan

// neko: client side of Trojan-Go's extras on top of plain Trojan, following
// github.com/p4gefau1t/trojan-go v0.10.6:
//
//   - tunnel/shadowsocks: after TLS (and the WebSocket, if any) the stream is a
//     go-shadowsocks2 AEAD stream (core.PickCipher(method, nil, password) then
//     Cipher.StreamConn), with no Shadowsocks address header: Trojan's own
//     request follows inside.
//   - tunnel/mux + tunnel/simplesocks: one Trojan request with command 0x7f and
//     the address MUX_CONN:0 opens an xtaci/smux session (smux.DefaultConfig,
//     version 1); each smux stream starts with a "simplesocks" header, the
//     Trojan command (1 connect, 3 associate) and a SOCKS address with no CRLF.
//     An associate stream carries Trojan's UDP framing (addr, length, CRLF,
//     payload), its header address being UDP_CONN:0.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xtaci/smux"
	"golang.org/x/crypto/chacha20poly1305"
)

// GoShadowsocks is Trojan-Go's shadowsocks AEAD layer. The stream is the same
// in both directions, so Conn serves the client and a test server alike.
type GoShadowsocks struct {
	saltLength  int
	constructor func(key []byte) (cipher.AEAD, error)
	key         []byte
}

// NewGoShadowsocks accepts the methods go-shadowsocks2 v0.1.5 (Trojan-Go's
// dependency) accepts, case-insensitively, under either spelling.
func NewGoShadowsocks(method string, password string) (*GoShadowsocks, error) {
	layer := &GoShadowsocks{}
	switch strings.ToUpper(method) {
	case "", "AES-128-GCM", "AEAD_AES_128_GCM": // Trojan-Go's default
		layer.saltLength = 16
		layer.constructor = newAESGCM
	case "AES-256-GCM", "AEAD_AES_256_GCM":
		layer.saltLength = 32
		layer.constructor = newAESGCM
	case "CHACHA20-IETF-POLY1305", "AEAD_CHACHA20_POLY1305":
		layer.saltLength = 32
		layer.constructor = chacha20poly1305.New
	default:
		return nil, E.New("trojan-go shadowsocks: unsupported method ", method, " (aes-128-gcm, aes-256-gcm or chacha20-ietf-poly1305)")
	}
	if password == "" {
		return nil, E.New("trojan-go shadowsocks: missing password")
	}
	// EVP_BytesToKey(MD5), as go-shadowsocks2's core.kdf
	layer.key = shadowsocks.Key([]byte(password), layer.saltLength)
	return layer, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (l *GoShadowsocks) Conn(conn net.Conn) net.Conn {
	return &goShadowsocksConn{Conn: conn, layer: l}
}

type goShadowsocksConn struct {
	net.Conn
	layer       *GoShadowsocks
	readAccess  sync.Mutex
	reader      *shadowaead.Reader
	writeAccess sync.Mutex
	writer      *shadowaead.Writer
}

func (l *GoShadowsocks) subkeyCipher(salt []byte) (cipher.AEAD, error) {
	subkey := buf.NewSize(l.saltLength)
	defer subkey.Release()
	shadowaead.Kdf(l.key, salt, subkey)
	return l.constructor(subkey.Bytes())
}

func (c *goShadowsocksConn) Read(p []byte) (int, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if c.reader == nil {
		salt := make([]byte, c.layer.saltLength)
		_, err := io.ReadFull(c.Conn, salt)
		if err != nil {
			return 0, E.Cause(err, "trojan-go shadowsocks: read salt")
		}
		readCipher, err := c.layer.subkeyCipher(salt)
		if err != nil {
			return 0, err
		}
		c.reader = shadowaead.NewReader(c.Conn, readCipher, shadowaead.MaxPacketSize)
	}
	return c.reader.Read(p)
}

func (c *goShadowsocksConn) Write(p []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if c.writer != nil {
		return c.writer.Write(p)
	}
	salt := make([]byte, c.layer.saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return 0, err
	}
	writeCipher, err := c.layer.subkeyCipher(salt)
	if err != nil {
		return 0, err
	}
	writer := shadowaead.NewWriter(c.Conn, writeCipher, shadowaead.MaxPacketSize)
	// the salt and the first chunk leave in one write
	header := writer.Buffer()
	common.Must1(header.Write(salt))
	bufferedWriter := writer.BufferedWriter(header.Len())
	_, err = bufferedWriter.Write(p)
	if err == nil {
		err = bufferedWriter.Flush()
	}
	if err != nil {
		return 0, err
	}
	c.writer = writer
	return len(p), nil
}

func (c *goShadowsocksConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *goShadowsocksConn) Upstream() any {
	return c.Conn
}

// Trojan-Go's tunnel/mux client defaults (mux.concurrency, mux.idle_timeout)
const (
	GoMuxConcurrency = 8
	GoMuxIdleTimeout = 30 * time.Second
)

var (
	goMuxAddress = M.ParseSocksaddrHostPort("MUX_CONN", 0)
	goUDPAddress = M.ParseSocksaddrHostPort("UDP_CONN", 0)
)

// GoMuxClient keeps a pool of smux sessions, each one Trojan connection, and
// opens up to GoMuxConcurrency streams on each, as Trojan-Go's mux client does.
type GoMuxClient struct {
	dial        func(ctx context.Context) (net.Conn, error)
	key         [KeyLength]byte
	concurrency int
	idleTimeout time.Duration
	access      sync.Mutex
	sessions    []*goMuxSession
	keepIdle    bool
	ctx         context.Context
	cancel      context.CancelFunc
	loopOnce    sync.Once
}

type goMuxSession struct {
	// streams being opened on it, not yet counted by the session (under the client's access)
	opening    int
	session    *smux.Session
	lastActive time.Time
}

// NewGoMuxClient: dial gives the connection Trojan's request goes on (after
// TLS, the transport and the shadowsocks layer).
func NewGoMuxClient(dial func(ctx context.Context) (net.Conn, error), key [KeyLength]byte) *GoMuxClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &GoMuxClient{
		dial:        dial,
		key:         key,
		concurrency: GoMuxConcurrency,
		idleTimeout: GoMuxIdleTimeout,
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (c *GoMuxClient) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		stream, err := c.openStream(ctx)
		if err != nil {
			return nil, err
		}
		return &goMuxStreamConn{Conn: stream, destination: destination}, nil
	case N.NetworkUDP:
		packetConn, err := c.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

// ListenPacket opens an associate stream (Trojan-Go's simplesocks DialPacket).
func (c *GoMuxClient) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	stream, err := c.openStream(ctx)
	if err != nil {
		return nil, err
	}
	header := buf.NewSize(1 + M.SocksaddrSerializer.AddrPortLen(goUDPAddress))
	defer header.Release()
	common.Must(header.WriteByte(CommandUDP))
	common.Must(M.SocksaddrSerializer.WriteAddrPort(header, goUDPAddress))
	_, err = stream.Write(header.Bytes())
	if err != nil {
		stream.Close()
		return nil, E.Cause(err, "trojan-go mux: write associate")
	}
	return &ClientPacketConn{Conn: stream, headerWritten: true}, nil
}

func (c *GoMuxClient) openStream(ctx context.Context) (net.Conn, error) {
	c.loopOnce.Do(func() { go c.cleanLoop() })
	c.access.Lock()
	sessions := c.sessions[:0]
	var picked *goMuxSession
	for _, s := range c.sessions {
		if s.session.IsClosed() {
			continue
		}
		sessions = append(sessions, s)
		// the streams being opened on it count too: parallel dials do not all pile onto one session (neko)
		if picked == nil && (c.concurrency <= 0 || s.session.NumStreams()+s.opening < c.concurrency) {
			picked = s
		}
	}
	c.sessions = sessions
	if picked != nil {
		picked.opening++
	}
	c.access.Unlock()
	if picked != nil {
		reserved := picked
		defer func() {
			c.access.Lock()
			reserved.opening--
			c.access.Unlock()
		}()
	}
	fresh := picked == nil
	if fresh {
		var err error
		picked, err = c.newSession(ctx)
		if err != nil {
			return nil, err
		}
	}
	stream, err := picked.session.OpenStream()
	if err != nil && !fresh {
		// the pooled session died since: once more on a new one
		picked.session.Close()
		picked, err = c.newSession(ctx)
		if err != nil {
			return nil, err
		}
		stream, err = picked.session.OpenStream()
	}
	if err != nil {
		picked.session.Close()
		return nil, E.Cause(err, "trojan-go mux: open stream")
	}
	c.access.Lock()
	picked.lastActive = time.Now()
	c.access.Unlock()
	return stream, nil
}

func (c *GoMuxClient) newSession(ctx context.Context) (*goMuxSession, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	session, err := smux.Client(&goMuxConn{Conn: conn, key: c.key}, smux.DefaultConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}
	s := &goMuxSession{session: session, lastActive: time.Now()}
	c.access.Lock()
	if c.ctx.Err() != nil {
		c.access.Unlock()
		session.Close()
		return nil, net.ErrClosed
	}
	c.sessions = append(c.sessions, s)
	c.access.Unlock()
	return s, nil
}

func (c *GoMuxClient) cleanLoop() {
	ticker := time.NewTicker(c.idleTimeout / 4)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.closeIdle(false)
		}
	}
}

// closeIdle closes the sessions with no stream; unless now, only those idle for idleTimeout.
func (c *GoMuxClient) closeIdle(now bool) {
	c.access.Lock()
	defer c.access.Unlock()
	if !now && c.keepIdle {
		return
	}
	sessions := c.sessions[:0]
	for _, s := range c.sessions {
		if s.session.IsClosed() {
			continue
		}
		if s.session.NumStreams() == 0 && (now || time.Since(s.lastActive) > c.idleTimeout) {
			s.session.Close()
			continue
		}
		sessions = append(sessions, s)
	}
	c.sessions = sessions
}

func (c *GoMuxClient) SetKeepIdleConnections(keep bool) {
	c.access.Lock()
	c.keepIdle = keep
	c.access.Unlock()
}

func (c *GoMuxClient) CloseIdleConnections() {
	c.closeIdle(true)
}

// Reset closes every session, streams included.
func (c *GoMuxClient) Reset() {
	c.access.Lock()
	sessions := c.sessions
	c.sessions = nil
	c.access.Unlock()
	for _, s := range sessions {
		s.session.Close()
	}
}

func (c *GoMuxClient) Close() error {
	c.cancel()
	c.Reset()
	return nil
}

// goMuxConn is the Trojan connection under an smux session; its request goes with smux's first frame.
type goMuxConn struct {
	net.Conn
	key           [KeyLength]byte
	access        sync.Mutex
	headerWritten bool
}

func (c *goMuxConn) Write(p []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.headerWritten {
		return c.Conn.Write(p)
	}
	err := ClientHandshakeRaw(c.Conn, c.key, CommandMux, goMuxAddress, p)
	if err != nil {
		return 0, err
	}
	c.headerWritten = true
	return len(p), nil
}

// goMuxStreamConn writes simplesocks' connect header with its first write.
type goMuxStreamConn struct {
	net.Conn
	destination   M.Socksaddr
	headerWritten bool
}

func (c *goMuxStreamConn) NeedHandshakeForWrite() bool {
	return !c.headerWritten
}

func (c *goMuxStreamConn) Write(p []byte) (int, error) {
	if c.headerWritten {
		return c.Conn.Write(p)
	}
	header := buf.NewSize(1 + M.SocksaddrSerializer.AddrPortLen(c.destination) + len(p))
	defer header.Release()
	common.Must(header.WriteByte(CommandTCP))
	err := M.SocksaddrSerializer.WriteAddrPort(header, c.destination)
	if err != nil {
		return 0, err
	}
	common.Must1(header.Write(p))
	_, err = c.Conn.Write(header.Bytes())
	if err != nil {
		return 0, E.Cause(err, "trojan-go mux: write request")
	}
	c.headerWritten = true
	return len(p), nil
}

func (c *goMuxStreamConn) Upstream() any {
	return c.Conn
}

func (c *goMuxStreamConn) ReaderReplaceable() bool {
	return true
}

func (c *goMuxStreamConn) WriterReplaceable() bool {
	return c.headerWritten
}
