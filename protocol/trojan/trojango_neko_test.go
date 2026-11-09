package trojan

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// The server is sing-box's own Trojan service (whose 0x7f command serves Trojan-Go's
// smux + simplesocks), behind crypto/tls on 127.0.0.1 and, when asked, the
// shadowsocks layer; its handler reports the destination, then echoes.
type nekoTrojanGoServer struct {
	listener net.Listener
	accepted atomic.Int32
	certPEM  string
}

type nekoEchoHandler struct{}

func (nekoEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if _, err := conn.Write([]byte(destination.String() + "\n")); err != nil {
		return
	}
	io.Copy(conn, conn)
}

func (nekoEchoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	for {
		buffer := buf.NewPacket()
		buffer.Resize(64, 0) // headroom for the reply header
		target, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return
		}
		if err = conn.WritePacket(buffer, target); err != nil {
			return
		}
	}
}

func startNekoTrojanGoServer(t *testing.T, password string, ss *trojan.GoShadowsocks) *nekoTrojanGoServer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &nekoTrojanGoServer{
		listener: listener,
		certPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
	service := trojan.NewService[int](nekoEchoHandler{}, nil, log.NewNOPFactory().Logger())
	if err = service.UpdateUsers([]int{0}, []string{password}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.accepted.Add(1)
			go func() {
				if ss != nil {
					conn = ss.Conn(conn)
				}
				service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
				conn.Close()
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return server
}

func (s *nekoTrojanGoServer) outbound(t *testing.T, password string, ss *option.TrojanGoShadowsocksOptions, mux bool) *Outbound {
	port := s.listener.Addr().(*net.TCPAddr).Port
	outbound, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "trojan-go", option.TrojanOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(port)},
		Password:      password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  "127.0.0.1",
			Certificate: []string{s.certPEM},
		}},
		TrojanGoShadowsocks: ss,
		TrojanGoMux:         mux,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err = outbound.(*Outbound).Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { scope.Close() })
	return outbound.(*Outbound)
}

func nekoCheckTCP(t *testing.T, outbound *Outbound, destination string) {
	conn, err := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(destination))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := make([]byte, 100000) // several shadowsocks chunks and smux frames
	rand.Read(payload)
	go conn.Write(payload)
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(line) != destination {
		t.Fatalf("server saw destination %q, want %q", line, destination)
	}
	echo := make([]byte, len(payload))
	if _, err = io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != string(payload) {
		t.Fatal("echo differs")
	}
}

func nekoCheckUDP(t *testing.T, outbound *Outbound) {
	packetConn, err := outbound.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	packetConn.SetDeadline(time.Now().Add(5 * time.Second))
	for _, target := range []string{"1.1.1.1:53", "8.8.4.4:5353"} {
		addr := M.ParseSocksaddr(target).UDPAddr()
		if _, err = packetConn.WriteTo([]byte("ping "+target), addr); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 1500)
		n, from, err := packetConn.ReadFrom(reply)
		if err != nil {
			t.Fatal(err)
		}
		if string(reply[:n]) != "ping "+target || M.SocksaddrFromNet(from).String() != target {
			t.Fatalf("udp echo %q from %v", reply[:n], from)
		}
	}
	// DialContext("udp") is bound to its destination
	conn, err := outbound.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddr("9.9.9.9:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte("bound")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 1500)
	n, err := conn.Read(reply)
	if err != nil || string(reply[:n]) != "bound" {
		t.Fatalf("bound udp echo %q: %v", reply[:n], err)
	}
}

func TestNekoTrojanGo(t *testing.T) {
	const password = "trojan-password"
	for _, test := range []struct {
		name   string
		method string
		mux    bool
	}{
		{name: "plain"},
		{name: "ss-aes-128-gcm", method: "aes-128-gcm"},
		{name: "ss-aes-256-gcm", method: "AES-256-GCM"},
		{name: "ss-chacha20", method: "chacha20-ietf-poly1305"},
		{name: "mux", mux: true},
		{name: "ss-mux", method: "aes-128-gcm", mux: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var ssOptions *option.TrojanGoShadowsocksOptions
			var ss *trojan.GoShadowsocks
			if test.method != "" {
				ssOptions = &option.TrojanGoShadowsocksOptions{Method: test.method, Password: "ss-password"}
				var err error
				ss, err = trojan.NewGoShadowsocks(test.method, "ss-password")
				if err != nil {
					t.Fatal(err)
				}
			}
			server := startNekoTrojanGoServer(t, password, ss)
			outbound := server.outbound(t, password, ssOptions, test.mux)
			nekoCheckTCP(t, outbound, "example.com:443")
			nekoCheckTCP(t, outbound, "10.0.0.1:80")
			nekoCheckTCP(t, outbound, "[2001:db8::1]:8443")
			nekoCheckUDP(t, outbound)
			if !test.mux {
				return
			}
			// so far one Trojan connection; 8 streams at once (Trojan-Go's concurrency) still fit on it,
			// and the ninth opens a second
			if accepted := server.accepted.Load(); accepted != 1 {
				t.Fatalf("%d connections for sequential mux streams", accepted)
			}
			var conns []net.Conn
			for i := 0; i < trojan.GoMuxConcurrency+1; i++ {
				conn, err := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.org:80"))
				if err != nil {
					t.Fatal(err)
				}
				conns = append(conns, conn)
			}
			var wg sync.WaitGroup
			for _, conn := range conns {
				wg.Add(1)
				go func(conn net.Conn) {
					defer wg.Done()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					conn.Write([]byte("x"))
					reader := bufio.NewReader(conn)
					line, err := reader.ReadString('\n')
					if err != nil || line != "example.org:80\n" {
						t.Errorf("concurrent stream: %q %v", line, err)
					}
					if b, err := reader.ReadByte(); err != nil || b != 'x' {
						t.Errorf("concurrent echo: %v", err)
					}
				}(conn)
			}
			wg.Wait()
			if accepted := server.accepted.Load(); accepted != 2 {
				t.Fatalf("%d connections for %d concurrent mux streams, want 2", accepted, len(conns))
			}
			for _, conn := range conns {
				conn.Close()
			}
			// closed streams leave the sessions idle; CloseIdleConnections drops them
			time.Sleep(100 * time.Millisecond)
			outbound.CloseIdleConnections()
			nekoCheckTCP(t, outbound, "example.net:443")
			if accepted := server.accepted.Load(); accepted != 3 {
				t.Fatalf("%d connections after closing the idle sessions, want 3", accepted)
			}
		})
	}
}

// A wrong password for the shadowsocks layer fails the request instead of passing data.
func TestNekoTrojanGoShadowsocksWrongPassword(t *testing.T) {
	serverSS, err := trojan.NewGoShadowsocks("aes-128-gcm", "right")
	if err != nil {
		t.Fatal(err)
	}
	server := startNekoTrojanGoServer(t, "p", serverSS)
	outbound := server.outbound(t, "p", &option.TrojanGoShadowsocksOptions{Method: "aes-128-gcm", Password: "wrong"}, false)
	conn, err := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("x"))
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("read through a mismatched shadowsocks layer")
	}
	for _, method := range []string{"aes-192-gcm", "rc4-md5", "2022-blake3-aes-128-gcm"} {
		if _, err = trojan.NewGoShadowsocks(method, "x"); err == nil {
			t.Fatalf("accepted %s, which Trojan-Go (go-shadowsocks2) refuses", method)
		}
	}
}

// The layer's bytes, opened with a from-scratch go-shadowsocks2 reading: EVP_BytesToKey(MD5)
// master key, HKDF-SHA1(key, salt, "ss-subkey"), then [len+tag][payload+tag] chunks,
// little-endian counter nonces, and nothing else (no address header).
func TestNekoTrojanGoShadowsocksWire(t *testing.T) {
	for _, test := range []struct {
		method  string
		keySize int
		aead    func(key []byte) (cipher.AEAD, error)
	}{
		{"aes-128-gcm", 16, func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}},
		{"aes-256-gcm", 32, func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}},
		{"chacha20-ietf-poly1305", 32, chacha20poly1305.New},
	} {
		layer, err := trojan.NewGoShadowsocks(test.method, "pass")
		if err != nil {
			t.Fatal(err)
		}
		client, server := net.Pipe()
		conn := layer.Conn(client)
		payload := []byte("trojan request goes here")
		go func() {
			conn.Write(payload)
			conn.Write([]byte("second"))
		}()
		var master, prev []byte
		for len(master) < test.keySize {
			h := md5.New()
			h.Write(prev)
			h.Write([]byte("pass"))
			master = h.Sum(master)
			prev = master[len(master)-md5.Size:]
		}
		master = master[:test.keySize]
		salt := make([]byte, test.keySize)
		if _, err = io.ReadFull(server, salt); err != nil {
			t.Fatal(err)
		}
		subkey := make([]byte, test.keySize)
		io.ReadFull(hkdf.New(sha1.New, master, salt, []byte("ss-subkey")), subkey)
		aead, err := test.aead(subkey)
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, aead.NonceSize())
		readChunk := func() []byte {
			lengthBox := make([]byte, 2+aead.Overhead())
			if _, err := io.ReadFull(server, lengthBox); err != nil {
				t.Fatal(err)
			}
			length, err := aead.Open(nil, nonce, lengthBox, nil)
			if err != nil {
				t.Fatalf("%s: length chunk: %v", test.method, err)
			}
			nonce[0]++
			box := make([]byte, int(binary.BigEndian.Uint16(length))+aead.Overhead())
			if _, err = io.ReadFull(server, box); err != nil {
				t.Fatal(err)
			}
			plain, err := aead.Open(nil, nonce, box, nil)
			if err != nil {
				t.Fatalf("%s: payload chunk: %v", test.method, err)
			}
			nonce[0]++
			return plain
		}
		if got := readChunk(); string(got) != string(payload) {
			t.Fatalf("%s: first chunk %q", test.method, got)
		}
		if got := readChunk(); string(got) != "second" {
			t.Fatalf("%s: second chunk %q", test.method, got)
		}
		client.Close()
		server.Close()
	}
}
