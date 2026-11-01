//go:build with_yggdrasil

package yggdrasil

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// A seed and the 64-byte key yggdrasil-go stores give the same node; the certificate
// carries that key, so the node's address follows from it.
func TestNekoYggdrasilKey(t *testing.T) {
	seed := strings.Repeat("ab", 32)
	fromSeed, err := parsePrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	fromFull, err := parsePrivateKey(hex.EncodeToString(fromSeed))
	if err != nil {
		t.Fatal(err)
	}
	if !fromSeed.Equal(fromFull) {
		t.Fatal("seed and full key differ")
	}
	for _, bad := range []string{"", "xyz", strings.Repeat("ab", 16)} {
		if _, err = parsePrivateKey(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	certificate, err := selfSignedCertificate(fromSeed)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	publicKey := parsed.PublicKey.(ed25519.PublicKey)
	if !publicKey.Equal(fromSeed.Public()) {
		t.Fatal("certificate key differs")
	}
	nodeAddress := address.AddrForKey(publicKey)
	ip, _ := netip.AddrFromSlice(nodeAddress[:])
	if !yggdrasilPrefix.Contains(ip) {
		t.Fatalf("address %s outside 200::/7", ip)
	}
}

func TestNekoYggdrasilPeers(t *testing.T) {
	for _, good := range []string{"tls://1.2.3.4:443", "tcp://peer.example:1234", "quic://[2001:db8::1]:443",
		"tls://peer.example:443?key=" + strings.Repeat("ab", 32),
		// a link through niko-server's tcpmux names its route by SNI
		"tls://203.0.113.7:443?sni=y.example.com"} {
		if _, err := parsePeer(good); err != nil {
			t.Fatalf("%s: %v", good, err)
		}
	}
	for _, bad := range []string{"http://peer.example:80", "tls://", "tls://peer.example:443?key=abc", "peer.example:443"} {
		if _, err := parsePeer(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// A tls:// peer with ?sni= sends that name in its ClientHello, also when the
// peer address is an IP: niko-server routes Yggdrasil links by it.
func TestNekoYggdrasilPeerSNI(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverName := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tls.Server(conn, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName <- hello.ServerName
			return nil, errors.New("captured")
		}}).Handshake()
	}()
	privateKey, err := parsePrivateKey(strings.Repeat("cd", 32))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := selfSignedCertificate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	node, err := core.New(certificate, &coreLogger{log.NewNOPFactory().Logger()})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Stop()
	peer, err := parsePeer("tls://" + listener.Addr().String() + "?sni=y.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err = node.AddPeer(peer, ""); err != nil {
		t.Fatal(err)
	}
	select {
	case name := <-serverName:
		if name != "y.example.com" {
			t.Fatalf("SNI %q, want y.example.com", name)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no ClientHello")
	}
}
