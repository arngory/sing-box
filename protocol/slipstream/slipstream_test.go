package slipstream

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	dnstt "github.com/sagernet/sing-box/transport/dnstt"
)

func TestEncodeDecodeQueryNameWithDNSAuth(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	auth := &AuthConfig{Key: key}
	now := time.Unix(1_700_000_000, 0)
	payload := []byte("hello-slipstream-quic-initial-packet-payload-64-bytes-minimum!!")

	qname, err := EncodeQueryName(payload, "s.example.com", auth, now)
	if err != nil {
		t.Fatalf("EncodeQueryName failed: %v", err)
	}
	tag, decoded, err := DecodeQueryName(qname, "s.example.com", true)
	if err != nil {
		t.Fatalf("DecodeQueryName failed: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", decoded, payload)
	}
	wantTag := dnstt.AuthTag(key, now, payload)
	if !bytes.Equal(tag, wantTag) {
		t.Fatalf("dnsauth tag mismatch: got %x, want %x", tag, wantTag)
	}
}

func TestVerifySPKIPin(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cdn.example.net"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	pin := base64.RawURLEncoding.EncodeToString(sum[:])

	if err := VerifySPKIPin(cert, pin); err != nil {
		t.Fatalf("valid pin rejected: %v", err)
	}
	if err := VerifySPKIPin(cert, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Fatal("wrong pin should be rejected")
	}
}

func TestDNSPacketConnLoopbackRoundTrip(t *testing.T) {
	// Mock DNS responder that echoes the decoded query payload back inside a TXT answer.
	srvConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := srvConn.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil || len(req.Question) == 0 {
				continue
			}
			_, payload, err := DecodeQueryName(req.Question[0].Name, "s.example.com", false)
			if err != nil {
				continue
			}
			resp, err := PackTXTResponse(req, append([]byte("echo:"), payload...))
			if err != nil {
				continue
			}
			wire, err := resp.Pack()
			if err == nil {
				_, _ = srvConn.WriteTo(wire, addr)
			}
		}
	}()

	cliUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := NewDNSPacketConn(cliUDP, []*net.UDPAddr{srvConn.LocalAddr().(*net.UDPAddr)}, "s.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	msg := []byte("quic-datagram-test-packet")
	if _, err := pc.WriteTo(msg, srvConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	out := make([]byte, 512)
	n, _, err := pc.ReadFrom(out)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(out[:n]) != "echo:quic-datagram-test-packet" {
		t.Fatalf("got %q, want echo:quic-datagram-test-packet", string(out[:n]))
	}
}
