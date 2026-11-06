//go:build with_quic

package hysteria2_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// neko: a client that half-closes (nc at the end of its input) through a Hysteria2 stream still gets the answer the
// target gives once it has read to the end: the stream's sides close one by one (sing-quic's CloseWrite), where
// before the core closed it whole and the answer was lost.
func TestNekoHysteria2HalfClose(t *testing.T) {
	// the target answers only once the question has ended
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				question, _ := io.ReadAll(conn)
				conn.Write(append([]byte("answer to "), question...))
			}()
		}
	}()
	certificate, key := nekoSelfSigned(t)
	serverPort, socksPort := nekoFreePort(t, "udp"), nekoFreePort(t, "tcp")
	nekoStartBox(t, fmt.Sprintf(`{"log":{"level":"error"},
		"inbounds":[{"type":"hysteria2","listen":"127.0.0.1","listen_port":%d,"users":[{"password":"neko"}],
			"tls":{"enabled":true,"certificate":%s,"key":%s}}],
		"outbounds":[{"type":"direct"}]}`, serverPort, nekoLines(certificate), nekoLines(key)))
	nekoStartBox(t, fmt.Sprintf(`{"log":{"level":"error"},
		"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":%d}],
		"outbounds":[{"type":"hysteria2","server":"127.0.0.1","server_port":%d,"password":"neko",
			"tls":{"enabled":true,"server_name":"localhost","insecure":true}}]}`, socksPort, serverPort))

	for _, question := range []string{"the question", ""} {
		conn := nekoSocksConnect(t, socksPort, target.Addr().(*net.TCPAddr))
		if question != "" {
			if _, err := conn.Write([]byte(question)); err != nil {
				t.Fatal(err)
			}
		}
		// a question of nothing: the half-close is all the stream carries, the request goes out with it
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		answer, err := io.ReadAll(conn)
		conn.Close()
		if want := "answer to " + question; string(answer) != want {
			t.Fatalf("the answer after a half-close: %q %v, want %q", answer, err, want)
		}
	}
}

func nekoStartBox(t *testing.T, config string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ctx = include.Context(ctx)
	var options option.Options
	if err := options.UnmarshalJSONContext(ctx, []byte(config)); err != nil {
		cancel()
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		instance.Close()
		cancel()
	})
}

// nekoSocksConnect is a SOCKS5 CONNECT to target through 127.0.0.1:port
func nekoSocksConnect(t *testing.T, port int, target *net.TCPAddr) *net.TCPConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	request := append([]byte{5, 1, 0, 5, 1, 0, 1}, target.IP.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(target.Port))
	if _, err = conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2+10)
	if _, err = io.ReadFull(conn, reply); err != nil || reply[1] != 0 || reply[3] != 0 {
		t.Fatalf("socks: %x %v", reply, err)
	}
	conn.SetDeadline(time.Time{})
	return conn.(*net.TCPConn)
}

func nekoFreePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).Port
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func nekoSelfSigned(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// nekoLines is a PEM as the JSON list of its lines
func nekoLines(text string) string {
	raw, _ := json.Marshal(strings.Split(strings.TrimSpace(text), "\n"))
	return string(raw)
}
