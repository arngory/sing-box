package tcpdesync_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/tls/chromehello"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

var errCaptured = errors.New("captured")

// captureConn keeps the first write (the ClientHello record) and fails it, which ends the handshake.
type captureConn struct {
	net.Conn
	once  sync.Once
	first []byte
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.once.Do(func() { c.first = append([]byte(nil), b...) })
	return 0, errCaptured
}

func (c *captureConn) Read([]byte) (int, error)         { return 0, errCaptured }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

// goHello is the ClientHello of Go's crypto/tls for config: X25519MLKEM768 first by default.
func goHello(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	conn := &captureConn{}
	_ = tls.Client(conn, config).Handshake()
	require.NotEmpty(t, conn.first)
	return conn.first
}

// chromeHello is the Chrome reference (common/tls/chromehello) as the core sends it, for serverName.
func chromeHello(t *testing.T, serverName string) []byte {
	t.Helper()
	spec, err := chromehello.Spec()
	require.NoError(t, err)
	conn := &captureConn{}
	uConn := utls.UClient(conn, &utls.Config{ServerName: serverName, InsecureSkipVerify: true}, utls.HelloCustom)
	require.NoError(t, uConn.ApplyPreset(spec))
	_ = uConn.Handshake()
	require.NotEmpty(t, conn.first)
	return conn.first
}

// utlsHello is the ClientHello of a uTLS preset.
func utlsHello(t *testing.T, serverName string, id utls.ClientHelloID) []byte {
	t.Helper()
	conn := &captureConn{}
	_ = utls.UClient(conn, &utls.Config{ServerName: serverName, InsecureSkipVerify: true}, id).Handshake()
	require.NotEmpty(t, conn.first)
	return conn.first
}

// echHello is a real ECH ClientHello: the outer SNI is publicName.
func echHello(t *testing.T, serverName string, publicName string) []byte {
	t.Helper()
	configPEM, _, err := sbtls.ECHKeygenDefault(publicName)
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(configPEM))
	require.NotNil(t, block)
	return goHello(t, &tls.Config{ServerName: serverName, EncryptedClientHelloConfigList: block.Bytes, MinVersion: tls.VersionTLS13})
}

type helloFixture struct {
	name string
	// sni is the name in the (outer) ClientHello; empty = none
	sni   string
	hello []byte
}

func helloFixtures(t *testing.T) []helloFixture {
	t.Helper()
	return []helloFixture{
		{"chrome-reference", "www.youtube.com", chromeHello(t, "www.youtube.com")},
		{"utls-chrome-auto", "discord.com", utlsHello(t, "discord.com", utls.HelloChrome_Auto)},
		{"go-pq", "rr1---sn-4g5edn6r.googlevideo.com", goHello(t, &tls.Config{
			ServerName: "rr1---sn-4g5edn6r.googlevideo.com",
			NextProtos: []string{"h2", "http/1.1"},
		})},
		{"no-sni", "", goHello(t, &tls.Config{InsecureSkipVerify: true})},
		{"ech", "public.example.org", echHello(t, "secret.example.com", "public.example.org")},
	}
}

// keyShareGroups lists the groups of the key_share extension of a ClientHello record.
func keyShareGroups(t *testing.T, hello []byte) []uint16 {
	t.Helper()
	b := hello[5+4:] // record header, handshake header
	b = b[2+32:]     // version, random
	b = b[1+int(b[0]):]
	b = b[2+int(binary.BigEndian.Uint16(b)):]
	b = b[1+int(b[0]):]
	b = b[2:]
	var groups []uint16
	for len(b) >= 4 {
		extType, extLen := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		data := b[4 : 4+extLen]
		if extType == 51 {
			data = data[2:]
			for len(data) >= 4 {
				group, keyLen := binary.BigEndian.Uint16(data), int(binary.BigEndian.Uint16(data[2:]))
				groups = append(groups, group)
				data = data[4+keyLen:]
			}
		}
		b = b[4+extLen:]
	}
	return groups
}

// testCertificate is a self-signed certificate for names.
func testCertificate(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
