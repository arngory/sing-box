//go:build with_naive_outbound && with_purego && windows

package naive_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The naive outbound on Windows (neko): libcronet.dll of the fork's cronet-go, loaded with purego from beside the
// executable (the desktop workflow builds the test and puts the library there, as beside the desktop's). Server and
// client run in this process on loopback, the server being the core's own naive inbound; what the outbound carries is
// echoed back.

const nekoNaiveName = "naive.test"

type nekoPKI struct {
	dir      string
	caPEM    string
	caPath   string
	certPEM  string
	keyPEM   string
	leafPin  []byte
	caSerial *big.Int
}

// nekoMakePKI: a root of its own and a leaf for nekoNaiveName under it, the leaf's key pin besides
func nekoMakePKI(t *testing.T) nekoPKI {
	t.Helper()
	now := time.Now()
	serial := func() *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "niko naive test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: nekoNaiveName},
		DNSNames:     []string{nekoNaiveName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	pki := nekoPKI{
		dir:      t.TempDir(),
		caPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		certPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		keyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		caSerial: caCert.SerialNumber,
	}
	pin := sha256.Sum256(leafCert.RawSubjectPublicKeyInfo)
	pki.leafPin = pin[:]
	pki.caPath = filepath.Join(pki.dir, "root.pem")
	if err := os.WriteFile(pki.caPath, []byte(pki.caPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	return pki
}

func nekoStartBox(t *testing.T, options option.Options) *box.Box {
	t.Helper()
	options.Log = &option.LogOptions{Level: "warn"}
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		instance.Close()
		cancel()
	})
	return instance
}

// nekoFreePort: a loopback port nothing listens on now, of the network the server takes (tcp for HTTP/2, udp for QUIC)
func nekoFreePort(t *testing.T, network string) uint16 {
	t.Helper()
	if network == N.NetworkUDP {
		packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer packetConn.Close()
		return uint16(packetConn.LocalAddr().(*net.UDPAddr).Port)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// nekoStartServer: the core's naive inbound on loopback with the leaf, over HTTP/2 (tcp) or QUIC (udp)
func nekoStartServer(t *testing.T, pki nekoPKI, network string) uint16 {
	t.Helper()
	certPath := filepath.Join(pki.dir, "leaf-"+network+".pem")
	keyPath := filepath.Join(pki.dir, "leaf-"+network+".key")
	if err := os.WriteFile(certPath, []byte(pki.certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(pki.keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	port := nekoFreePort(t, network)
	nekoStartBox(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeNaive,
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
					ListenPort: port,
				},
				Users:   []auth.User{{Username: "niko", Password: "naive-test"}},
				Network: option.NetworkList(network),
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled:         true,
						ServerName:      nekoNaiveName,
						CertificatePath: certPath,
						KeyPath:         keyPath,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
	})
	return port
}

// nekoStartEcho: a loopback TCP server that sends back what it reads
func nekoStartEcho(t *testing.T) M.Socksaddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return M.SocksaddrFromNet(listener.Addr())
}

// nekoClient: a box with the naive outbound to the server on loopback, the profile's root and key pins as given
func nekoClient(t *testing.T, port uint16, quic bool, certificate string, pins [][]byte) adapter.Outbound {
	t.Helper()
	tlsOptions := &option.OutboundTLSOptions{Enabled: true, ServerName: nekoNaiveName}
	if certificate != "" {
		tlsOptions.Certificate = badoption.Listable[string]{certificate}
	}
	if len(pins) > 0 {
		tlsOptions.CertificatePublicKeySHA256 = pins
	}
	instance := nekoStartBox(t, option.Options{
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect, Tag: "direct"},
			{
				Type: C.TypeNaive,
				Tag:  "naive-out",
				Options: &option.NaiveOutboundOptions{
					ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
					Username:                    "niko",
					Password:                    "naive-test",
					QUIC:                        quic,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
				},
			},
		},
	})
	outbound, loaded := instance.Outbound().Outbound("naive-out")
	if !loaded {
		t.Fatal("no naive-out")
	}
	return outbound
}

// nekoRoundTrip: a stream through the outbound to the echo, and back
func nekoRoundTrip(outbound adapter.Outbound, echo M.Socksaddr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, echo)
	if err != nil {
		return err
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		payload := []byte("niko naive on windows")
		if _, err := conn.Write(payload); err != nil {
			done <- err
			return
		}
		back := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, back); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(back, payload) {
			done <- fmt.Errorf("echo %q, want %q", back, payload)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		conn.Close()
		return ctx.Err()
	}
}

// TestNekoNaiveWindows: over HTTP/2 and over QUIC, the profile's own root carries, a pin of the leaf's key with it
// too, and a pin of another key does not
func TestNekoNaiveWindows(t *testing.T) {
	pki := nekoMakePKI(t)
	echo := nekoStartEcho(t)
	otherPin := sha256.Sum256([]byte("another key"))
	for _, carriage := range []struct {
		name    string
		network string
		quic    bool
	}{{"h2", N.NetworkTCP, false}, {"quic", N.NetworkUDP, true}} {
		t.Run(carriage.name, func(t *testing.T) {
			port := nekoStartServer(t, pki, carriage.network)
			if err := nekoRoundTrip(nekoClient(t, port, carriage.quic, pki.caPEM, nil), echo); err != nil {
				t.Fatalf("with the profile's root: %v", err)
			}
			if err := nekoRoundTrip(nekoClient(t, port, carriage.quic, pki.caPEM, [][]byte{pki.leafPin}), echo); err != nil {
				t.Fatalf("with the leaf's key pinned: %v", err)
			}
			if err := nekoRoundTrip(nekoClient(t, port, carriage.quic, pki.caPEM, [][]byte{otherPin[:]}), echo); err == nil {
				t.Fatal("with another key pinned: carried, want refused")
			} else {
				t.Logf("with another key pinned: refused (%v)", err)
			}
		})
	}
}

// TestNekoNaiveWindowsSystemRoots: a root in the Windows store (a corporate interceptor's, say) is not taken without
// CRONET_WINDOWS_SYSTEM_ROOTS=1, and is with it, in a process of its own. It changes the machine's store (the
// LocalMachine Root, as administrator, taken out again after), so it runs only where NEKO_NAIVE_WINDOWS_ROOTS=1 asks
// for it: the desktop workflow's runner.
func TestNekoNaiveWindowsSystemRoots(t *testing.T) {
	if os.Getenv("NEKO_NAIVE_WINDOWS_ROOTS") != "1" {
		t.Skip("changes the machine's Root store: NEKO_NAIVE_WINDOWS_ROOTS=1 runs it")
	}
	pki := nekoMakePKI(t)
	if out, err := exec.Command("certutil", "-addstore", "-f", "Root", pki.caPath).CombinedOutput(); err != nil {
		t.Fatalf("certutil -addstore: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("certutil", "-delstore", "Root", pki.caSerial.Text(16)).CombinedOutput(); err != nil {
			t.Logf("certutil -delstore: %v\n%s", err, out)
		}
	})
	echo := nekoStartEcho(t)
	port := nekoStartServer(t, pki, N.NetworkTCP)

	if os.Getenv("CRONET_WINDOWS_SYSTEM_ROOTS") != "" {
		t.Fatal("CRONET_WINDOWS_SYSTEM_ROOTS is set for the test itself")
	}
	if err := nekoRoundTrip(nekoClient(t, port, false, "", nil), echo); err == nil {
		t.Fatal("a root of the Windows store alone carried, want refused without CRONET_WINDOWS_SYSTEM_ROOTS")
	} else {
		t.Logf("without CRONET_WINDOWS_SYSTEM_ROOTS: refused (%v)", err)
	}

	child := exec.Command(os.Args[0], "-test.run=^TestNekoNaiveWindowsSystemRootsChild$", "-test.v", "-test.count=1")
	child.Env = append(os.Environ(),
		"CRONET_WINDOWS_SYSTEM_ROOTS=1",
		"NEKO_NAIVE_CHILD_PORT="+strconv.Itoa(int(port)),
		"NEKO_NAIVE_CHILD_ECHO="+echo.String(),
	)
	out, err := child.CombinedOutput()
	t.Logf("with CRONET_WINDOWS_SYSTEM_ROOTS=1:\n%s", out)
	if err != nil {
		t.Fatalf("with CRONET_WINDOWS_SYSTEM_ROOTS=1 the root of the Windows store did not carry: %v", err)
	}
	if !bytes.Contains(out, []byte("--- PASS: TestNekoNaiveWindowsSystemRootsChild")) {
		t.Fatal("the child did not run its check")
	}
}

// TestNekoNaiveWindowsSystemRootsChild: TestNekoNaiveWindowsSystemRoots's process with CRONET_WINDOWS_SYSTEM_ROOTS=1,
// against the server and echo it names
func TestNekoNaiveWindowsSystemRootsChild(t *testing.T) {
	portText := os.Getenv("NEKO_NAIVE_CHILD_PORT")
	if portText == "" {
		t.Skip("TestNekoNaiveWindowsSystemRoots runs it")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	echo := M.ParseSocksaddr(os.Getenv("NEKO_NAIVE_CHILD_ECHO"))
	if err := nekoRoundTrip(nekoClient(t, uint16(port), false, "", nil), echo); err != nil {
		t.Fatalf("a root of the Windows store with CRONET_WINDOWS_SYSTEM_ROOTS=1: %v", err)
	}
}
