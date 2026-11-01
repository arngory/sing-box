//go:build with_utls

package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
)

// captureGroups runs a TLS server that records the ClientHello's supported groups.
func captureGroups(t *testing.T) (string, <-chan []tls.CurveID) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	groups := make(chan []tls.CurveID, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tls.Server(conn, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			groups <- hello.SupportedCurves
			return nil, errors.New("captured")
		}}).Handshake()
	}()
	return listener.Addr().String(), groups
}

func utlsHandshake(t *testing.T, address string, fingerprint string, curves ...option.CurvePreference) error {
	config, err := NewUTLSClient(context.Background(), nil, "example.com", option.OutboundTLSOptions{
		Enabled: true, ServerName: "example.com",
		UTLS:             &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
		CurvePreferences: curves,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tlsConn, err := config.Client(conn)
	if err != nil {
		t.Fatal(err)
	}
	return tlsConn.HandshakeContext(context.Background())
}

// A raycontrol node takes X25519MLKEM768 only: uTLS keeps the fingerprint but offers that group alone.
func TestNekoUTLSCurvePreferences(t *testing.T) {
	address, groups := captureGroups(t)
	utlsHandshake(t, address, "chrome", option.CurvePreference(option.X25519MLKEM768))
	got := <-groups
	if len(got) == 0 {
		t.Fatal("no groups")
	}
	for _, group := range got {
		if !isGREASECurve(utls.CurveID(group)) && group != tls.X25519MLKEM768 {
			t.Fatalf("group %v offered, want only X25519MLKEM768: %v", group, got)
		}
	}

	// without curve_preferences the fingerprint stays as it is
	address, groups = captureGroups(t)
	utlsHandshake(t, address, "chrome")
	if got = <-groups; !containsCurve(got, tls.X25519) {
		t.Fatalf("plain chrome lost X25519: %v", got)
	}

	// a fingerprint without the group fails instead of falling back
	address, _ = captureGroups(t)
	err := utlsHandshake(t, address, "chrome", option.CurvePreference(option.CurveP521))
	if err == nil || !strings.Contains(err.Error(), "no key share among curve_preferences") {
		t.Fatalf("want a key share error, got %v", err)
	}
}

func containsCurve(curves []tls.CurveID, want tls.CurveID) bool {
	for _, curve := range curves {
		if curve == want {
			return true
		}
	}
	return false
}
