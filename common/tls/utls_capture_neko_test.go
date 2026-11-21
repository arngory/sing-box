//go:build with_utls

package tls

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/common/tls/browserhello"

	utls "github.com/metacubex/utls"
)

// TestFingerprintsTakeTheirCaptures: each fingerprint name with a capture (browserhello) is that capture, and its
// connection builds a hello; "random" picks among Chrome's reference and the captures.
func TestFingerprintsTakeTheirCaptures(t *testing.T) {
	names := browserhello.Names()
	if len(names) == 0 {
		t.Skip("no captures")
	}
	for _, name := range names {
		id, err := uTLSClientHelloID(name)
		if err != nil {
			t.Fatal(name, err)
		}
		if id.Client != name || id.Version != helloCaptured {
			t.Fatalf("%s: %v, not its capture", name, id)
		}
		conn, _ := net.Pipe()
		u, err := newUClient(conn, &utls.Config{ServerName: "www.example.com"}, id)
		if err != nil {
			t.Fatal(name, err)
		}
		if err = u.BuildHandshakeState(); err != nil {
			t.Fatal(name, err)
		}
		conn.Close()
	}
	if randomFingerprint != helloChromeReference && randomFingerprint.Version != helloCaptured {
		t.Fatalf("random picked %v, neither Chrome's reference nor a capture", randomFingerprint)
	}
}
