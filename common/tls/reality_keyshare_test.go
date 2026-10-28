//go:build with_utls

package tls

import (
	"net"
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing/common"
)

// The Chrome fingerprint must carry X25519MLKEM768 (Xray >= v26.9.8 requires it) next to plain
// X25519 (older REALITY servers derive the AuthKey from it), and the classical filter must drop it.
func TestRealityChromeKeyShares(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	uConn := utls.UClient(client, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if !realityHelloCarriesHybridShare(uConn) {
		t.Fatal("chrome hello has no X25519MLKEM768 share")
	}
	keys := uConn.HandshakeState.State13.KeyShareKeys
	if keys == nil || (keys.Ecdhe == nil && keys.MlkemEcdhe == nil) {
		t.Fatal("no X25519 key for the REALITY AuthKey")
	}
	for _, extension := range uConn.Extensions {
		if ks, ok := extension.(*utls.KeyShareExtension); ok {
			ks.KeyShares = common.Filter(ks.KeyShares, func(share utls.KeyShare) bool {
				return share.Group != utls.X25519MLKEM768
			})
		}
	}
	if realityHelloCarriesHybridShare(uConn) {
		t.Fatal("classical filter left the hybrid share")
	}
}
