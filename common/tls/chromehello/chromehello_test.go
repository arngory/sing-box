package chromehello

import (
	"net"
	"testing"

	utls "github.com/metacubex/utls"
)

func coreHello(t *testing.T, serverName string) []byte {
	t.Helper()
	spec, err := Spec()
	if err != nil {
		t.Fatal(err)
	}
	c, _ := net.Pipe()
	defer c.Close()
	u := utls.UClient(c, &utls.Config{ServerName: serverName}, utls.HelloCustom)
	if err = u.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err = u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return u.HandshakeState.Hello.Raw
}

// TestShapeEqualsCapture: what the core sends has the capture's shape and JA4.
func TestShapeEqualsCapture(t *testing.T) {
	raw, err := Raw()
	if err != nil {
		t.Fatal(err)
	}
	captured, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		core, err := Parse(coreHello(t, "www.example.com"))
		if err != nil {
			t.Fatal(err)
		}
		if core.Shape() != captured.Shape() {
			t.Fatalf("shape differs\n--- capture\n%s\n--- core\n%s", captured.Shape(), core.Shape())
		}
		if core.JA4() != captured.JA4() {
			t.Fatalf("JA4 %s, capture %s", core.JA4(), captured.JA4())
		}
	}
	t.Logf("JA4 %s (%s)", captured.JA4(), Source)
}

// TestPerConnection: the order of extensions, GREASE (also in signature_algorithms) and key shares change.
func TestPerConnection(t *testing.T) {
	orders := map[string]bool{}
	sigGREASE := map[string]bool{}
	keys := map[string]bool{}
	for range 20 {
		h, err := Parse(coreHello(t, "www.example.com"))
		if err != nil {
			t.Fatal(err)
		}
		var order []byte
		for _, id := range h.Extensions {
			order = append(order, byte(id>>8), byte(id))
		}
		orders[string(order)] = true
		sigGREASE[string(h.Data[extSigAlgs][2:4])] = true
		keys[string(h.Data[extKeyShare])] = true
	}
	if len(orders) < 10 || len(sigGREASE) < 3 || len(keys) != 20 {
		t.Fatalf("per connection: %d orders, %d signature GREASE values, %d key shares of 20", len(orders), len(sigGREASE), len(keys))
	}
}

// TestNoSNIForAddress: like Chrome, no server_name for an IP address; and never the capture's name.
func TestNoSNIForAddress(t *testing.T) {
	h, err := Parse(coreHello(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Data[extSNI]; ok {
		t.Fatal("SNI sent for an address")
	}
	h, _ = Parse(coreHello(t, "www.example.com"))
	if string(h.Data[extSNI][5:]) != "www.example.com" {
		t.Fatalf("SNI %q", h.Data[extSNI])
	}
}
