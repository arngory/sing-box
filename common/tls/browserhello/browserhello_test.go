package browserhello

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/tls/chromehello"

	utls "github.com/metacubex/utls"
)

func coreHello(t *testing.T, c *Capture) *chromehello.Hello {
	t.Helper()
	conn, _ := net.Pipe()
	defer conn.Close()
	u := utls.UClient(conn, &utls.Config{ServerName: "www.example.com"}, utls.HelloCustom)
	if err := c.Apply(u); err != nil {
		t.Fatal(err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	h, err := chromehello.Parse(u.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// order is the extensions in the order sent, GREASE as one, the server name and padding left out
func order(h *chromehello.Hello) string {
	var ids []string
	for _, id := range h.Extensions {
		switch {
		case id == 0x0000 || id == 0x0015:
		case chromehello.IsGREASE(id):
			ids = append(ids, "GREASE")
		default:
			ids = append(ids, fmt.Sprintf("%04x", id))
		}
	}
	return strings.Join(ids, ",")
}

// TestCoreSendsTheCapture: for each capture, what the core sends has its shape and JA4; a client that does not
// shuffle its extensions has them in the capture's order too.
func TestCoreSendsTheCapture(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			c, _ := Get(name)
			captured, err := chromehello.Parse(c.Raw)
			if err != nil {
				t.Fatal(err)
			}
			for range 5 {
				core := coreHello(t, c)
				if core.Shape() != captured.Shape() {
					t.Fatalf("shape differs\n--- capture\n%s\n--- core\n%s", captured.Shape(), core.Shape())
				}
				if core.JA4() != captured.JA4() {
					t.Fatalf("JA4 %s, capture %s", core.JA4(), captured.JA4())
				}
				if !c.Shuffle && order(core) != order(captured) {
					t.Fatalf("extension order differs\n--- capture %s\n--- core    %s", order(captured), order(core))
				}
			}
			t.Logf("JA4 %s, shuffled %v (%s)", captured.JA4(), c.Shuffle, c.Source)
		})
	}
}

// TestPerConnection: what a client makes anew per connection is new in the core's hellos too: the key shares, the
// GREASE ECH payload; the order of extensions where the client shuffles it, and only there.
func TestPerConnection(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			c, _ := Get(name)
			orders, shares, ech := map[string]bool{}, map[string]bool{}, map[string]bool{}
			for range 20 {
				h := coreHello(t, c)
				orders[order(h)] = true
				shares[fmt.Sprintf("%x", h.Data[0x0033])] = true
				if payload, ok := h.Data[0xfe0d]; ok {
					ech[fmt.Sprintf("%x", payload)] = true
				}
			}
			if len(shares) != 20 {
				t.Fatalf("key shares repeated: %d distinct of 20", len(shares))
			}
			if len(ech) != 0 && len(ech) != 20 {
				t.Fatalf("the ECH payload repeated: %d distinct of 20", len(ech))
			}
			if c.Shuffle && len(orders) < 2 {
				t.Fatal("a shuffling client's extensions came in one order 20 times")
			}
			if !c.Shuffle && len(orders) != 1 {
				t.Fatalf("a client that keeps its order sent %d orders", len(orders))
			}
		})
	}
}

// TestX25519KeyAsTheClient: a client that puts one X25519 key in its hybrid and its X25519 share (Firefox) has the
// core do the same, and one that does not, not; the key the handshake keeps for X25519 is the one in the hello.
func TestX25519KeyAsTheClient(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			c, _ := Get(name)
			conn, _ := net.Pipe()
			defer conn.Close()
			u := utls.UClient(conn, &utls.Config{ServerName: "www.example.com"}, utls.HelloCustom)
			if err := c.Apply(u); err != nil {
				t.Fatal(err)
			}
			if err := u.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			shares, err := KeyShares(u.HandshakeState.Hello.Raw)
			if err != nil {
				t.Fatal(err)
			}
			hybrid, x25519 := shares[uint16(utls.X25519MLKEM768)], shares[uint16(utls.X25519)]
			if len(hybrid) == 0 || len(x25519) == 0 {
				return
			}
			reused := string(hybrid[len(hybrid)-32:]) == string(x25519)
			if reused != c.ReuseX25519 {
				t.Fatalf("the core reuses the X25519 key: %v, the client: %v", reused, c.ReuseX25519)
			}
			if keys := u.HandshakeState.State13.KeyShareKeys; string(keys.Ecdhe.PublicKey().Bytes()) != string(x25519) {
				t.Fatal("the handshake's X25519 key is not the one in the hello")
			}
		})
	}
}
