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
	spec, err := c.Spec()
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := net.Pipe()
	defer conn.Close()
	u := utls.UClient(conn, &utls.Config{ServerName: "www.example.com"}, utls.HelloCustom)
	if err = u.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err = u.BuildHandshakeState(); err != nil {
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
