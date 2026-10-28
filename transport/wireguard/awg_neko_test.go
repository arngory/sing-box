//go:build with_awg

package wireguard

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// An AmneziaWG 2.0 profile as Amnezia VPN exports it becomes the device's uapi lines.
func TestNekoAWGIpcLines(t *testing.T) {
	lines, err := awgIpcLines(option.AmneziaWGOptions{
		Jc: 4, Jmin: 40, Jmax: 70, S1: 15, S2: 18,
		H1: "1234567", H2: "100000-200000", H3: "3", H4: "4",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "\njc=4\njmin=40\njmax=70\ns1=15\ns2=18\nh1=1234567\nh2=100000-200000\nh3=3\nh4=4"
	if lines != want {
		t.Fatalf("got %q, want %q", lines, want)
	}
	// plain WireGuard stays byte-identical to upstream
	if lines, err = awgIpcLines(option.AmneziaWGOptions{}); err != nil || lines != "" {
		t.Fatalf("plain WireGuard: %q %v", lines, err)
	}
	// jmin above jmax is a config error, not a silent fallback
	if _, err = awgIpcLines(option.AmneziaWGOptions{Jc: 3, Jmin: 80, Jmax: 40}); err == nil {
		t.Fatal("jmin > jmax accepted")
	}
	spec, err := awgKeepaliveSpec("20-30")
	if err != nil || !strings.Contains(spec, "-") {
		t.Fatalf("keepalive range: %q %v", spec, err)
	}
}
