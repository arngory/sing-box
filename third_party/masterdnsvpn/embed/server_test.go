package embed

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNekoRefuseQuery(t *testing.T) {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'o', 'r', 'g', 0, 0, 1, 0, 1}
	answer, err := RefuseQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer) != len(query) || answer[0] != 0x12 || answer[2] != 0x81 || answer[3] != 5 || answer[5] != 1 || answer[7] != 0 {
		t.Fatalf("% x", answer)
	}
	if _, err = RefuseQuery([]byte{1, 2}); err == nil {
		t.Fatal("short query accepted")
	}
}

// neko: the most a session's answers carry, and its probes ask, is 1232 unless niko-server says otherwise.
func TestNekoServerMaxDownloadMTU(t *testing.T) {
	options := ServerOptions{Domains: []string{"t.example.com"}, Method: 0}
	cfg, err := serverConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientMaxDownloadMTU != DefaultMaxDownloadMTU {
		t.Fatalf("default %d", cfg.ClientMaxDownloadMTU)
	}
	options.MaxDownloadMTU = 900
	if cfg, err = serverConfig(options); err != nil || cfg.ClientMaxDownloadMTU != 900 {
		t.Fatalf("900: %d %v", cfg.ClientMaxDownloadMTU, err)
	}
}

// neko: masterdns-key-rotation §3: the key file holds the current key and, under AES-GCM, the previous one
func TestNekoReadKeys(t *testing.T) {
	const a, b = "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
	write := func(text string) string {
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, c := range []struct {
		name   string
		text   string
		method int
		want   []string
	}{
		{"one", a + "\n", 5, []string{a}},
		{"two", a + "\n" + b + "\n", 5, []string{a, b}},
		{"two, CRLF and a blank line", a + "\r\n\r\n" + b, 5, []string{a, b}},
		{"three", a + "\n" + b + "\n" + a, 5, nil},
		{"none", "\n", 5, nil},
		{"two under method 2", a + "\n" + b, 2, nil},
		{"one under method 2", a, 2, []string{a}},
		{"a short one", a + "\nshort", 5, nil},
		{"method 3, 16 characters", "0123456789abcdef", 3, []string{"0123456789abcdef"}},
	} {
		got, err := readKeys(write(c.text), c.method)
		if c.want == nil {
			if err == nil {
				t.Fatalf("%s: taken %q", c.name, got)
			}
			continue
		}
		if err != nil || len(got) != len(c.want) || got[0] != c.want[0] || got[len(got)-1] != c.want[len(c.want)-1] {
			t.Fatalf("%s: %q %v", c.name, got, err)
		}
	}
	if got, err := readKeys("", 0); err != nil || len(got) != 1 || got[0] != "" {
		t.Fatalf("method 0: %q %v", got, err)
	}

	// a server made from a file of two keys takes a change of them, and refuses a bad one
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server, err := NewServer(ServerOptions{
		Domains: []string{"t.example.com"}, Method: 5, KeyFile: write(a + "\n" + b), Seal: "optional",
		Conn: conn.(*net.UDPConn), Dial: func(time.Duration) (net.Conn, error) { return nil, os.ErrClosed },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.SetKeys([]string{b}); err != nil {
		t.Fatal(err)
	}
	if err := server.SetKeys([]string{"short"}); err == nil {
		t.Fatal("a short key taken")
	}
}
