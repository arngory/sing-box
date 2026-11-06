package embed

import "testing"

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
