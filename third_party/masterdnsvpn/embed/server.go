package embed

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/udpserver"
)

// UDPConn is the DNS socket the server reads queries from and answers on.
type UDPConn = udpserver.UDPConn

// ServerOptions configure an embedded MasterDnsVPN server (neko: niko-server's masterdns backend).
type ServerOptions struct {
	Domains []string
	// Method is DATA_ENCRYPTION_METHOD; raycontrol nodes use 5 (AES-256-GCM)
	Method int
	// KeyFile holds the key as text, as the server's own key file; it is never generated here
	KeyFile  string
	LogLevel string
	// Conn is the DNS socket (a virtual one fed by niko-server's front)
	Conn UDPConn
	// Dial connects a client stream to the one fixed upstream (TCP mode)
	Dial func(timeout time.Duration) (net.Conn, error)
	// MaxDownloadMTU is the most a session's answers carry and its MTU probes ask
	// (MAX_ALLOWED_CLIENT_DOWNLOAD_MTU); 0 is DefaultMaxDownloadMTU
	MaxDownloadMTU int
	// Seal is mdseal-v1's mode: "" or "off", "optional", "required" (raycontrol docs/spec/mdseal-v1.md §5); the key
	// is the text of KeyFile, and a seal needs one (Method 1-5)
	Seal string
	// Log receives the server log (nil: discarded)
	Log io.Writer
}

// DefaultMaxDownloadMTU bounds a session's answers and the MTU probes: an answer that carries more passes few resolvers
// (most take 1232 bytes), and a probe for 4096 reflected about 50 times its query.
const DefaultMaxDownloadMTU = 1232

// RunServer serves until ctx ends or the server stops.
func RunServer(ctx context.Context, options ServerOptions) error {
	if len(options.Domains) == 0 {
		return errors.New("masterdnsvpn: no domains")
	}
	if options.Conn == nil || options.Dial == nil {
		return errors.New("masterdnsvpn: socket and upstream dialer are required")
	}
	cfg, err := serverConfig(options)
	if err != nil {
		return err
	}
	seal, err := udpserver.ParseSealMode(options.Seal)
	if err != nil {
		return err
	}
	key, err := readKey(options.KeyFile, options.Method)
	if err != nil {
		return err
	}
	if seal != 0 && key == "" {
		return errors.New("masterdnsvpn: a seal needs the key (DATA_ENCRYPTION_METHOD 1-5)")
	}
	codec, err := security.NewCodecFromConfig(cfg, key)
	if err != nil {
		return fmt.Errorf("masterdnsvpn: %w", err)
	}
	var log *logger.Logger
	if options.Log != nil {
		log = logger.NewWithWriter("MasterDnsVPN Server", cfg.LogLevel, options.Log)
	} else {
		log = logger.NewWithWriter("MasterDnsVPN Server", cfg.LogLevel, io.Discard)
	}
	server := udpserver.New(cfg, log, codec)
	if err := server.SetSeal(seal, key); err != nil {
		return fmt.Errorf("masterdnsvpn: seal: %w", err)
	}
	server.SetListener(options.Conn)
	server.SetStreamDialer(func(_, _ string, timeout time.Duration) (net.Conn, error) {
		return options.Dial(timeout)
	})
	// DNS queries through the tunnel get REFUSED: the node resolves nothing itself
	// (the client resolves inside the inner stage); without this the server would
	// ask 1.1.1.1 straight from the node
	server.SetDNSResolver(RefuseQuery)
	err = server.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// serverConfig is the server's configuration for options.
func serverConfig(options ServerOptions) (config.ServerConfig, error) {
	values := map[string]any{
		"DOMAIN":                 options.Domains,
		"PROTOCOL_TYPE":          "TCP",
		"FORWARD_IP":             "127.0.0.1",
		"FORWARD_PORT":           1,
		"DATA_ENCRYPTION_METHOD": options.Method,
		"ENCRYPTION_KEY_FILE":    options.KeyFile,
		"LOG_LEVEL":              defaultString(options.LogLevel, "WARN"),
		"UDP_PORT":               53,
		// the server's own default, 4096, let an MTU probe reflect kilobytes; Niko asks 500 at most
		"MAX_ALLOWED_CLIENT_DOWNLOAD_MTU": defaultInt(options.MaxDownloadMTU, DefaultMaxDownloadMTU),
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return config.ServerConfig{}, err
	}
	cfg, err := config.LoadServerConfigFromJSONBase64WithOverrides(base64.StdEncoding.EncodeToString(raw), config.ServerConfigOverrides{})
	if err != nil {
		return config.ServerConfig{}, fmt.Errorf("masterdnsvpn: %w", err)
	}
	return cfg, nil
}

// RefuseQuery answers a DNS query with REFUSED: same ID, opcode and RD, the question echoed.
func RefuseQuery(query []byte) ([]byte, error) {
	if len(query) < 12 || query[2]&0x80 != 0 {
		return nil, errors.New("masterdnsvpn: not a DNS query")
	}
	end := 12
	if query[4] != 0 || query[5] != 0 {
		for end < len(query) && query[end] != 0 {
			if query[end]&0xc0 != 0 {
				return nil, errors.New("masterdnsvpn: compressed question")
			}
			end += int(query[end]) + 1
		}
		end += 1 + 4
		if end > len(query) {
			return nil, errors.New("masterdnsvpn: short question")
		}
	}
	answer := make([]byte, end)
	copy(answer, query[:end])
	answer[2] = 0x80 | query[2]&0x79
	answer[3] = 5
	if end > 12 {
		answer[4], answer[5] = 0, 1
	}
	for i := 6; i < 12; i++ {
		answer[i] = 0
	}
	return answer, nil
}

// readKey reads the key as the server would, but fails instead of writing a new one.
func readKey(path string, method int) (string, error) {
	if method == 0 {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("masterdnsvpn: read key: %w", err)
	}
	key := strings.TrimSpace(string(raw))
	want := 32
	switch method {
	case 3:
		want = 16
	case 4:
		want = 24
	}
	if len(key) != want {
		return "", fmt.Errorf("masterdnsvpn: the key for method %d must be %d characters, the file has %d", method, want, len(key))
	}
	return key, nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func defaultInt(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}
