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
	// Log receives the server log (nil: discarded)
	Log io.Writer
}

// RunServer serves until ctx ends or the server stops.
func RunServer(ctx context.Context, options ServerOptions) error {
	if len(options.Domains) == 0 {
		return errors.New("masterdnsvpn: no domains")
	}
	if options.Conn == nil || options.Dial == nil {
		return errors.New("masterdnsvpn: socket and upstream dialer are required")
	}
	values := map[string]any{
		"DOMAIN":                 options.Domains,
		"PROTOCOL_TYPE":          "TCP",
		"FORWARD_IP":             "127.0.0.1",
		"FORWARD_PORT":           1,
		"DATA_ENCRYPTION_METHOD": options.Method,
		"ENCRYPTION_KEY_FILE":    options.KeyFile,
		"LOG_LEVEL":              defaultString(options.LogLevel, "WARN"),
		"UDP_PORT":               53,
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return err
	}
	cfg, err := config.LoadServerConfigFromJSONBase64WithOverrides(base64.StdEncoding.EncodeToString(raw), config.ServerConfigOverrides{})
	if err != nil {
		return fmt.Errorf("masterdnsvpn: %w", err)
	}
	key, err := readKey(options.KeyFile, options.Method)
	if err != nil {
		return err
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
	server.SetListener(options.Conn)
	server.SetStreamDialer(func(_, _ string, timeout time.Duration) (net.Conn, error) {
		return options.Dial(timeout)
	})
	err = server.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
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
