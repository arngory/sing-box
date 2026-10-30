// Package embed runs the MasterDnsVPN client inside another Go program. It is the
// only addition to the vendored client (neko): the client's packages are internal,
// so an importable wrapper has to live in this module.
package embed

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
)

type Options struct {
	// client config keys (DOMAINS, DATA_ENCRYPTION_METHOD, ENCRYPTION_KEY, PROTOCOL_TYPE, ...)
	Config map[string]any
	// resolver lines: "8.8.8.8", "1.1.1.1:5353", "192.168.1.0/30"
	Resolvers []string
	// where the resolver list is written, the client reads it from a file
	WorkDir string
	// connections for the client's SOCKS5 or TCP proxy, in process: there is no port
	// another app could connect to or take over
	Conns <-chan net.Conn
	// Android VpnService protect socket, "" off
	ProtectPath string
}

// Run starts the client and blocks until ctx is done. Keys that would expose the
// listener, start a local DNS server or write files are forced off.
func Run(ctx context.Context, options Options) error {
	values := make(map[string]any, len(options.Config)+12)
	for key, value := range options.Config {
		values[key] = value
	}
	// the listener is in process (SetListenerFactory), these only pass validation
	values["LISTEN_IP"] = "127.0.0.1"
	values["LISTEN_PORT"] = 1
	values["SOCKS5_AUTH"] = false
	values["LOCAL_DNS_ENABLED"] = false
	values["LOCAL_DNS_CACHE_PERSIST_TO_FILE"] = false
	values["SAVE_MTU_SERVERS_TO_FILE"] = false
	values["FD_CONTROL_UNIX_SOCKET"] = options.ProtectPath
	raw, err := json.Marshal(values)
	if err != nil {
		return err
	}
	resolversFile, err := os.CreateTemp(options.WorkDir, "masterdnsvpn_resolvers_*.txt")
	if err != nil {
		return err
	}
	resolversPath := resolversFile.Name()
	resolversFile.Close()
	err = os.WriteFile(resolversPath, []byte(strings.Join(options.Resolvers, "\n")+"\n"), 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(resolversPath)
	cfg, err := config.LoadClientConfigFromJSONBase64WithOverrides(
		base64.StdEncoding.EncodeToString(raw),
		config.ClientConfigOverrides{ResolversFilePath: &resolversPath},
	)
	if err != nil {
		return err
	}
	app, err := client.BootstrapLoadedConfig(cfg, "")
	if err != nil {
		return err
	}
	app.SetListenerFactory(func() (net.Listener, error) {
		return &connListener{conns: options.Conns, closed: make(chan struct{})}, nil
	})
	return app.Run(ctx)
}

// connListener hands the client connections from Conns. Each restart of the client's
// listener gets its own, so closing one leaves Conns for the next.
type connListener struct {
	conns     <-chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.conns:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *connListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}
