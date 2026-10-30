// Package embed runs the MasterDnsVPN client inside another Go program. It is the
// only addition to the vendored client (neko): the client's packages are internal,
// so an importable wrapper has to live in this module.
package embed

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	// the local SOCKS5 or TCP listener of the client
	ListenPort int
	SOCKSUser  string
	SOCKSPass  string
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
	values["LISTEN_IP"] = "127.0.0.1"
	values["LISTEN_PORT"] = options.ListenPort
	values["SOCKS5_AUTH"] = options.SOCKSUser != ""
	values["SOCKS5_USER"] = options.SOCKSUser
	values["SOCKS5_PASS"] = options.SOCKSPass
	values["LOCAL_DNS_ENABLED"] = false
	values["LOCAL_DNS_CACHE_PERSIST_TO_FILE"] = false
	values["SAVE_MTU_SERVERS_TO_FILE"] = false
	values["FD_CONTROL_UNIX_SOCKET"] = options.ProtectPath
	raw, err := json.Marshal(values)
	if err != nil {
		return err
	}
	resolversPath := filepath.Join(options.WorkDir, "masterdnsvpn_resolvers_"+strconv.Itoa(options.ListenPort)+".txt")
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
	return app.Run(ctx)
}
