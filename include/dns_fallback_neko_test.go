package include_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// A fallback DNS server in a whole config: its servers start before it, and
// a dead first server hands the query to the next.
func TestDNSFallbackInConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = include.Context(ctx)
	var options option.Options
	require.NoError(t, options.UnmarshalJSONContext(ctx, []byte(`{
		"log": {"disabled": true},
		"dns": {
			"servers": [
				{"type": "fallback", "tag": "dns-remote", "servers": ["dns-remote-1", "dns-remote-2"], "timeout": "1s"},
				{"type": "tcp", "tag": "dns-remote-1", "server": "127.0.0.1", "server_port": 1},
				{"type": "hosts", "tag": "dns-remote-2", "predefined": {"example.com": "192.0.2.7"}}
			],
			"final": "dns-remote"
		}
	}`)))
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	defer instance.Close()

	router := service.FromContext[adapter.DNSRouter](ctx)
	lookupCtx, lookupCancel := context.WithTimeout(ctx, 5*time.Second)
	defer lookupCancel()
	addresses, err := router.Lookup(lookupCtx, "example.com", adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.7")}, addresses)
}

func TestDNSFallbackUnknownServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = include.Context(ctx)
	var options option.Options
	require.NoError(t, options.UnmarshalJSONContext(ctx, []byte(`{
		"log": {"disabled": true},
		"dns": {"servers": [{"type": "fallback", "tag": "dns-remote", "servers": ["nowhere"]}]}
	}`)))
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.ErrorContains(t, instance.Start(), "nowhere")
}
