package rule

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestNekoRuleActionTCPDesyncJSON(t *testing.T) {
	t.Parallel()
	content := `{"action":"route","outbound":"direct","tcp_desync":{"split":[{"at":"1","mode":"split"},{"at":"sni+1","mode":"disoob"}],"tlsrec":["sni+2"],"oob_byte":"a"}}`
	action, err := json.UnmarshalExtendedContext[option.RuleAction](context.Background(), []byte(content))
	require.NoError(t, err)
	require.NotNil(t, action.RouteOptions.TCPDesync)
	require.Len(t, action.RouteOptions.TCPDesync.Split, 2)
	encoded, err := json.Marshal(action)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"tcp_desync":{"split":[{"at":"1","mode":"split"},{"at":"sni+1","mode":"disoob"}],"tlsrec":"sni+2","oob_byte":"a"}`)

	options, err := json.UnmarshalExtendedContext[option.RuleAction](context.Background(), []byte(`{"action":"route-options","tcp_desync":{"tlsrec":"sni+1"}}`))
	require.NoError(t, err)
	require.Equal(t, []string{"sni+1"}, []string(options.RouteOptionsOptions.TCPDesync.TLSRec))

	_, err = json.UnmarshalExtendedContext[option.RuleAction](context.Background(), []byte(`{"action":"route","tcp_desync":{"splits":[{"at":"1"}]}}`))
	require.ErrorContains(t, err, "unknown field")
}

func TestNekoRuleActionTCPDesync(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().NewLogger("router")
	desync := &option.TCPDesyncOptions{
		Split:  []option.TCPDesyncSplitOptions{{At: "1"}, {At: "sni+1", Mode: "disoob"}},
		TLSRec: []string{"sni+2"},
	}
	action, err := NewRuleAction(logger, option.RuleAction{
		Action:       C.RuleActionTypeRoute,
		RouteOptions: option.RouteActionOptions{Outbound: "direct", RawRouteOptionsActionOptions: option.RawRouteOptionsActionOptions{TCPDesync: desync}},
	})
	require.NoError(t, err)
	route := action.(*RuleActionRoute)
	require.NotNil(t, route.TCPDesync)
	require.Contains(t, route.String(), "tcp-desync=split=1:split,host+1:disoob tlsrec=host+2")

	action, err = NewRuleAction(logger, option.RuleAction{
		Action:              C.RuleActionTypeRouteOptions,
		RouteOptionsOptions: option.RouteOptionsActionOptions{TCPDesync: desync},
	})
	require.NoError(t, err)
	require.NotNil(t, action.(*RuleActionRouteOptions).TCPDesync)

	for _, test := range []struct {
		options option.RawRouteOptionsActionOptions
		message string
	}{
		{option.RawRouteOptionsActionOptions{TCPDesync: &option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "sni+x"}}}}, "tcp_desync: split[0]: bad marker offset"},
		{option.RawRouteOptionsActionOptions{TCPDesync: &option.TCPDesyncOptions{Split: []option.TCPDesyncSplitOptions{{At: "1", Mode: "wiggle"}}}}, "unknown mode: wiggle"},
		{option.RawRouteOptionsActionOptions{TCPDesync: &option.TCPDesyncOptions{TLSRec: []string{"sni"}, Fake: []byte(`{}`)}}, "not supported until 1.68"},
		{option.RawRouteOptionsActionOptions{TCPDesync: desync, TLSFragment: true}, "mutually exclusive"},
		{option.RawRouteOptionsActionOptions{TCPDesync: desync, TLSRecordFragment: true}, "mutually exclusive"},
	} {
		_, err = NewRuleAction(logger, option.RuleAction{
			Action:       C.RuleActionTypeRoute,
			RouteOptions: option.RouteActionOptions{Outbound: "direct", RawRouteOptionsActionOptions: test.options},
		})
		require.ErrorContains(t, err, test.message)
	}
}
