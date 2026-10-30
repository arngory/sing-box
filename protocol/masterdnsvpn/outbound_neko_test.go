//go:build with_masterdnsvpn

package masterdnsvpn

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// The client runs in process against a resolver that never answers, and Close stops it.
func TestNekoMasterDNSVPNLifecycle(t *testing.T) {
	workDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(workDir)
	defer os.Chdir(oldDir)

	for _, bad := range []option.MasterDNSVPNOutboundOptions{
		{Resolvers: []string{"127.0.0.1:9"}},
		{Domains: []string{"v.example.com"}},
		{Domains: []string{"v.example.com"}, Resolvers: []string{"127.0.0.1:9"}, Mode: "udp"},
	} {
		if _, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "bad", bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}

	outbound, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "mdv", option.MasterDNSVPNOutboundOptions{
		Domains:          []string{"v.example.com"},
		Resolvers:        []string{"127.0.0.1:9"},
		EncryptionMethod: 2,
		EncryptionKey:    strings.Repeat("k", 32),
		Extra:            map[string]any{"mtu_test_timeout": 0.5},
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err = outbound.(*Outbound).Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err = outbound.(*Outbound).DialContext(context.Background(), "udp", M.ParseSocksaddr("1.1.1.1:53")); err == nil {
		t.Fatal("UDP accepted")
	}
	// no session yet: a dial gives up with its context instead of hanging
	dialCtx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	_, err = outbound.(*Outbound).DialContext(dialCtx, "tcp", M.ParseSocksaddr("example.com:443"))
	cancel()
	if err == nil {
		t.Fatal("dial without a session succeeded")
	}
	start := time.Now()
	outbound.(*Outbound).Close()
	select {
	case <-outbound.(*Outbound).done:
	default:
		t.Fatal("client still running after Close")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("Close took too long")
	}
	// the resolver list it wrote is removed again
	files, _ := os.ReadDir(workDir)
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "masterdnsvpn_resolvers_") {
			t.Fatalf("left %s behind", file.Name())
		}
	}
}
