//go:build with_yggdrasil

package yggdrasil

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/multicast"
)

// The entries as yggdrasil-go's module takes them: an interface named, a password it can hold.
func TestNekoYggdrasilMulticastSetup(t *testing.T) {
	setup, err := multicastSetup([]option.YggdrasilMulticastOptions{{Interface: "^wlan[0-9]+$", Beacon: true, Listen: true, Password: "p"}})
	if err != nil || len(setup) != 1 {
		t.Fatal(setup, err)
	}
	entry := setup[0].(multicast.MulticastInterface)
	if !entry.Regex.MatchString("wlan0") || entry.Regex.MatchString("tun0") || !entry.Beacon || !entry.Listen || entry.Password != "p" {
		t.Fatalf("%+v", entry)
	}
	for _, bad := range []option.YggdrasilMulticastOptions{
		{},
		{Interface: "("},
		{Interface: "eth0", Password: strings.Repeat("x", 65)},
	} {
		if _, err := multicastSetup([]option.YggdrasilMulticastOptions{bad}); err == nil {
			t.Errorf("taken: %+v", bad)
		}
	}
}

// An interface with an IPv6 link-local address that takes multicast: where the beacons go. None: the live test
// cannot run here (a container without IPv6); CI's runners have one.
func multicastInterface() string {
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 || iface.Flags&net.FlagLoopback != 0 ||
			iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			if prefix, ok := address.(*net.IPNet); ok && prefix.IP.To4() == nil && prefix.IP.IsLinkLocalUnicast() {
				return iface.Name
			}
		}
	}
	return ""
}

// Two nodes that know the password find each other on the local network and link, through the dialer the
// peers' links take; a node with another password is heard but never linked.
func TestNekoYggdrasilMulticastPeers(t *testing.T) {
	iface := multicastInterface()
	if iface == "" {
		t.Skip("no interface with an IPv6 link-local address and multicast")
	}
	dialed := make(chan string, 16)
	newNode := func(seed, password string) *core.Core {
		privateKey, err := parsePrivateKey(strings.Repeat(seed, 32))
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := selfSignedCertificate(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		logger := &coreLogger{log.NewNOPFactory().Logger()}
		node, err := core.New(certificate, logger, core.LinkDialer{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				select {
				case dialed <- address:
				default:
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(node.Stop)
		setup, err := multicastSetup([]option.YggdrasilMulticastOptions{{
			Interface: "^" + iface + "$", Beacon: true, Listen: true, Password: password,
		}})
		if err != nil {
			t.Fatal(err)
		}
		mc, err := multicast.New(node, logger, setup...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = mc.Stop() })
		return node
	}
	a := newNode("a1", "the user's")
	b := newNode("b2", "the user's")
	stranger := newNode("c3", "someone else's")
	linked := func(node, to *core.Core) bool {
		for _, info := range node.GetPeers() {
			if info.Up && string(info.Key) == string(to.PublicKey()) {
				return true
			}
		}
		return false
	}
	deadline := time.Now().Add(30 * time.Second)
	for !(linked(a, b) && linked(b, a)) {
		if time.Now().After(deadline) {
			t.Fatalf("no link between the user's nodes on %s: %+v", iface, a.GetPeers())
		}
		time.Sleep(200 * time.Millisecond)
	}
	select {
	case address := <-dialed:
		if !strings.Contains(address, "%") {
			t.Errorf("a link-local peer dialled without its interface: %s", address)
		}
	default:
		t.Error("the link did not go through the peers' dialer")
	}
	// the stranger's beacon is heard, its password is not the user's: it never links with them
	time.Sleep(3 * time.Second)
	if linked(a, stranger) || linked(stranger, a) || linked(b, stranger) {
		t.Fatalf("a node with another password linked: %+v", stranger.GetPeers())
	}
}
