package knock

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/chacha20poly1305"
)

// testdata/spa_v3_vectors.json is raycontrol internal/spa/testdata/vectors-v3.json at v0.35.0 (17d2f5e), unchanged:
// the v2 parameters but len_min 85, each packet with the address it goes to.
type spa3Vectors struct {
	Params  SPAv2Options `json:"params"`
	Packets []struct {
		DeviceKey string   `json:"device_key"`
		Time      int64    `json:"time"`
		TTL       uint16   `json:"ttl_s"`
		Scope     []uint16 `json:"scope"`
		Nonce     string   `json:"nonce"`
		Length    int      `json:"length"`
		Epoch     uint64   `json:"epoch"`
		EpochKey  string   `json:"epoch_key"`
		Packet    string   `json:"packet"`
		Dst       string   `json:"dst"`
	} `json:"packets"`
}

func TestSPA3Vectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/spa_v3_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v spa3Vectors
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Packets) != 4 {
		t.Fatalf("%d packets", len(v.Packets))
	}
	for i, c := range v.Packets {
		options := v.Params
		options.DeviceKey = c.DeviceKey
		options.Scope = c.Scope
		options.TTL = c.TTL
		options.Versions = []int{2, 3}
		p, err := parseSPAv2(options)
		if err != nil {
			t.Fatal(err)
		}
		if !p.v3 {
			t.Fatalf("packet %d: no v3 for versions [2, 3]", i)
		}
		now := time.Unix(c.Time, 0)
		key, err := p.epochKey(c.Epoch)
		if err != nil || hex.EncodeToString(key) != c.EpochKey || p.epoch(now) != c.Epoch {
			t.Fatalf("packet %d: epoch key %x, want %s (%v)", i, key, c.EpochKey, err)
		}
		dst := netip.MustParseAddr(c.Dst)
		nonce, _ := hex.DecodeString(c.Nonce)
		packet, err := p.seal(now, nonce, c.Length, dst)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(packet); got != c.Packet {
			t.Fatalf("packet %d:\n got %s\nwant %s", i, got, c.Packet)
		}
		// the plaintext field by field (spa-v3 §2)
		plaintext := spa3Plaintext(t, p, packet, now)
		if plaintext[0] != spa3Version || plaintext[11] != 0 || int(plaintext[12]) != len(c.Scope) {
			t.Fatalf("packet %d: header % x", i, plaintext[:13])
		}
		if got := netip.AddrFrom16([16]byte(plaintext[13:29])).Unmap(); got != dst {
			t.Fatalf("packet %d: dst %v, want %v", i, got, dst)
		}
		for j, id := range c.Scope {
			if binary.BigEndian.Uint16(plaintext[29+2*j:]) != id {
				t.Fatalf("packet %d: scope %d", i, j)
			}
		}
	}
	// the shortest v3 packet with the whole scope: 69 + 2·16 (§2)
	if last := v.Packets[3]; last.Length != 101 || len(last.Scope) != 16 {
		t.Fatalf("the full-scope vector: length %d, scope %d", last.Length, len(last.Scope))
	}
}

func spa3Plaintext(t *testing.T, p *spa2Params, packet []byte, now time.Time) []byte {
	t.Helper()
	aad := append([]byte(spa2AADLabel), p.nodeID[:]...)
	key, _ := p.epochKey(p.epoch(now))
	aead, _ := chacha20poly1305.NewX(key)
	plaintext, err := aead.Open(nil, packet[:spa2NonceSize], packet[spa2NonceSize:], aad)
	if err != nil {
		t.Fatal("packet does not authenticate")
	}
	return plaintext
}

// TestSPA3Lengths: v3's lengths start where the address fits; lengths that never fit it knock v2.
func TestSPA3Lengths(t *testing.T) {
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: 40000, PortRange: 4096, LenMin: 53, LenMax: 117,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
		Scope:     []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, Versions: []int{2, 3},
	}
	options.LenMin = 85
	p, err := parseSPAv2(options)
	if err != nil || !p.v3 {
		t.Fatalf("v3 %v, %v", p != nil && p.v3, err)
	}
	for range 50 {
		_, packet, err := p.packet(time.Now(), netip.MustParseAddr("203.0.113.7"))
		if err != nil || len(packet) < 101 || len(packet) > 117 {
			t.Fatalf("v3 packet of %d bytes: %v", len(packet), err)
		}
	}
	// no room for the address: v2 only
	options.LenMax = 100
	if p, err = parseSPAv2(options); err != nil || p.v3 {
		t.Fatalf("v3 with len_max 100: %v", err)
	}
	// no versions: v2, as before raycontrol v0.35.0
	options.LenMax, options.Versions = 160, nil
	if p, err = parseSPAv2(options); err != nil || p.v3 {
		t.Fatalf("v3 without versions: %v", err)
	}
}

// TestSPA3DstOf: the address a v3 knock names: NAT64's embedded IPv4 (spa-v3 §3), no zone, IPv4 unmapped.
func TestSPA3DstOf(t *testing.T) {
	defer SetNAT64Prefix("")
	for _, c := range []struct{ prefix, addr, want string }{
		{"", "203.0.113.7", "203.0.113.7"},
		{"", "::ffff:203.0.113.7", "203.0.113.7"},
		{"", "2001:db8::7", "2001:db8::7"},
		{"", "fe80::1%eth0", "fe80::1"},
		{"", "64:ff9b::cb00:7107", "203.0.113.7"},
		// the network's own prefix: /96, and /64 with bits 64-71 left out (RFC 6052 §2.2)
		{"2001:db8:64::/96", "2001:db8:64::cb00:7107", "203.0.113.7"},
		{"2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100:0", "192.0.2.33"},
		{"2001:db8:64::/96", "2001:db8:65::cb00:7107", "2001:db8:65::cb00:7107"},
		{"not a prefix", "2001:db8:64::cb00:7107", "2001:db8:64::cb00:7107"},
	} {
		SetNAT64Prefix(c.prefix)
		if got := DstOf(netip.MustParseAddr(c.addr)); got != netip.MustParseAddr(c.want) {
			t.Fatalf("%s with prefix %q: %v, want %s", c.addr, c.prefix, got, c.want)
		}
	}
}

// TestSPA3FallbackToV2: a node that takes v2 alone (rolled back before v0.35.0) is reached with v2 at its signed
// address after v3 opened nothing, and gets v2 there from then on.
func TestSPA3FallbackToV2(t *testing.T) {
	spaConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spaConn.Close()
	// the service's port, closed until a v2 packet comes
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	servicePort := uint16(free.Addr().(*net.TCPAddr).Port)
	free.Close()
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: uint16(spaConn.LocalAddr().(*net.UDPAddr).Port), PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
		Carriers:  []string{"udp"}, Versions: []int{2, 3},
	}
	outbound := newBox(t, Options{SPAv2: &options, NodeAddresses: []string{"127.0.0.1"}})
	versions := make(chan byte, 16)
	go func() {
		buffer := make([]byte, 1024)
		opened := false
		for {
			n, _, err := spaConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			plaintext := spa3Plaintext(t, outbound.spa2, bytes.Clone(buffer[:n]), time.Now())
			versions <- plaintext[0]
			if plaintext[0] == spa3Version {
				if got := netip.AddrFrom16([16]byte(plaintext[13:29])).Unmap(); got != netip.MustParseAddr("127.0.0.1") {
					t.Errorf("dst %v", got)
				}
			}
			if plaintext[0] == spa2Version && !opened {
				opened = true
				listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(servicePort))))
				if err != nil {
					t.Error(err)
					return
				}
				t.Cleanup(func() { listener.Close() })
				go func() {
					for {
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						conn.Close()
					}
				}()
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", servicePort))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	var got []byte
	for len(versions) > 0 {
		got = append(got, <-versions)
	}
	// v3, v3 once more after the failed dial, then v2
	if len(got) != 3 || got[0] != spa3Version || got[1] != spa3Version || got[2] != spa2Version {
		t.Fatalf("versions % x", got)
	}
	// the address keeps v2
	outbound.forget(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", servicePort))
	conn, err = outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", servicePort))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case v := <-versions:
		if v != spa2Version {
			t.Fatalf("version %x after v2 opened the address", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no packet")
	}
}

// TestSPA3NoV2BeyondSignedData: v2 follows v3 only at an address of the signed data (spa-v3 §6 p. 4); without
// node_addresses (a node known by name alone) at none, and through a detour v3 goes to the signed addresses.
func TestSPA3NoV2BeyondSignedData(t *testing.T) {
	node, err := parseNodeAddresses([]string{"203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	o := &Outbound{node: node, signedAddrs: node}
	if !o.signed(netip.MustParseAddr("203.0.113.7")) || o.signed(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("the node's addresses")
	}
	if (&Outbound{}).signed(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("an address without node_addresses")
	}
	v3 := &spa2Params{v3: true}
	detoured := &Outbound{signedAddrs: node, hasDetour: true, spa2: v3}
	targets := detoured.detourTargets(M.ParseSocksaddrHostPort("node.example.com", 443))
	if len(targets) != 1 || targets[0] != M.ParseSocksaddrHostPort("203.0.113.7", 443) {
		t.Fatal("through a detour: ", targets)
	}
	for _, o := range []*Outbound{
		{signedAddrs: node, spa2: v3},                             // no detour: dialNode's
		{signedAddrs: node, hasDetour: true, spa2: &spa2Params{}}, // v2: the name, as before
		{hasDetour: true, spa2: v3},                               // no signed addresses
	} {
		if o.detourTargets(M.ParseSocksaddrHostPort("node.example.com", 443)) != nil {
			t.Fatal("detour targets where none are due")
		}
	}
	if detoured.detourTargets(M.ParseSocksaddrHostPort("203.0.113.7", 443)) != nil {
		t.Fatal("detour targets for an address")
	}
}

func TestSPA3KnocksV3(t *testing.T) {
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: 40000, PortRange: 4096, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111", Versions: []int{2, 3},
	}
	if !KnocksV3(options, "203.0.113.7") || !KnocksV3(options, "[2001:db8::7]") || !TakesV3(options) || TakesV3(options.V2()) {
		t.Fatal("v3 at an address")
	}
	// never v2 at a name for a node that takes v3 (§6 p. 4)
	if _, _, err := SPAv2Packet(options, "node.example.com", time.Now()); err == nil {
		t.Fatal("a packet for a name")
	}
	if _, _, err := SPAv2Packet(options.V2(), "node.example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	if KnocksV3(options, "node.example.com") || KnocksV3(options.V2(), "203.0.113.7") {
		t.Fatal("v3 at a name, or after V2")
	}
	// a request's packet at an address names it
	_, packet, err := SPAv2Packet(options, "203.0.113.7", time.Unix(1767225600, 0))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := parseSPAv2(options)
	if plaintext := spa3Plaintext(t, p, packet, time.Unix(1767225600, 0)); plaintext[0] != spa3Version ||
		netip.AddrFrom16([16]byte(plaintext[13:29])).Unmap() != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("plaintext % x", plaintext[:29])
	}
}

// TestSPA3DNSAnswers: with v3 a DNS answer outside the signed data is knocked at, the node's own addresses after it;
// a connection to it does not make it the address that answered last (it would lead the node's own on a fallback).
func TestSPA3DNSAnswers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("localhost")
	}
	spaConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spaConn.Close()
	r := &recorder{}
	service := listenTCP(t, r, "service")
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: uint16(spaConn.LocalAddr().(*net.UDPAddr).Port), PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
		Carriers:  []string{"udp"}, Versions: []int{2, 3},
	}
	o := newBox(t, Options{SPAv2: &options, NodeAddresses: []string{"192.0.2.1"}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// the node's own first: a forged answer (a block page that takes TCP) does not hold them up
	// (localhost may answer ::1 as well)
	if got, _ := o.ResolveNode(ctx, "localhost"); len(got) < 2 || got[0] != netip.MustParseAddr("192.0.2.1") || !slices.Contains(got[1:], netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("v3: the node's own, then the answer: ", got)
	}
	conn, err := o.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("localhost", service))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if first := o.node.fallback(o.generation.Load())[0]; first != netip.MustParseAddr("192.0.2.1") {
		t.Fatal("a DNS answer leads the node's own addresses: ", first)
	}
	// the knock at the answer was v3, naming it
	spaConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, _, err := spaConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext := spa3Plaintext(t, o.spa2, buffer[:n], time.Now()); plaintext[0] != spa3Version ||
		netip.AddrFrom16([16]byte(plaintext[13:29])).Unmap() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("plaintext % x", plaintext[:29])
	}
}

// TestSPA3FallbackAfterTimeout: a node rolled back whose perimeter drops the SYN (no refusal) until a v2 knock: v3
// runs out of its half of a dial with a deadline, v2 opens in the other half, and the next dial goes straight to v2.
func TestSPA3FallbackAfterTimeout(t *testing.T) {
	spaConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spaConn.Close()
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: uint16(spaConn.LocalAddr().(*net.UDPAddr).Port), PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
		Carriers:  []string{"udp"}, Versions: []int{2, 3},
	}
	o := newBox(t, Options{SPAv2: &options, NodeAddresses: []string{"127.0.0.1"}})
	opened := make(chan struct{})
	var open sync.Once
	var versions []byte
	var access sync.Mutex
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, _, err := spaConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			v := spa3Plaintext(t, o.spa2, bytes.Clone(buffer[:n]), time.Now())[0]
			access.Lock()
			versions = append(versions, v)
			if v == spa2Version {
				open.Do(func() { close(opened) })
			}
			access.Unlock()
		}
	}()
	// the dial hangs until a v2 knock opened the port, as a dropped SYN does
	o.testDialPeer = func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		select {
		case <-opened:
			client, server := net.Pipe()
			server.Close()
			return client, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	destination := M.ParseSocksaddrHostPort("127.0.0.1", 443)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := o.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	access.Lock()
	first := bytes.Clone(versions)
	access.Unlock()
	if len(first) < 2 || first[0] != spa3Version || first[len(first)-1] != spa2Version {
		t.Fatalf("v3, then v2: % x", first)
	}
	// the next dial knocks v2 straight away
	o.forget(context.Background(), destination)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel2()
	started := time.Now()
	conn, err = o.DialContext(ctx2, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(100 * time.Millisecond)
	access.Lock()
	second := bytes.Clone(versions[len(first):])
	access.Unlock()
	if len(second) != 1 || second[0] != spa2Version || time.Since(started) > time.Second {
		t.Fatalf("the second dial: % x after %v", second, time.Since(started))
	}
	// the hold ran out: a renewal sends v2 beside v3, for a node still rolled back
	expire := func() {
		target := o.target("127.0.0.1")
		target.access.Lock()
		target.v2Until = time.Now().Add(-time.Second)
		target.access.Unlock()
	}
	expire()
	if err = o.sendSPA2(withRenewal(context.Background()), destination); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	access.Lock()
	third := bytes.Clone(versions[len(first)+len(second):])
	access.Unlock()
	if len(third) != 2 || third[0] != spa2Version || third[1] != spa3Version {
		t.Fatalf("a renewal after the hold: % x", third)
	}
	// a dial right after, on the access that v2 opened (the knock cached): it proves nothing of v3, the mark stays
	ctx4, cancel4 := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel4()
	conn, err = o.DialContext(ctx4, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !o.hadV2(destination) {
		t.Fatal("the mark went on access a v2 knock opened")
	}
	// a dial that knocks v3 alone, no v2 within the access time, and opens (this node opens to anything now): the
	// mark goes
	target := o.target("127.0.0.1")
	target.access.Lock()
	target.lastV2At = time.Time{}
	target.access.Unlock()
	o.forget(context.Background(), destination)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel3()
	conn, err = o.DialContext(ctx3, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(100 * time.Millisecond)
	access.Lock()
	fourth := bytes.Clone(versions[len(first)+len(second)+len(third):])
	access.Unlock()
	if len(fourth) != 1 || fourth[0] != spa3Version || o.hadV2(destination) {
		t.Fatalf("a dial after the hold: % x, v2 mark %v", fourth, o.hadV2(destination))
	}
}

// A node that opens to nothing, its SYN dropped: at an address the outbound gives up on (nodeDialTimeout), the
// attempt (v3, then v2 in the other half) is a failed round, counted once, from the knock; the last address, given up
// on by the caller's deadline, is not.
func TestSPA3HungAttemptIsAFailedRound(t *testing.T) {
	spaConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spaConn.Close()
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: uint16(spaConn.LocalAddr().(*net.UDPAddr).Port), PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
		Carriers:  []string{"udp"}, Versions: []int{2, 3},
	}
	o := newBox(t, Options{SPAv2: &options, NodeAddresses: []string{"127.0.0.1", "127.0.0.2"}})
	o.testDialPeer = func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	// by the node's name, which does not resolve: its addresses in their order
	ctx, cancel := context.WithTimeout(context.Background(), nodeDialTimeout+time.Second)
	defer cancel()
	if _, err = o.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("node.invalid", 443)); err == nil {
		t.Fatal("a dial to a node that opens to nothing went through")
	}
	// the addresses are dialled in the node's order: the first given up on by the outbound, the last by the caller
	_, first := o.rounds.wait("127.0.0.1", time.Now())
	_, second := o.rounds.wait("127.0.0.2", time.Now())
	if first+second != 1 {
		t.Fatalf("failed rounds: %d at 127.0.0.1, %d at 127.0.0.2; want 1 at the address given up on alone", first, second)
	}
}
