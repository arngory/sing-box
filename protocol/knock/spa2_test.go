package knock

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls/chromehello"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/chacha20poly1305"
)

// testdata/spa_v2_vectors.json is raycontrol internal/spa/testdata/vectors.json
// (branch claude/clever-feynman-w0e2v1, commit 55535a0), unchanged.
type spa2Vectors struct {
	Params SPAv2Options `json:"params"`
	Ports  []struct {
		Time int64  `json:"time"`
		Slot uint64 `json:"slot"`
		Port uint16 `json:"port"`
	} `json:"ports"`
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
	} `json:"packets"`
}

func loadSPA2Vectors(t *testing.T) spa2Vectors {
	raw, err := os.ReadFile("testdata/spa_v2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v spa2Vectors
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSPA2Vectors(t *testing.T) {
	v := loadSPA2Vectors(t)
	base := v.Params
	base.DeviceKey = hex.EncodeToString(make([]byte, 32))
	p, err := parseSPAv2(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Ports {
		now := time.Unix(c.Time, 0)
		if slot := p.slot(now); slot != c.Slot {
			t.Fatalf("time %d: slot %d, want %d", c.Time, slot, c.Slot)
		}
		if port := p.port(c.Slot); port != c.Port {
			t.Fatalf("slot %d: port %d, want %d", c.Slot, port, c.Port)
		}
	}
	for i, c := range v.Packets {
		options := v.Params
		options.DeviceKey = c.DeviceKey
		options.Scope = c.Scope
		options.TTL = c.TTL
		p, err := parseSPAv2(options)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Unix(c.Time, 0)
		if epoch := p.epoch(now); epoch != c.Epoch {
			t.Fatalf("packet %d: epoch %d, want %d", i, epoch, c.Epoch)
		}
		key, err := p.epochKey(c.Epoch)
		if err != nil || hex.EncodeToString(key) != c.EpochKey {
			t.Fatalf("packet %d: epoch key %x, want %s (%v)", i, key, c.EpochKey, err)
		}
		nonce, _ := hex.DecodeString(c.Nonce)
		packet, err := p.seal(now, nonce, c.Length)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(packet); got != c.Packet {
			t.Fatalf("packet %d:\n got %s\nwant %s", i, got, c.Packet)
		}
	}
}

// spa2Open is the server side check of spa-v2.md §6 steps 3-5, for the tests.
func spa2Open(t *testing.T, p *spa2Params, packet []byte, now time.Time) (sent time.Time, ttl uint16, scope []uint16) {
	t.Helper()
	if len(packet) < p.lenMin || len(packet) > p.lenMax {
		t.Fatalf("length %d outside [%d, %d]", len(packet), p.lenMin, p.lenMax)
	}
	aad := append([]byte(spa2AADLabel), p.nodeID[:]...)
	for _, epoch := range []uint64{p.epoch(now) - 1, p.epoch(now), p.epoch(now) + 1} {
		key, _ := p.epochKey(epoch)
		aead, _ := chacha20poly1305.NewX(key)
		plaintext, err := aead.Open(nil, packet[:spa2NonceSize], packet[spa2NonceSize:], aad)
		if err != nil {
			continue
		}
		if plaintext[0] != spa2Version || plaintext[11] != 0 {
			t.Fatal("version or flags")
		}
		sent = time.Unix(int64(binary.BigEndian.Uint64(plaintext[1:9])), 0)
		if p.epoch(sent) != epoch {
			t.Fatal("epoch of the time field differs from the key's")
		}
		ttl = binary.BigEndian.Uint16(plaintext[9:11])
		for i := range int(plaintext[12]) {
			scope = append(scope, binary.BigEndian.Uint16(plaintext[spa2Header+2*i:]))
		}
		return
	}
	t.Fatal("packet does not authenticate")
	return
}

func TestSPA2BeforeDialAndAfterNetworkChange(t *testing.T) {
	spaConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spaConn.Close()
	spaPort := uint16(spaConn.LocalAddr().(*net.UDPAddr).Port)
	packets := make(chan []byte, 8)
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, _, err := spaConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			packets <- bytes.Clone(buffer[:n])
		}
	}()
	r := &recorder{}
	server := listenTCP(t, r, "server")

	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: spaPort, PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
		Scope:     []uint16{1, 3}, TTL: 600,
	}
	outbound := newBox(t, Options{SPAv2: &options})
	destination := M.ParseSocksaddrHostPort("127.0.0.1", server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	started := time.Now()
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(started); waited < 150*time.Millisecond {
		t.Fatalf("connected %v after the packet, want at least 150ms", waited)
	}
	select {
	case packet := <-packets:
		sent, ttl, scope := spa2Open(t, outbound.spa2, packet, time.Now())
		if time.Since(sent) > 5*time.Second || ttl != 600 || len(scope) != 2 || scope[0] != 1 || scope[1] != 3 {
			t.Fatalf("plaintext: %v %d %v", sent, ttl, scope)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no SPA packet")
	}

	// in use: tracked, and no new packet within the access time
	if !outbound.inUse(outbound.target("127.0.0.1")) {
		t.Fatal("host not in use")
	}
	conn2, err := outbound.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	conn2.Close()
	conn.Close()
	select {
	case <-packets:
		t.Fatal("a second packet within the access time")
	case <-time.After(300 * time.Millisecond):
	}

	// a network change sends a packet at once for a host in use
	outbound.InterfaceUpdated(context.Background())
	select {
	case <-packets:
	case <-time.After(2 * time.Second):
		t.Fatal("no packet after a network change")
	}
}

func TestSPA2RetryAfterFailedDial(t *testing.T) {
	spaConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spaConn.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := uint16(closed.Addr().(*net.TCPAddr).Port)
	closed.Close()
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: uint16(spaConn.LocalAddr().(*net.UDPAddr).Port), PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
	}
	outbound := newBox(t, Options{SPAv2: &options})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", closedPort)); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	// the first packet, then one more after the failed connection
	buffer := make([]byte, 1024)
	for i := range 2 {
		spaConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err = spaConn.ReadFrom(buffer); err != nil {
			t.Fatalf("packet %d: %v", i+1, err)
		}
	}
	spaConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err = spaConn.ReadFrom(buffer); err == nil {
		t.Fatal("a third packet")
	}
}

// TestSPA2RetryCoalesced: parallel dials that fail together send one more packet between them, not one each.
func TestSPA2RetryCoalesced(t *testing.T) {
	spaConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spaConn.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := uint16(closed.Addr().(*net.TCPAddr).Port)
	closed.Close()
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: uint16(spaConn.LocalAddr().(*net.UDPAddr).Port), PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
	}
	outbound := newBox(t, Options{SPAv2: &options})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", closedPort))
		}()
	}
	wg.Wait()
	// the first packet, shared, and one retry, shared
	buffer := make([]byte, 1024)
	packets := 0
	for {
		spaConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, _, err = spaConn.ReadFrom(buffer); err != nil {
			break
		}
		packets++
	}
	if packets != 2 {
		t.Fatalf("%d packets over UDP for 8 failed dials, want 2", packets)
	}
}

func TestSPA2Options(t *testing.T) {
	good := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 60, SlotLen: 60,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: 40000, PortRange: 4096, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
	}
	if _, err := parseSPAv2(good); err != nil {
		t.Fatal(err)
	}
	for i, mutate := range []func(*SPAv2Options){
		func(o *SPAv2Options) { o.NodeID = "33" },
		func(o *SPAv2Options) { o.DeviceKey = "zz" },
		func(o *SPAv2Options) { o.SlotLen = 0 },
		func(o *SPAv2Options) { o.PortBase, o.PortRange = 65000, 1000 },
		func(o *SPAv2Options) { o.LenMax = 600 },
		func(o *SPAv2Options) { o.LenMin = 40 },
		func(o *SPAv2Options) { o.Scope = make([]uint16, 17); o.LenMin, o.LenMax = 200, 300 },
	} {
		o := good
		mutate(&o)
		if _, err := parseSPAv2(o); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	byRef := good
	byRef.DeviceKey, byRef.DeviceKeyRef = "", "node-a"
	if _, err := parseSPAv2(byRef); err == nil {
		t.Fatal("unknown key reference accepted")
	}
	SetDeviceKey("node-a", good.DeviceKey)
	if p, err := parseSPAv2(byRef); err != nil || p.deviceKey[0] != 0x11 {
		t.Fatal("key reference: ", err)
	}
	SetDeviceKey("node-b", good.DeviceKey)
	RetainDeviceKeys([]string{"node-a"})
	if _, err := parseSPAv2(byRef); err != nil {
		t.Fatal("retained key dropped: ", err)
	}
	if _, loaded := deviceKeys.Load("node-b"); loaded {
		t.Fatal("stale key kept")
	}
	SetDeviceKey("node-a", "")
	if _, err := New(context.Background(), nil, nil, "x", Options{SPAv2: &good, Sequence: []Step{{Port: 1}}}); err == nil {
		t.Fatal("spa_v2 with a sequence accepted")
	}
	// packets are random: different nonce, length within bounds
	p, _ := parseSPAv2(good)
	_, a, _ := p.packet(time.Now())
	_, b, _ := p.packet(time.Now())
	if bytes.Equal(a[:spa2NonceSize], b[:spa2NonceSize]) || len(a) < 96 || len(a) > 160 {
		t.Fatal("packet not random")
	}
}

// fromTLSCarrier is the node's reading of a ClientHello carrier (raycontrol internal/spa FromTLSCarrier,
// spa-v2.md §10.1): the data of the first session_ticket extension.
func fromTLSCarrier(data []byte) ([]byte, bool) {
	if len(data) < 5 || data[0] != 0x16 || data[1] != 0x03 || data[2] > 0x04 {
		return nil, false
	}
	rec := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+rec {
		return nil, false
	}
	b := data[5 : 5+rec]
	if len(b) < 4 || b[0] != 0x01 {
		return nil, false
	}
	n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if len(b) < 4+n {
		return nil, false
	}
	b = b[4 : 4+n]
	skip := func(k int) bool {
		if len(b) < k {
			return false
		}
		b = b[k:]
		return true
	}
	vec := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		l := 0
		for i := range lenBytes {
			l = l<<8 | int(b[i])
		}
		return skip(lenBytes + l)
	}
	if !skip(2+32) || !vec(1) || !vec(2) || !vec(1) || len(b) < 2 {
		return nil, false
	}
	extLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < extLen {
		return nil, false
	}
	b = b[:extLen]
	for len(b) >= 4 {
		typ := int(binary.BigEndian.Uint16(b))
		l := int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+l {
			return nil, false
		}
		if typ == 0x0023 {
			return b[4 : 4+l], true
		}
		b = b[4+l:]
	}
	return nil, false
}

// tcpNode is a node whose slot port takes TCP only (UDP is lost on the way): it reads each connection to EOF
// like rayd (at most 4096 bytes), takes the packet out of a ClientHello when tls, a bare packet when bare, and
// opens the service port on the first one that authenticates.
type tcpNode struct {
	slotPort, servicePort uint16
	tls, bare             atomic.Int32 // carriers that arrived
	opened                chan struct{}
}

func newTCPNode(t *testing.T, acceptTLS, acceptBare bool) (*tcpNode, *SPAv2Options) {
	carrier, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { carrier.Close() })
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	node := &tcpNode{
		slotPort:    uint16(carrier.Addr().(*net.TCPAddr).Port),
		servicePort: uint16(probe.Addr().(*net.TCPAddr).Port),
		opened:      make(chan struct{}),
	}
	probe.Close()
	options := &SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: node.slotPort, PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
	}
	params, err := parseSPAv2(*options)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	open := func() {
		once.Do(func() {
			service, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(node.servicePort))))
			if err != nil {
				t.Error(err)
				return
			}
			t.Cleanup(func() { service.Close() })
			go func() {
				for {
					c, err := service.Accept()
					if err != nil {
						return
					}
					c.Close()
				}
			}()
			close(node.opened)
		})
	}
	authentic := func(packet []byte) bool {
		if len(packet) < params.lenMin || len(packet) > params.lenMax {
			return false
		}
		aad := append([]byte(spa2AADLabel), params.nodeID[:]...)
		now := time.Now()
		for _, epoch := range []uint64{params.epoch(now) - 1, params.epoch(now), params.epoch(now) + 1} {
			key, _ := params.epochKey(epoch)
			aead, _ := chacha20poly1305.NewX(key)
			if _, err := aead.Open(nil, packet[:spa2NonceSize], packet[spa2NonceSize:], aad); err == nil {
				return true
			}
		}
		return false
	}
	go func() {
		for {
			conn, err := carrier.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				data, _ := io.ReadAll(io.LimitReader(conn, 4096))
				if packet, ok := fromTLSCarrier(data); ok {
					node.tls.Add(1)
					if acceptTLS && authentic(packet) {
						open()
					}
				} else if len(data) > 0 {
					node.bare.Add(1)
					if acceptBare && authentic(data) {
						open()
					}
				}
			}()
		}
	}()
	return node, options
}

func (n *tcpNode) dial(t *testing.T, outbound *Outbound) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", n.servicePort))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

// Where UDP is cut, the dial falls back to the ClientHello carrier (spa-v2.md §10.1) and keeps it; a node
// that reads ClientHello never sees a bare packet.
func TestSPA2TLSCarrier(t *testing.T) {
	node, options := newTCPNode(t, true, false)
	outbound := newBox(t, Options{SPAv2: options})
	node.dial(t, outbound)
	if outbound.carrier() != CarrierTLS {
		t.Fatalf("carrier %v, want tls", outbound.carrier())
	}
	if node.bare.Load() != 0 {
		t.Fatalf("%d bare packets to a node that took the ClientHello", node.bare.Load())
	}
	// a new network starts with UDP again
	outbound.InterfaceUpdated(context.Background())
	if outbound.carrier() != CarrierUDP {
		t.Fatal("the carrier survived a network change")
	}
}

// A node before raycontrol v0.10.0 does not read a ClientHello: the bare packet opens it, and is kept.
func TestSPA2BareCarrierForOldNode(t *testing.T) {
	node, options := newTCPNode(t, false, true)
	outbound := newBox(t, Options{SPAv2: options})
	node.dial(t, outbound)
	if outbound.carrier() != CarrierTCP {
		t.Fatalf("carrier %v, want tcp", outbound.carrier())
	}
	if node.tls.Load() == 0 {
		t.Fatal("no ClientHello was tried first")
	}
	tried := node.tls.Load()
	node.dial(t, outbound)
	if node.tls.Load() != tried {
		t.Fatal("a ClientHello again after bare TCP worked")
	}
}

// The node's spa.carriers (raycontrol v0.10.1): the order to try them in, and nothing it does not list.
func TestSPA2CarrierOrder(t *testing.T) {
	for _, c := range []struct {
		names []string
		want  []Carrier
	}{
		{nil, []Carrier{CarrierUDP, CarrierTLS, CarrierTCP}},
		{[]string{"udp"}, []Carrier{CarrierUDP}},
		{[]string{"udp", "tcp", "tls"}, []Carrier{CarrierUDP, CarrierTCP, CarrierTLS}},
		{[]string{"quic", "udp", "udp"}, []Carrier{CarrierUDP}},
		{[]string{"quic"}, []Carrier{CarrierUDP, CarrierTLS, CarrierTCP}},
	} {
		if got := (SPAv2Options{Carriers: c.names}).CarrierOrder(); !slices.Equal(got, c.want) {
			t.Errorf("%v: %v, want %v", c.names, got, c.want)
		}
	}
	// one-off requests: the listed ones first, then UDP or the ClientHello it left out (the list may be out of
	// date); bare TCP only to a node that lists it, or sends no list
	for _, c := range []struct {
		names []string
		want  []Carrier
	}{
		{[]string{"udp", "tls"}, []Carrier{CarrierUDP, CarrierUDP, CarrierTLS}},
		{[]string{"udp"}, []Carrier{CarrierUDP, CarrierUDP, CarrierTLS}},
		{[]string{"tcp"}, []Carrier{CarrierTCP, CarrierUDP, CarrierUDP, CarrierTLS}},
		{nil, []Carrier{CarrierUDP, CarrierUDP, CarrierTLS, CarrierTCP}},
	} {
		if got := (SPAv2Options{Carriers: c.names}).FetchCarriers(); !slices.Equal(got, c.want) {
			t.Errorf("fetch order for %v: %v, want %v", c.names, got, c.want)
		}
	}
}

// A node that lists udp and tcp is never sent a ClientHello; one that lists only udp and tls never a bare packet.
func TestSPA2CarriersListed(t *testing.T) {
	node, options := newTCPNode(t, true, true)
	options.Carriers = []string{"udp", "tcp"}
	outbound := newBox(t, Options{SPAv2: options})
	node.dial(t, outbound)
	if outbound.carrier() != CarrierTCP || node.tls.Load() != 0 {
		t.Fatalf("carrier %v, %d ClientHellos to a node without tls", outbound.carrier(), node.tls.Load())
	}

	old, options := newTCPNode(t, false, true)
	options.Carriers = []string{"udp", "tls"}
	outbound = newBox(t, Options{SPAv2: options})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if conn, err := outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", old.servicePort)); err == nil {
		conn.Close()
		t.Fatal("opened by a carrier the node did not list")
	}
	if old.bare.Load() != 0 {
		t.Fatalf("%d bare packets to a node that listed udp and tls", old.bare.Load())
	}
}

// The carrier is a ClientHello crypto/tls reads as one: no server name (an address), TLS 1.3, the packet as the
// session ticket; and the rest of it is the core's Chrome reference.
func TestTLSCarrierShape(t *testing.T) {
	packet := bytes.Repeat([]byte{0xab}, 128)
	record, err := tlsCarrier(packet)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := fromTLSCarrier(record)
	if !ok || !bytes.Equal(got, packet) {
		t.Fatal("the node does not find the packet")
	}
	client, server := net.Pipe()
	defer client.Close()
	hello := make(chan *stdtls.ClientHelloInfo, 1)
	go func() {
		stdtls.Server(server, &stdtls.Config{GetConfigForClient: func(info *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			hello <- info
			return nil, errors.New("enough")
		}}).Handshake()
		server.Close()
	}()
	go client.Write(record)
	select {
	case info := <-hello:
		if info.ServerName != "" || !slices.Contains(info.SupportedVersions, stdtls.VersionTLS13) {
			t.Fatalf("server name %q, versions %v", info.ServerName, info.SupportedVersions)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("crypto/tls did not read a ClientHello")
	}
	h, err := chromehello.Parse(record)
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := chromehello.Raw()
	r, _ := chromehello.Parse(reference)
	// t13d…17… with a name, t13i…16… to an address (no server_name); the hashes of ciphers and extensions are equal
	ja4, ref := strings.SplitN(h.JA4(), "_", 2), strings.SplitN(r.JA4(), "_", 2)
	if !strings.HasPrefix(ja4[0], "t13i") || ja4[1] != ref[1] {
		t.Fatalf("JA4 %s, reference %s", h.JA4(), r.JA4())
	}
}

// TestSPA2TCPCarrierCoalesced: parallel dials that all find UDP cut send one TCP carrier packet between them, and
// all connect after it.
func TestSPA2TCPCarrierCoalesced(t *testing.T) {
	carrier, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer carrier.Close()
	slotPort := uint16(carrier.Addr().(*net.TCPAddr).Port)
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	servicePort := uint16(probe.Addr().(*net.TCPAddr).Port)
	probe.Close()
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: slotPort, PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
	}
	outbound := newBox(t, Options{SPAv2: &options})
	var carried atomic.Int32
	var service atomic.Pointer[net.Listener]
	var serviceOnce sync.Once
	go func() {
		for {
			conn, err := carrier.Accept()
			if err != nil {
				return
			}
			io.ReadAll(io.LimitReader(conn, 161))
			conn.Close()
			carried.Add(1)
			serviceOnce.Do(func() {
				l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(servicePort))))
				if err != nil {
					t.Error(err)
					return
				}
				service.Store(&l)
				go func() {
					for {
						c, err := l.Accept()
						if err != nil {
							return
						}
						c.Close()
					}
				}()
			})
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var failed atomic.Int32
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", servicePort))
			if err != nil {
				failed.Add(1)
				return
			}
			conn.Close()
		}()
	}
	wg.Wait()
	if l := service.Load(); l != nil {
		(*l).Close()
	}
	if failed.Load() != 0 {
		t.Fatalf("%d of 8 dials failed", failed.Load())
	}
	if n := carried.Load(); n != 1 {
		t.Fatalf("%d TCP carrier packets for 8 dials, want 1", n)
	}
	if outbound.carrier() == CarrierUDP {
		t.Fatal("the TCP carrier is not remembered")
	}
}

// Hosts: a Yggdrasil endpoint dials the node and the node's public peers through one knock outbound; only the node
// is knocked at, by name, by address, or by the address its name resolves to (a caller that resolved it first)
func TestSPA2Hosts(t *testing.T) {
	spaConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spaConn.Close()
	spaPort := uint16(spaConn.LocalAddr().(*net.UDPAddr).Port)
	packets := make(chan []byte, 8)
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, _, err := spaConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			packets <- bytes.Clone(buffer[:n])
		}
	}()
	r := &recorder{}
	server := listenTCP(t, r, "server")
	options := SPAv2Options{
		NodeID: "33333333333333333333333333333333", EpochLen: 86400, SlotLen: 600,
		PortKey:  "4444444444444444444444444444444444444444444444444444444444444444",
		PortBase: spaPort, PortRange: 1, LenMin: 96, LenMax: 160,
		DeviceKey: "1111111111111111111111111111111111111111111111111111111111111111",
		Scope:     []uint16{1}, TTL: 600,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dial := func(o *Outbound, host string, knocked bool) {
		t.Helper()
		conn, err := o.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort(host, server))
		if err != nil {
			t.Fatal(host, ": ", err)
		}
		conn.Close()
		select {
		case <-packets:
			if !knocked {
				t.Fatal(host, ": a host outside the list got an SPA packet")
			}
		case <-time.After(map[bool]time.Duration{true: 2 * time.Second, false: 300 * time.Millisecond}[knocked]):
			if knocked {
				t.Fatal(host, ": no SPA packet for the node")
			}
		}
	}

	// the node elsewhere: 127.0.0.1 is a public peer, by address, dialled plainly
	dial(newBox(t, Options{SPAv2: &options, Hosts: []string{"node.invalid"}}), "127.0.0.1", false)
	// the node by its address
	dial(newBox(t, Options{SPAv2: &options, Hosts: []string{"node.invalid", "127.0.0.1"}}), "127.0.0.1", true)
	// the node by name, and by the address a caller resolved its name to
	node := newBox(t, Options{SPAv2: &options, Hosts: []string{"localhost"}})
	dial(node, "localhost", true)
	node.forget(M.ParseSocksaddrHostPort("127.0.0.1", server))
	dial(node, "127.0.0.1", true)
	// without a list, everything is knocked at
	dial(newBox(t, Options{SPAv2: &options}), "127.0.0.1", true)

	// a failed lookup keeps what the name resolved to before: the node stays knocked at by address
	kept := newBox(t, Options{SPAv2: &options, Hosts: []string{"node.invalid"}})
	stale := time.Now().Add(-hostLookupTTL - time.Minute)
	kept.hosts.lookups["node.invalid"] = &hostLookup{
		addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, resolved: stale, tried: stale,
	}
	if kept.plain(ctx, M.ParseSocksaddrHostPort("127.0.0.2", server)) != true {
		t.Fatal("an address the name never had is knocked at")
	}
	if l := kept.hosts.lookups["node.invalid"]; len(l.addrs) != 1 || time.Since(l.tried) > time.Minute {
		t.Fatal("the failed lookup dropped the addresses or was not noted: ", l.addrs)
	}
	dial(kept, "127.0.0.1", true)
}
