package knock

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type recorder struct {
	access sync.Mutex
	events []string
}

func (r *recorder) add(event string) {
	r.access.Lock()
	r.events = append(r.events, event)
	r.access.Unlock()
}

func (r *recorder) snapshot() []string {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]string(nil), r.events...)
}

func listenTCP(t *testing.T, r *recorder, name string) uint16 {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			r.add(name)
			if name == "server" {
				go func() {
					defer conn.Close()
					io.Copy(conn, conn)
				}()
			} else {
				conn.Close()
			}
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func listenUDP(t *testing.T, r *recorder, name string, payloads chan<- string) uint16 {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, _, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			r.add(name)
			payloads <- string(buffer[:n])
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func newBox(t *testing.T, options Options) *Outbound {
	registry := outbound.NewRegistry()
	direct.RegisterOutbound(registry)
	Register(registry)
	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	ctx := box.Context(context.Background(), inbound.NewRegistry(), registry, endpoint.NewRegistry(),
		dnsRegistry, service.NewRegistry(), certificate.NewRegistry())
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Log:       &option.LogOptions{Disabled: true},
			Outbounds: []option.Outbound{{Type: TypeKnock, Tag: "knock", Options: &options}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	outbound, loaded := instance.Outbound().Outbound("knock")
	if !loaded {
		t.Fatal("knock outbound not found")
	}
	return outbound.(*Outbound)
}

func TestKnockSequenceBeforeDial(t *testing.T) {
	r := &recorder{}
	payloads := make(chan string, 4)
	first := listenTCP(t, r, "tcp-1")
	second := listenUDP(t, r, "udp-2", payloads)
	server := listenTCP(t, r, "server")

	outbound := newBox(t, Options{
		Sequence: []Step{{Port: first}, {Port: second, Network: "udp", Payload: "6b6e6f636b"}},
		Interval: 0,
		TTL:      0,
	})
	outbound.interval = 50 * time.Millisecond
	outbound.ttl = time.Minute

	destination := M.ParseSocksaddrHostPort("127.0.0.1", server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if payload := <-payloads; payload != "knock" {
		t.Fatalf("udp payload: %q", payload)
	}
	time.Sleep(100 * time.Millisecond)
	events := r.snapshot()
	want := []string{"tcp-1", "udp-2", "server"}
	if len(events) != len(want) {
		t.Fatalf("events: %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events: %v, want %v", events, want)
		}
	}

	// within ttl the sequence is not repeated
	conn, err = outbound.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(100 * time.Millisecond)
	if events = r.snapshot(); len(events) != 4 || events[3] != "server" {
		t.Fatalf("second dial re-knocked: %v", events)
	}
}

func TestParseSequence(t *testing.T) {
	for i, sequence := range [][]Step{
		nil,
		{{Port: 0}},
		{{Port: 1, Network: "icmp"}},
		{{Port: 1, Payload: "00"}},
		{{Port: 1, Network: "udp", Payload: "zz"}},
	} {
		if _, err := parseSequence(sequence); err == nil {
			t.Fatal("case " + strconv.Itoa(i) + ": expected error")
		}
	}
	steps, err := parseSequence([]Step{{Port: 7000}, {Port: 8000, Network: "UDP", Payload: "ff"}})
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].udp || !steps[1].udp || steps[1].payload[0] != 0xff {
		t.Fatalf("unexpected steps: %+v", steps)
	}
}

func count(events []string, name string) int {
	n := 0
	for _, event := range events {
		if event == name {
			n++
		}
	}
	return n
}

func TestReknockAfterNetworkChange(t *testing.T) {
	r := &recorder{}
	knockPort := listenTCP(t, r, "knock")
	server := listenTCP(t, r, "server")
	outbound := newBox(t, Options{Sequence: []Step{{Port: knockPort}}})
	outbound.interval = 20 * time.Millisecond
	outbound.ttl = time.Minute
	destination := M.ParseSocksaddrHostPort("127.0.0.1", server)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		conn, err := outbound.DialContext(ctx, N.NetworkTCP, destination)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		if i == 0 {
			outbound.InterfaceUpdated(ctx)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := count(r.snapshot(), "knock"); n != 2 {
		t.Fatalf("knocks after network change: %d, want 2", n)
	}
}

func TestReknockWhenCachedDialFails(t *testing.T) {
	r := &recorder{}
	knockPort := listenTCP(t, r, "knock")
	outbound := newBox(t, Options{Sequence: []Step{{Port: knockPort}}})
	outbound.interval = 20 * time.Millisecond
	outbound.ttl = time.Minute
	// a closed port: the dial fails although a knock is cached
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	destination := M.ParseSocksaddrHostPort("127.0.0.1", uint16(closed.Addr().(*net.TCPAddr).Port))
	closed.Close()
	ctx := context.Background()
	if _, err = outbound.knock(ctx, destination, false); err != nil {
		t.Fatal(err)
	}
	outbound.target(destination.AddrString()).lastKnock = time.Now().Add(-minReknockGap)
	if _, err = outbound.DialContext(ctx, N.NetworkTCP, destination); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	time.Sleep(100 * time.Millisecond)
	if n := count(r.snapshot(), "knock"); n != 2 {
		t.Fatalf("knocks: %d, want a second knock after the failed dial", n)
	}
	// the retry after a fresh knock failed too, so the next dial knocks again
	if outbound.cached(destination) {
		t.Fatal("failed dial after a fresh knock kept it cached")
	}
}

// silentUDP is a server that receives but never answers.
func silentUDP(t *testing.T) M.Socksaddr {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { silent.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			if _, _, err := silent.ReadFrom(buffer); err != nil {
				return
			}
		}
	}()
	return M.SocksaddrFromNet(silent.LocalAddr())
}

func newSilenceBox(t *testing.T, r *recorder) *Outbound {
	knockPort := listenTCP(t, r, "knock")
	outbound := newBox(t, Options{Sequence: []Step{{Port: knockPort}}})
	outbound.interval = 20 * time.Millisecond
	outbound.ttl = time.Minute
	outbound.silence = 150 * time.Millisecond
	return outbound
}

func TestReknockOnSilencePacketConn(t *testing.T) {
	r := &recorder{}
	outbound := newSilenceBox(t, r)
	destination := silentUDP(t)
	packetConn, err := outbound.ListenPacket(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	outbound.target(destination.AddrString()).lastKnock = time.Now().Add(-minReknockGap)
	for i := 0; i < 6; i++ {
		if _, err = packetConn.WriteTo([]byte("x"), destination.UDPAddr()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	// one knock on dial, one re-knock for the silence episode, not one per write
	if n := count(r.snapshot(), "knock"); n != 2 {
		t.Fatalf("knocks: %d, want exactly one re-knock", n)
	}
}

// WireGuard with one peer dials its UDP socket instead of listening.
func TestReknockOnSilenceDialedUDP(t *testing.T) {
	r := &recorder{}
	outbound := newSilenceBox(t, r)
	destination := silentUDP(t)
	conn, err := outbound.DialContext(context.Background(), N.NetworkUDP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	outbound.target(destination.AddrString()).lastKnock = time.Now().Add(-minReknockGap)
	if _, err = conn.Write([]byte("handshake")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if n := count(r.snapshot(), "knock"); n != 2 {
		t.Fatalf("knocks: %d, want a re-knock for the dialed UDP session", n)
	}
}

func TestTCPConnectionsAreNotWatched(t *testing.T) {
	r := &recorder{}
	outbound := newSilenceBox(t, r)
	server := listenTCP(t, r, "server")
	conn, err := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", server))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, wrapped := conn.(*silentConn); wrapped {
		t.Fatal("tcp connection wrapped: half-close and splice would be lost")
	}
}

func TestWireGuardKeepaliveDoesNotArm(t *testing.T) {
	r := &recorder{}
	outbound := newSilenceBox(t, r)
	destination := silentUDP(t)
	conn, err := outbound.DialContext(context.Background(), N.NetworkUDP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	keepalive := make([]byte, 32)
	keepalive[0] = 4
	keepalive[1] = 0x12 // reserved bytes
	for i := 0; i < 4; i++ {
		if _, err = conn.Write(keepalive); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if n := count(r.snapshot(), "knock"); n != 1 {
		t.Fatalf("knocks: %d, keepalives on an idle tunnel must not re-knock", n)
	}
}

func TestSkippedReknockStaysArmed(t *testing.T) {
	r := &recorder{}
	outbound := newSilenceBox(t, r)
	destination := silentUDP(t)
	conn, err := outbound.DialContext(context.Background(), N.NetworkUDP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// the dial knocked just now, so the first silence re-knock is skipped by minReknockGap
	if _, err = conn.Write([]byte("handshake")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if conn.(*silentConn).knocked.Load() {
		t.Fatal("watchdog disarmed although nothing was knocked")
	}
}

func TestNetworkChangeDoesNotBlock(t *testing.T) {
	r := &recorder{}
	knockPort := listenTCP(t, r, "knock")
	outbound := newBox(t, Options{Sequence: []Step{{Port: knockPort}, {Port: knockPort}}})
	outbound.interval = 300 * time.Millisecond
	destination := M.ParseSocksaddrHostPort("127.0.0.1", knockPort)
	go outbound.knock(context.Background(), destination, false)
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	outbound.InterfaceUpdated(context.Background())
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("InterfaceUpdated waited %v for a knock in flight", elapsed)
	}
	time.Sleep(700 * time.Millisecond)
	// the knock started before the change must not count for the new network
	if outbound.cached(destination) {
		t.Fatal("knock from before the network change is still cached")
	}
}

func TestDefaultUDPPayloadLikeKnockClient(t *testing.T) {
	r := &recorder{}
	payloads := make(chan string, 1)
	port := listenUDP(t, r, "udp", payloads)
	outbound := newBox(t, Options{Sequence: []Step{{Port: port, Network: "udp"}}})
	outbound.interval = 10 * time.Millisecond
	if _, err := outbound.knock(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", port), false); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-payloads:
		if payload != "\x00" {
			t.Fatalf("payload %q, want one zero byte", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("no udp knock")
	}
}

func TestStrictOrderWithShortInterval(t *testing.T) {
	r := &recorder{}
	var steps []Step
	var want []string
	for i := 0; i < 6; i++ {
		name := "p" + strconv.Itoa(i)
		steps = append(steps, Step{Port: listenTCP(t, r, name)})
		want = append(want, name)
	}
	outbound := newBox(t, Options{Sequence: steps})
	outbound.interval = 10 * time.Millisecond
	if _, err := outbound.knock(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 1), false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	events := r.snapshot()
	if len(events) != len(want) {
		t.Fatalf("events %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events %v, want %v", events, want)
		}
	}
}

// A dropped port never answers; the attempt must end before the kernel
// retransmits the SYN (1s), whatever the interval, or knockd sees a late SYN
// to the previous port and resets the sequence.
func TestTCPAttemptEndsBeforeRetransmit(t *testing.T) {
	for _, interval := range []time.Duration{0, 10 * time.Millisecond, 200 * time.Millisecond, time.Second, time.Minute} {
		timeout := tcpAttemptTimeout(interval)
		if timeout >= time.Second || timeout < minTCPAttempt {
			t.Fatalf("interval %v: attempt timeout %v", interval, timeout)
		}
	}
}
