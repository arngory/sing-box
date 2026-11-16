package knock

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// The schedule is the SPA port formula with the service's key and range (spa-v2.md §11).
func TestNekoUDPPortsFormula(t *testing.T) {
	p, err := parseSPAv2(SPAv2Options{
		NodeID: strings.Repeat("33", 16), EpochLen: 86400, SlotLen: 600, PortKey: strings.Repeat("44", 32),
		PortBase: 40000, PortRange: 4096, LenMin: 96, LenMax: 160, DeviceKey: strings.Repeat("11", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	schedules, err := parseUDPPorts([]UDPPortSchedule{{Port: 443, PortKey: strings.Repeat("44", 32), PortBase: 40000, PortRange: 4096}}, p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1767225600, 0)
	if got, want := schedules[443].port(now), p.port(p.slot(now)); got != want {
		t.Fatalf("slot port %d, SPA formula gives %d", got, want)
	}
	if _, err = parseUDPPorts([]UDPPortSchedule{{Port: 443, PortKey: "00", PortBase: 1, PortRange: 1}}, p); err == nil {
		t.Fatal("accepted a short key")
	}
	if _, err = parseUDPPorts([]UDPPortSchedule{{Port: 443, PortKey: strings.Repeat("44", 32), PortBase: 65000, PortRange: 1000}}, p); err == nil {
		t.Fatal("accepted a range past 65535")
	}
	if _, err = parseUDPPorts([]UDPPortSchedule{{Port: 443, PortKey: strings.Repeat("44", 32), PortBase: 1, PortRange: 1}}, nil); err == nil {
		t.Fatal("accepted udp_ports without spa_v2")
	}
}

// One socket follows the slot port; replies from any slot port look like the service's address.
func TestNekoUDPPortsRotate(t *testing.T) {
	listen := func() net.PacketConn {
		t.Helper()
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	portOf := func(conn net.PacketConn) uint16 { return uint16(conn.LocalAddr().(*net.UDPAddr).Port) }
	slotA, slotB, slotC := listen(), listen(), listen()
	defer slotA.Close()
	defer slotB.Close()
	defer slotC.Close()
	var slot atomic.Pointer[net.PacketConn]
	slot.Store(&slotA)

	first := listen()
	service := M.ParseSocksaddrHostPort("127.0.0.1", 443)
	var opened atomic.Int32
	conn := newRotatingUDPConn(first, service, &portSchedule{span: 1, slotLen: 1}, func() (net.PacketConn, error) {
		opened.Add(1)
		return net.ListenPacket("udp", "127.0.0.1:0")
	})
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	conn.now = func() time.Time { return time.Unix(0, clock.Load()) }
	conn.portAt = func(time.Time) uint16 { return portOf(*slot.Load()) }
	var turns []uint16
	conn.onTurn = func(from, to uint16, err error) {
		if err != nil {
			t.Errorf("turn without a socket: %v", err)
		}
		turns = append(turns, from, to)
	}
	defer conn.Close()

	buf := make([]byte, 64)
	read := func(want string) {
		t.Helper()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("client got %q, %v; want %q", buf[:n], err, want)
		}
	}
	// send writes payload and returns the client address the slot's server saw it from
	send := func(server net.PacketConn, payload string) net.Addr {
		t.Helper()
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := server.ReadFrom(buf)
		if err != nil || string(buf[:n]) != payload {
			t.Fatalf("server got %q, %v", buf[:n], err)
		}
		return from
	}

	fromA := send(slotA, "one")
	if fromA.(*net.UDPAddr).Port != int(portOf(first)) {
		t.Fatalf("first slot from %v, want the first socket", fromA)
	}
	slotA.WriteTo([]byte("re:one"), fromA)
	read("re:one")

	// the turn: a new client port, so the node's NAT sees a flow of its own, not a second redirect of the first
	slot.Store(&slotB)
	fromB := send(slotB, "two")
	if fromB.(*net.UDPAddr).Port == fromA.(*net.UDPAddr).Port || opened.Load() != 1 {
		t.Fatalf("after the turn from %v (before %v), %d sockets opened; want a new one", fromB, fromA, opened.Load())
	}
	if conn.RemoteAddr().String() != "127.0.0.1:443" {
		t.Fatalf("remote address %v, want the service's", conn.RemoteAddr())
	}
	// a server that moved answers the new socket, one that has not the old one: both reach the flow
	slotB.WriteTo([]byte("re:two"), fromB)
	read("re:two")
	slotA.WriteTo([]byte("late"), fromA)
	read("late")
	if len(turns) != 2 || turns[0] != portOf(slotA) || turns[1] != portOf(slotB) {
		t.Fatalf("turns %v", turns)
	}

	// a datagram from another host is dropped
	if stranger, err := net.ListenPacket("udp", "127.0.0.2:0"); err == nil {
		stranger.WriteTo([]byte("x"), fromB)
		slotB.WriteTo([]byte("ok"), fromB)
		read("ok")
		stranger.Close()
	}

	// the next turn after a quiet while: of the earlier sockets the one heard from last stays (a server that never
	// moves answers there), the quiet others close
	clock.Add(int64(time.Millisecond))
	slotA.WriteTo([]byte("latest"), fromA)
	read("latest")
	clock.Add(int64(rotatingQuiet + time.Second))
	slot.Store(&slotC)
	fromC := send(slotC, "three")
	conn.access.Lock()
	var open []uint16
	for _, s := range conn.sockets {
		open = append(open, portOf(s.PacketConn))
	}
	conn.access.Unlock()
	if len(open) != 2 || open[0] != uint16(fromA.(*net.UDPAddr).Port) || open[1] != uint16(fromC.(*net.UDPAddr).Port) {
		t.Fatalf("open sockets %v; want the last heard from (%v) and the current (%v)", open, fromA, fromC)
	}

	conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

// TestNekoUDPPortsRotateNoSocket: a turn without a new socket keeps the flow on its own one at the new port.
func TestNekoUDPPortsRotateNoSocket(t *testing.T) {
	slotA, _ := net.ListenPacket("udp", "127.0.0.1:0")
	slotB, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer slotA.Close()
	defer slotB.Close()
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn := newRotatingUDPConn(local, M.ParseSocksaddrHostPort("127.0.0.1", 443), &portSchedule{span: 1, slotLen: 1}, func() (net.PacketConn, error) {
		return nil, errors.New("no socket")
	})
	defer conn.Close()
	var second atomic.Bool
	conn.portAt = func(time.Time) uint16 {
		if second.Load() {
			return uint16(slotB.LocalAddr().(*net.UDPAddr).Port)
		}
		return uint16(slotA.LocalAddr().(*net.UDPAddr).Port)
	}
	conn.Write([]byte("a"))
	second.Store(true)
	if _, err := conn.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	slotB.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := slotB.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "b" || from.(*net.UDPAddr).Port != local.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("got %q from %v, %v", buf[:n], from, err)
	}
}

// TestNekoUDPPortsCache: the cached port of a slot is the formula's, also across slots and back.
func TestNekoUDPPortsCache(t *testing.T) {
	s := &portSchedule{base: 40000, span: 4096, slotLen: 600}
	copy(s.key[:], bytes.Repeat([]byte{0x44}, len(s.key)))
	for _, at := range []int64{0, 599, 600, 1767268800, 1767268800 + 599, 1767268800 + 600, 1767268800} {
		want := slotPort(s.key[:], s.base, s.span, uint64(at)/s.slotLen)
		for range 2 {
			if got := s.port(time.Unix(at, 0)); got != want {
				t.Fatalf("t=%d: port %d, want %d", at, got, want)
			}
		}
	}
}

func BenchmarkNekoUDPPortCached(b *testing.B) {
	s := &portSchedule{base: 40000, span: 4096, slotLen: 600}
	now := time.Now()
	for range b.N {
		s.port(now)
	}
}
