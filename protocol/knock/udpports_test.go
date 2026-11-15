package knock

import (
	"bytes"
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
	slotA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer slotA.Close()
	slotB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer slotB.Close()
	portA := uint16(slotA.LocalAddr().(*net.UDPAddr).Port)
	portB := uint16(slotB.LocalAddr().(*net.UDPAddr).Port)

	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service := M.ParseSocksaddrHostPort("127.0.0.1", 443)
	conn := newRotatingUDPConn(local, service, &portSchedule{span: 1, slotLen: 1})
	var second atomic.Bool
	conn.portAt = func(time.Time) uint16 {
		if second.Load() {
			return portB
		}
		return portA
	}
	var turns []uint16
	conn.onTurn = func(from, to uint16) { turns = append(turns, from, to) }
	defer conn.Close()

	roundTrip := func(server net.PacketConn, payload string) {
		t.Helper()
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := server.ReadFrom(buf)
		if err != nil || string(buf[:n]) != payload {
			t.Fatalf("server got %q, %v", buf[:n], err)
		}
		// the same client port across slots: the node keeps one flow
		if from.(*net.UDPAddr).Port != local.LocalAddr().(*net.UDPAddr).Port {
			t.Fatalf("client port changed: %v", from)
		}
		if _, err := server.WriteTo([]byte("re:"+payload), from); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err = conn.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], []byte("re:"+payload)) {
			t.Fatalf("client got %q, %v", buf[:n], err)
		}
	}
	roundTrip(slotA, "one")
	second.Store(true)
	roundTrip(slotB, "two")
	if conn.RemoteAddr().String() != "127.0.0.1:443" {
		t.Fatalf("remote address %v, want the service's", conn.RemoteAddr())
	}
	if len(turns) != 2 || turns[0] != portA || turns[1] != portB {
		t.Fatalf("turns %v", turns)
	}

	// a datagram from another host is dropped
	stranger, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Skip("no 127.0.0.2:", err)
	}
	defer stranger.Close()
	stranger.WriteTo([]byte("x"), local.LocalAddr())
	slotB.WriteTo([]byte("ok"), local.LocalAddr())
	buf := make([]byte, 8)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("got %q, %v; want only the node's datagram", buf[:n], err)
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
