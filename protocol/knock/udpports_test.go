package knock

import (
	"bytes"
	"net"
	"strings"
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
// TestNekoUDPPortsSlotKept: a flow keeps the slot port it was dialed in, from its one socket, whatever the
// slot is later (the node keeps an established flow's redirect; a moved one is dropped), and reads only the node.
func TestNekoUDPPortsSlotKept(t *testing.T) {
	slotA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer slotA.Close()
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service := M.ParseSocksaddrHostPort("127.0.0.1", 443)
	conn := newSlotUDPConn(local, service, uint16(slotA.LocalAddr().(*net.UDPAddr).Port))
	defer conn.Close()

	buf := make([]byte, 64)
	for _, payload := range []string{"one", "two"} {
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		slotA.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := slotA.ReadFrom(buf)
		if err != nil || string(buf[:n]) != payload {
			t.Fatalf("slot got %q, %v", buf[:n], err)
		}
		if from.(*net.UDPAddr).Port != local.LocalAddr().(*net.UDPAddr).Port {
			t.Fatalf("from %v, want the flow's one socket", from)
		}
		slotA.WriteTo([]byte("re:"+payload), from)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err = conn.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], []byte("re:"+payload)) {
			t.Fatalf("client got %q, %v", buf[:n], err)
		}
	}
	if conn.RemoteAddr().String() != "127.0.0.1:443" {
		t.Fatalf("remote address %v, want the service's", conn.RemoteAddr())
	}

	// a datagram from another host is dropped
	stranger, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Skip("no 127.0.0.2:", err)
	}
	defer stranger.Close()
	stranger.WriteTo([]byte("x"), local.LocalAddr())
	slotA.WriteTo([]byte("ok"), local.LocalAddr())
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
