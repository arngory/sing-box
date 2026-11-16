//go:build with_naive_outbound

package naive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/cronet-go"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// fakeDatagramConn stands for cronet's DatagramConn: it records what is written and hands out queued frames.
type fakeDatagramConn struct {
	access     sync.Mutex
	written    [][]byte
	writeErr   error
	maxPayload int
	frames     chan []byte
	truncate   bool
	status     int
	headers    map[string]string
	readyErr   error
	done       chan struct{}
	err        error
	closed     bool
}

func newFakeDatagramConn() *fakeDatagramConn {
	return &fakeDatagramConn{frames: make(chan []byte, 16), done: make(chan struct{}), status: 200,
		headers: map[string]string{"niko-udp": "1"}}
}

func (f *fakeDatagramConn) WaitReady(ctx context.Context) (int, map[string]string, error) {
	return f.status, f.headers, f.readyErr
}

func (f *fakeDatagramConn) ReadDatagram(ctx context.Context, b []byte) (int, error) {
	frame, ok := <-f.frames
	if !ok {
		return 0, net.ErrClosed
	}
	n := copy(b, frame)
	if n < len(frame) {
		return n, errDatagramTruncated
	}
	return n, nil
}

func (f *fakeDatagramConn) WriteDatagram(b []byte) error {
	f.access.Lock()
	defer f.access.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	f.written = append(f.written, append([]byte(nil), b...))
	return nil
}

func (f *fakeDatagramConn) MaxPayload() int                  { return f.maxPayload }
func (f *fakeDatagramConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeDatagramConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeDatagramConn) Done() <-chan struct{}            { return f.done }
func (f *fakeDatagramConn) Err() error                       { return f.err }

func (f *fakeDatagramConn) Close() error {
	f.access.Lock()
	defer f.access.Unlock()
	f.closed = true
	return nil
}

func (f *fakeDatagramConn) frameCount() int {
	f.access.Lock()
	defer f.access.Unlock()
	return len(f.written)
}

func TestNekoDatagramAddress(t *testing.T) {
	for _, c := range []struct {
		name        string
		destination M.Socksaddr
		want        []byte
	}{
		{"ipv4", M.ParseSocksaddrHostPort("1.2.3.4", 53), []byte{4, 1, 2, 3, 4, 0, 53}},
		{"ipv4 in ipv6", M.SocksaddrFrom(netip.MustParseAddr("::ffff:1.2.3.4"), 443), []byte{4, 1, 2, 3, 4, 1, 187}},
		{"ipv6", M.ParseSocksaddrHostPort("2001:db8::1", 3478),
			append(append([]byte{6}, netip.MustParseAddr("2001:db8::1").AsSlice()...), 0x0d, 0x96)},
		{"name", M.Socksaddr{Fqdn: "example.com", Port: 443}, append(append([]byte{3, 11}, "example.com"...), 1, 187)},
	} {
		got, err := appendDatagramAddress(nil, c.destination)
		if err != nil || !bytes.Equal(got, c.want) {
			t.Errorf("%s: got %x, %v; want %x", c.name, got, err, c.want)
		}
	}
	for _, c := range []struct {
		name        string
		destination M.Socksaddr
	}{
		{"port 0", M.ParseSocksaddrHostPort("1.2.3.4", 0)},
		{"nothing", M.Socksaddr{Port: 53}},
		{"name too long", M.Socksaddr{Fqdn: strings.Repeat("a", 256), Port: 53}},
	} {
		if _, err := appendDatagramAddress(nil, c.destination); err == nil {
			t.Errorf("%s: an address with no form was written", c.name)
		}
	}
}

func TestNekoDatagramParse(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::2")
	mapped := netip.MustParseAddr("::ffff:9.8.7.6").As16()
	for _, c := range []struct {
		name   string
		frame  []byte
		source string
		header int
	}{
		{"ipv4", []byte{4, 9, 8, 7, 6, 0, 53, 'x'}, "9.8.7.6:53", 7},
		{"ipv6", append(append([]byte{6}, v6.AsSlice()...), 1, 187, 'y'), "[2001:db8::2]:443", 19},
		{"ipv4 in ipv6", append(append([]byte{6}, mapped[:]...), 0, 53), "9.8.7.6:53", 19},
	} {
		source, header, err := parseDatagramAddress(c.frame)
		if err != nil || source.String() != c.source || header != c.header {
			t.Errorf("%s: got %s %d %v; want %s %d", c.name, source, header, err, c.source, c.header)
		}
	}
	for _, c := range []struct {
		name  string
		frame []byte
	}{
		{"empty", nil},
		{"short ipv4", []byte{4, 1, 2, 3, 4, 0}},
		{"short ipv6", append([]byte{6}, make([]byte, 17)...)},
		{"a name from the node", append(append([]byte{3, 1}, 'a'), 0, 53)},
		{"unknown type", []byte{5, 1, 2, 3, 4, 0, 53}},
		{"port 0", []byte{4, 1, 2, 3, 4, 0, 0}},
	} {
		if _, _, err := parseDatagramAddress(c.frame); err == nil {
			t.Errorf("%s: an unreadable address was taken", c.name)
		}
	}
}

func quicInitial(version uint32, size int) []byte {
	p := make([]byte, size)
	p[0] = 0xc3
	p[1], p[2], p[3], p[4] = byte(version>>24), byte(version>>16), byte(version>>8), byte(version)
	return p
}

func TestNekoDatagramQUICHeader(t *testing.T) {
	for _, c := range []struct {
		name string
		p    []byte
		want bool
	}{
		{"v1", quicInitial(1, 1200), true},
		{"v2", quicInitial(0x6b3343cf, 1200), true},
		{"draft-29", quicInitial(0xff00001d, 1200), false},
		{"short header", append([]byte{0x43}, make([]byte, 30)...), false},
		{"too short", []byte{0xc3, 0, 0, 0}, false},
		{"dns", []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01}, false},
	} {
		if got := isQUICLongHeader(c.p); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNekoDatagramWriteRules(t *testing.T) {
	quicServer := M.ParseSocksaddrHostPort("5.6.7.8", 443)
	dns := M.Socksaddr{Fqdn: "dns.example", Port: 53}
	fake := newFakeDatagramConn()
	conn := newDatagramPacketConn(fake)

	// before the node's answer every datagram goes as a capsule (MaxPayload 0)
	if _, err := conn.WriteTo(quicInitial(1, 1200), quicServer); err != nil {
		t.Fatal(err)
	}
	// a QUIC pair's datagram over 1252 bytes that would need a capsule is dropped, not an error
	if _, err := conn.WriteTo(make([]byte, 1300), quicServer); err != nil {
		t.Fatal(err)
	}
	if n := fake.frameCount(); n != 1 {
		t.Fatalf("a QUIC pair's long datagram went as a capsule: %d frames", n)
	}
	// up to 1252 a QUIC pair's datagram goes as a capsule
	if _, err := conn.WriteTo(make([]byte, quicPairCapsuleLimit), quicServer); err != nil || fake.frameCount() != 2 {
		t.Fatalf("a QUIC pair's datagram of %d bytes was not sent: %v", quicPairCapsuleLimit, err)
	}
	// once a QUIC datagram holds it, the long one goes
	fake.maxPayload = 1400
	if _, err := conn.WriteTo(make([]byte, 1300), quicServer); err != nil || fake.frameCount() != 3 {
		t.Fatalf("a QUIC pair's datagram that fits a QUIC datagram was not sent: %v", err)
	}
	// a pair that began otherwise takes a capsule of any size
	fake.maxPayload = 0
	if _, err := conn.WriteTo(make([]byte, 4000), dns); err != nil || fake.frameCount() != 4 {
		t.Fatalf("a long datagram of a pair that is not QUIC was not sent: %v", err)
	}
	// a later QUIC packet does not make a pair QUIC: the first datagram decides
	if _, err := conn.WriteTo(quicInitial(1, 1300), dns); err != nil || fake.frameCount() != 5 {
		t.Fatalf("the pair turned QUIC on a later datagram: %v", err)
	}
	// the frame: the destination's address, then the payload
	fake.access.Lock()
	first := fake.written[0]
	fake.access.Unlock()
	if !bytes.Equal(first[:7], []byte{4, 5, 6, 7, 8, 1, 187}) || len(first) != 7+1200 {
		t.Errorf("frame %x...", first[:8])
	}

	// no room in the library: lost as UDP is; a closed request: an error
	fake.writeErr = errDatagramQueueFull
	if _, err := conn.WriteTo([]byte("x"), dns); err != nil {
		t.Errorf("a full queue was an error: %v", err)
	}
	fake.writeErr = errDatagramCapsuleTimeout
	if _, err := conn.WriteTo([]byte("x"), dns); err != nil {
		t.Errorf("a capsule timeout was an error: %v", err)
	}
	fake.writeErr = errDatagramClosed
	if _, err := conn.WriteTo([]byte("x"), dns); !errors.Is(err, errDatagramClosed) {
		t.Errorf("a closed request was not an error: %v", err)
	}
	fake.writeErr = nil
	if _, err := conn.WriteTo([]byte("x"), M.Socksaddr{Port: 53}); err == nil {
		t.Error("a destination with no address was written")
	}
}

func TestNekoDatagramWritePacketHeadroom(t *testing.T) {
	fake := newFakeDatagramConn()
	conn := newDatagramPacketConn(fake)
	destination := M.Socksaddr{Fqdn: "a.example", Port: 53}
	buffer := buf.NewSize(conn.FrontHeadroom() + 64)
	buffer.Resize(conn.FrontHeadroom(), 0)
	buffer.Write([]byte("query"))
	if err := conn.WritePacket(buffer, destination); err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{3, 9}, "a.example"...), 0, 53)
	want = append(want, "query"...)
	if fake.frameCount() != 1 || !bytes.Equal(fake.written[0], want) {
		t.Fatalf("frame %x, want %x", fake.written, want)
	}
	// without headroom the frame is built in a copy
	small := buf.NewSize(16)
	small.Write([]byte("query"))
	if err := conn.WritePacket(small, destination); err != nil {
		t.Fatal(err)
	}
	if fake.frameCount() != 2 || !bytes.Equal(fake.written[1], want) {
		t.Fatalf("frame without headroom %x, want %x", fake.written[1], want)
	}
}

func TestNekoDatagramRead(t *testing.T) {
	fake := newFakeDatagramConn()
	conn := newDatagramPacketConn(fake)
	fake.frames <- []byte{5, 0, 0}                        // unreadable: skipped
	fake.frames <- []byte{4, 9, 8, 7, 6, 0, 53, 'o', 'k'} // taken
	fake.frames <- []byte{4, 9, 8, 7, 6, 0, 53, 'l', 'o', 'n', 'g'}
	close(fake.frames)

	buffer := buf.NewPacket()
	defer buffer.Release()
	source, err := conn.ReadPacket(buffer)
	if err != nil || source.String() != "9.8.7.6:53" || string(buffer.Bytes()) != "ok" {
		t.Fatalf("got %s %q %v", source, buffer.Bytes(), err)
	}
	// a buffer too short: the payload cut, as UDP cuts it
	p := make([]byte, 9)
	n, addr, err := conn.ReadFrom(p)
	if err != nil || string(p[:n]) != "lo" || addr.String() != "9.8.7.6:53" {
		t.Fatalf("cut read: %q %v %v", p[:n], addr, err)
	}
	if _, _, err = conn.ReadFrom(p); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after the end: %v", err)
	}
}

func TestNekoDatagramAccepted(t *testing.T) {
	for _, c := range []struct {
		status  int
		headers map[string]string
		want    bool
	}{
		{200, map[string]string{"niko-udp": "1"}, true},
		{200, map[string]string{"Niko-UDP": " 1 "}, true},
		{200, map[string]string{}, false},
		{200, map[string]string{"niko-udp": "2"}, false},
		{404, map[string]string{"niko-udp": "1"}, false},
		{429, nil, false},
	} {
		if got := datagramAccepted(c.status, c.headers); got != c.want {
			t.Errorf("%d %v: %v, want %v", c.status, c.headers, got, c.want)
		}
	}
}

func TestNekoDatagramWatch(t *testing.T) {
	newClient := func() *datagramClient {
		d := &datagramClient{ctx: context.Background(), logger: log.NewNOPFactory().Logger()}
		d.allowed.Store(true)
		return d
	}

	// accepted, then the node ends the request cleanly: nothing changes
	d := newClient()
	fake := newFakeDatagramConn()
	fake.err = io.EOF
	close(fake.done)
	d.watch(context.Background(), fake, d.generation.Load())
	if !d.usable() {
		t.Error("a clean end sent sockets back over UoT")
	}

	// accepted, then the QUIC connection breaks: back over UoT
	d = newClient()
	fake = newFakeDatagramConn()
	fake.err = errors.New("net error -101")
	close(fake.done)
	d.watch(context.Background(), fake, d.generation.Load())
	if d.usable() {
		t.Error("a broken connection kept datagrams")
	}

	// the node answers otherwise: back over UoT, the request closed
	for _, answer := range []struct {
		status  int
		headers map[string]string
		err     error
	}{
		{404, nil, nil},
		{200, nil, nil},
		{0, nil, errors.New("net error -322")},
		{0, nil, errDatagramUnsupported},
	} {
		d = newClient()
		fake = newFakeDatagramConn()
		fake.status, fake.headers, fake.readyErr = answer.status, answer.headers, answer.err
		d.watch(context.Background(), fake, d.generation.Load())
		if d.usable() || !fake.closed {
			t.Errorf("answer %d %v: usable %v, closed %v", answer.status, answer.err, d.usable(), fake.closed)
		}
	}

	// a 429 or a 503 refuses this socket only: it ends, the next one asks again
	for _, status := range []int{429, 503} {
		d = newClient()
		fake = newFakeDatagramConn()
		fake.status, fake.headers = status, nil
		d.watch(context.Background(), fake, d.generation.Load())
		if !d.usable() || !fake.closed {
			t.Errorf("answer %d: usable %v, closed %v", status, d.usable(), fake.closed)
		}
	}

	// the app closed the socket before the answer: not the path's fault
	d = newClient()
	fake = newFakeDatagramConn()
	fake.readyErr = net.ErrClosed
	d.watch(context.Background(), fake, d.generation.Load())
	if !d.usable() {
		t.Error("a socket the app closed sent sockets back over UoT")
	}

	// a new network forgets the refusal and waits for the app's probe
	d = newClient()
	d.refuse(d.generation.Load(), "test")
	d.networkChanged()
	if d.usable() || d.refused.Load() {
		t.Error("a new network kept the last one's decision")
	}
	d.allowed.Store(true)
	if !d.usable() {
		t.Error("the app's allowance after the probe did not take")
	}
	// a request of the last network that fails once its connections are closed says nothing about this one
	last := d.generation.Load()
	d.networkChanged()
	d.allowed.Store(true)
	fake = newFakeDatagramConn()
	fake.err = errors.New("net error -3")
	close(fake.done)
	d.watch(context.Background(), fake, last)
	if !d.usable() {
		t.Error("the last network's closed request sent this one's sockets back over UoT")
	}
	var none *datagramClient
	if none.usable() {
		t.Error("an outbound without the option uses datagrams")
	}
	none.networkChanged()
}

func TestNekoDatagramPadding(t *testing.T) {
	for i := 0; i < 100; i++ {
		p := datagramPadding()
		if len(p) < 30 || len(p) > 61 || strings.Trim(p[16:], "~") != "" {
			t.Fatalf("padding %q", p)
		}
	}
}

func TestNekoDatagramClientURL(t *testing.T) {
	d := newDatagramClient(context.Background(), log.NewNOPFactory().Logger(),
		cronet.NaiveClientOptions{ServerAddress: M.ParseSocksaddrHostPort("10.0.0.1", 443), QUIC: false, InsecureConcurrency: 4},
		"node.example", "Basic dTpw")
	if d.url != "https://node.example:443/.well-known/masque/udp/%2A/%2A/" {
		t.Errorf("url %s", d.url)
	}
	if !d.options.QUIC || d.options.InsecureConcurrency != 0 {
		t.Errorf("the second engine is not one QUIC connection: %+v", d.options)
	}
	if d.usable() {
		t.Error("datagrams before the app allowed them")
	}
}

func TestNekoDatagramHeaders(t *testing.T) {
	d := newDatagramClient(context.Background(), log.NewNOPFactory().Logger(),
		cronet.NaiveClientOptions{ServerAddress: M.ParseSocksaddrHostPort("10.0.0.1", 443),
			ExtraHeaders: map[string]string{"x-extra": "1", "niko-udp": "9"}},
		"node.example", "Basic dTpw")
	headers := d.headers()
	for key, want := range map[string]string{"proxy-authorization": "Basic dTpw", "-force-quic": "true", "x-extra": "1",
		"niko-udp": "1"} {
		if headers[key] != want {
			t.Errorf("%s: %q, want %q", key, headers[key], want)
		}
	}
	if len(headers["padding"]) < 30 {
		t.Errorf("padding %q", headers["padding"])
	}
	none := newDatagramClient(context.Background(), log.NewNOPFactory().Logger(),
		cronet.NaiveClientOptions{ServerAddress: M.ParseSocksaddrHostPort("10.0.0.1", 443)}, "node.example", "")
	if _, has := none.headers()["proxy-authorization"]; has {
		t.Error("an authorization header without a user")
	}
}

func TestNekoDatagramClosed(t *testing.T) {
	d := newDatagramClient(context.Background(), log.NewNOPFactory().Logger(),
		cronet.NaiveClientOptions{ServerAddress: M.ParseSocksaddrHostPort("10.0.0.1", 443)}, "node.example", "")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.start(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("an engine started after the outbound closed: %v", err)
	}
}

// A core without with_naive_datagram, or a libcronet without the datagram symbols (or none at all), keeps UDP over
// TCP: the engine is not started and new sockets stop asking for datagrams.
func TestNekoDatagramSupport(t *testing.T) {
	err := checkDatagramSupport()
	if err == nil {
		t.Skip("this build and its library can do datagrams")
	}
	d := newDatagramClient(context.Background(), log.NewNOPFactory().Logger(),
		cronet.NaiveClientOptions{ServerAddress: M.ParseSocksaddrHostPort("10.0.0.1", 443)}, "node.example", "")
	d.allowed.Store(true)
	if _, startErr := d.start(); startErr == nil || !d.unsupported.Load() || d.usable() {
		t.Errorf("without datagrams (%v): start %v, unsupported %v, usable %v", err, startErr, d.unsupported.Load(), d.usable())
	}
	if _, listenErr := d.listenPacket(context.Background()); listenErr == nil {
		t.Error("a socket opened without datagrams")
	}
}
