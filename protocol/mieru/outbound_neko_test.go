package mieru

import (
	"bufio"
	"context"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mieruserver "github.com/enfein/mieru/v3/apis/server"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

// listenFactory binds the server's port binding to an ephemeral port on 127.0.0.1.
type listenFactory struct{ bound chan net.Addr }

func (f *listenFactory) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err == nil {
		f.bound <- listener.Addr()
	}
	return listener, err
}

func (f *listenFactory) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err == nil {
		f.bound <- conn.LocalAddr()
	}
	return conn, err
}

// startServer runs mieru's own server API in process: a connect reports its destination,
// then echoes; a UDP associate echoes datagrams through the library's own UDP wrappers.
func startServer(t *testing.T, transport mierupb.TransportProtocol) uint16 {
	factory := &listenFactory{bound: make(chan net.Addr, 1)}
	server := mieruserver.NewServer()
	err := server.Store(&mieruserver.ServerConfig{
		Config: &mierupb.ServerConfig{
			PortBindings: []*mierupb.PortBinding{{Port: proto.Int32(8964), Protocol: transport.Enum()}},
			Users:        []*mierupb.User{{Name: proto.String("user"), Password: proto.String("secret")}},
		},
		StreamListenerFactory: factory,
		PacketListenerFactory: factory,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Stop() })
	port := M.SocksaddrFromNet(<-factory.bound).Port
	go func() {
		for {
			conn, request, err := server.Accept()
			if err != nil {
				if !server.IsRunning() {
					return
				}
				continue
			}
			go serve(conn, request)
		}
	}()
	return port
}

func serve(conn net.Conn, request *mierumodel.Request) {
	defer conn.Close()
	response := &mierumodel.Response{
		Reply:    mieruconstant.Socks5ReplySuccess,
		BindAddr: mierumodel.AddrSpec{IP: net.IPv4zero, Port: 0},
	}
	if err := response.WriteToSocks5(conn); err != nil {
		return
	}
	switch request.Command {
	case mieruconstant.Socks5ConnectCmd:
		conn.Write([]byte(request.DstAddr.String() + "\n"))
		io.Copy(conn, conn)
	case mieruconstant.Socks5UDPAssociateCmd:
		packetConn := mierucommon.NewUDPAssociateWrapper(mierucommon.NewPacketOverStreamTunnel(conn))
		buffer := make([]byte, 65535)
		for {
			n, addr, err := packetConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			if _, err = packetConn.WriteTo(append([]byte("echo "), buffer[:n]...), addr); err != nil {
				return
			}
		}
	}
}

func newTestOutbound(t *testing.T, options option.MieruOutboundOptions) *Outbound {
	outbound, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "mieru-test", options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { outbound.(*Outbound).Close() })
	return outbound.(*Outbound)
}

func checkTCP(t *testing.T, outbound *Outbound, destination string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(destination))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, 200000)
	rand.Read(payload)
	go conn.Write(payload)
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(line) != destination {
		t.Fatalf("server saw %q, want %q", line, destination)
	}
	echo := make([]byte, len(payload))
	if _, err = io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != string(payload) {
		t.Fatal("echo differs")
	}
}

func checkUDP(t *testing.T, outbound *Outbound) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	packetConn, err := outbound.ListenPacket(ctx, M.ParseSocksaddr("1.1.1.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	packetConn.SetDeadline(time.Now().Add(10 * time.Second))
	for _, target := range []string{"1.1.1.1:53", "[2001:db8::2]:5353", "8.8.8.8:443"} {
		if _, err = packetConn.WriteTo([]byte(target), M.ParseSocksaddr(target).UDPAddr()); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 2048)
		n, from, err := packetConn.ReadFrom(reply)
		if err != nil {
			t.Fatal(err)
		}
		if string(reply[:n]) != "echo "+target || M.SocksaddrFromNet(from).String() != target {
			t.Fatalf("udp echo %q from %v", reply[:n], from)
		}
	}
	conn, err := outbound.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr("9.9.9.9:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = conn.Write([]byte("bound")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2048)
	n, err := conn.Read(reply)
	if err != nil || string(reply[:n]) != "echo bound" {
		t.Fatalf("bound udp echo %q: %v", reply[:n], err)
	}
}

func TestNekoMieru(t *testing.T) {
	for _, test := range []struct {
		name      string
		transport mierupb.TransportProtocol
		options   option.MieruOutboundOptions
	}{
		{name: "tcp", transport: mierupb.TransportProtocol_TCP},
		{name: "tcp-mux-high", transport: mierupb.TransportProtocol_TCP, options: option.MieruOutboundOptions{Multiplexing: "high"}},
		{name: "tcp-mux-off-nowait", transport: mierupb.TransportProtocol_TCP, options: option.MieruOutboundOptions{Multiplexing: "MULTIPLEXING_OFF", HandshakeMode: "no_wait"}},
		{name: "udp", transport: mierupb.TransportProtocol_UDP, options: option.MieruOutboundOptions{Transport: "udp"}},
		{name: "udp-mtu-middle", transport: mierupb.TransportProtocol_UDP, options: option.MieruOutboundOptions{Transport: "UDP", MTU: 1300, Multiplexing: "middle"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			port := startServer(t, test.transport)
			options := test.options
			options.Server = "127.0.0.1"
			options.ServerPort = port
			options.Username = "user"
			options.Password = "secret"
			outbound := newTestOutbound(t, options)
			checkTCP(t, outbound, "example.com:443")
			checkTCP(t, outbound, "10.0.0.1:80")
			checkTCP(t, outbound, "[2001:db8::1]:8443")
			checkUDP(t, outbound)
		})
	}
}

// A port range in server_ports alone reaches the server (a range of one port here).
func TestNekoMieruPortRange(t *testing.T) {
	port := startServer(t, mierupb.TransportProtocol_TCP)
	portString := strconv.Itoa(int(port))
	outbound := newTestOutbound(t, option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1"},
		ServerPorts:   []string{portString + ":" + portString},
		Username:      "user",
		Password:      "secret",
	})
	checkTCP(t, outbound, "example.org:80")
}

// A wrong password, or no server listening, fails the dial within its context.
func TestNekoMieruFailures(t *testing.T) {
	port := startServer(t, mierupb.TransportProtocol_TCP)
	wrong := newTestOutbound(t, option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		Username:      "user",
		Password:      "wrong",
	})
	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := M.SocksaddrFromNet(closedListener.Addr()).Port
	closedListener.Close()
	closed := newTestOutbound(t, option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: closedPort},
		Username:      "user",
		Password:      "secret",
	})
	for name, outbound := range map[string]*Outbound{"wrong password": wrong, "closed port": closed} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		conn, err := outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
		if err == nil {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			conn.Write([]byte("x"))
			_, err = conn.Read(make([]byte, 64))
			conn.Close()
		}
		cancel()
		if err == nil {
			t.Fatalf("%s: got through", name)
		}
		if time.Since(start) > 8*time.Second {
			t.Fatalf("%s: took %v", name, time.Since(start))
		}
	}
	// closed outbound refuses
	closed.Close()
	if _, err = closed.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:80")); err == nil {
		t.Fatal("dial after close")
	}
}

func TestNekoMieruOptions(t *testing.T) {
	good := option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "mieru.example.com", ServerPort: 443},
		ServerPorts:   []string{"2000-2010", "3000:3005", "4000"},
		Transport:     "tcp",
		Username:      "u",
		Password:      "p",
		Multiplexing:  "low",
		HandshakeMode: "standard",
	}
	profile, err := BuildProfile("tag", good)
	if err != nil {
		t.Fatal(err)
	}
	server := profile.GetServers()[0]
	if server.GetDomainName() != "mieru.example.com" || len(server.GetPortBindings()) != 4 ||
		server.GetPortBindings()[1].GetPortRange() != "2000-2010" || server.GetPortBindings()[2].GetPortRange() != "3000-3005" ||
		server.GetPortBindings()[3].GetPort() != 4000 || profile.GetMultiplexing().GetLevel() != mierupb.MultiplexingLevel_MULTIPLEXING_LOW ||
		profile.GetHandshakeMode() != mierupb.HandshakeMode_HANDSHAKE_STANDARD {
		t.Fatalf("profile %v", profile)
	}
	// no DNS services in this context: an IP server from here on
	good.Server = "192.0.2.1"
	if _, err = NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "ok", good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*option.MieruOutboundOptions){
		"no server":         func(o *option.MieruOutboundOptions) { o.Server = "" },
		"no port":           func(o *option.MieruOutboundOptions) { o.ServerPort = 0; o.ServerPorts = nil },
		"no user":           func(o *option.MieruOutboundOptions) { o.Username = "" },
		"bad transport":     func(o *option.MieruOutboundOptions) { o.Transport = "quic" },
		"bad multiplexing":  func(o *option.MieruOutboundOptions) { o.Multiplexing = "max" },
		"bad handshake":     func(o *option.MieruOutboundOptions) { o.HandshakeMode = "later" },
		"bad range":         func(o *option.MieruOutboundOptions) { o.ServerPorts = []string{"3000-2000"} },
		"bad port":          func(o *option.MieruOutboundOptions) { o.ServerPorts = []string{"70000"} },
		"bad mtu":           func(o *option.MieruOutboundOptions) { o.Transport = "udp"; o.MTU = 9000 },
		"bad pattern":       func(o *option.MieruOutboundOptions) { o.TrafficPattern = "!!" },
		"long password":     func(o *option.MieruOutboundOptions) { o.Password = strings.Repeat("p", 65) },
		"unknown transport": func(o *option.MieruOutboundOptions) { o.Transport = "sctp" },
	} {
		options := good
		mutate(&options)
		if _, err = NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "bad", options); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
