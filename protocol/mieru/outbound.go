package mieru

// neko: a mieru client through github.com/enfein/mieru/v3's client API, the way
// mihomo's adapter/outbound/mieru.go drives it, reaching the server through
// sing-box's dialer (detour, bind, domain resolver).

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mierutp "github.com/enfein/mieru/v3/apis/trafficpattern"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MieruOutboundOptions](registry, C.TypeMieru, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	client mieruclient.Client
	access sync.Mutex
	closed bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MieruOutboundOptions) (adapter.Outbound, error) {
	profile, err := BuildProfile(tag, options)
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	var queryOptions adapter.DNSQueryOptions
	if resolveDialer, isResolveDialer := outboundDialer.(dialer.ResolveDialer); isResolveDialer {
		queryOptions = resolveDialer.QueryOptions()
	}
	client := mieruclient.NewClient()
	err = client.Store(&mieruclient.ClientConfig{
		Profile:      profile,
		Dialer:       streamDialer{outboundDialer},
		PacketDialer: packetDialer{outboundDialer},
		// only the UDP transport asks: TCP hands the server's name to the dialer as it is
		Resolver: &dnsResolver{
			router:       service.FromContext[adapter.DNSRouter](ctx),
			queryOptions: queryOptions,
		},
		DNSConfig: &mierucommon.ClientDNSConfig{BypassDialerDNS: true},
	})
	if err != nil {
		return nil, E.Cause(err, "mieru")
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeMieru, tag, options.Network.Build(), options.DialerOptions),
		logger:  logger,
		client:  client,
	}, nil
}

// BuildProfile turns the options into mieru's client profile, as a mierus:// link would.
func BuildProfile(name string, options option.MieruOutboundOptions) (*mierupb.ClientProfile, error) {
	if options.Server == "" {
		return nil, E.New("mieru: missing server")
	}
	if options.Username == "" || options.Password == "" {
		return nil, E.New("mieru: missing username or password")
	}
	if name == "" {
		name = "mieru"
	}
	var transport mierupb.TransportProtocol
	switch strings.ToLower(options.Transport) {
	case "", "tcp":
		transport = mierupb.TransportProtocol_TCP
	case "udp":
		transport = mierupb.TransportProtocol_UDP
	default:
		return nil, E.New("mieru: unknown transport ", options.Transport, " (tcp or udp)")
	}
	server := &mierupb.ServerEndpoint{}
	if address, err := netip.ParseAddr(options.Server); err == nil {
		server.IpAddress = proto.String(address.Unmap().String())
	} else {
		server.DomainName = proto.String(options.Server)
	}
	if options.ServerPort != 0 {
		server.PortBindings = append(server.PortBindings, &mierupb.PortBinding{
			Port:     proto.Int32(int32(options.ServerPort)),
			Protocol: transport.Enum(),
		})
	}
	for _, ports := range options.ServerPorts {
		binding := &mierupb.PortBinding{Protocol: transport.Enum()}
		begin, end, isRange := strings.Cut(strings.ReplaceAll(ports, ":", "-"), "-")
		beginPort, err := parsePort(begin)
		if err != nil {
			return nil, E.Cause(err, "mieru: server_ports ", ports)
		}
		if isRange {
			endPort, err := parsePort(end)
			if err != nil {
				return nil, E.Cause(err, "mieru: server_ports ", ports)
			}
			if beginPort > endPort {
				return nil, E.New("mieru: server_ports ", ports, ": begin after end")
			}
			binding.PortRange = proto.String(strconv.Itoa(beginPort) + "-" + strconv.Itoa(endPort))
		} else {
			binding.Port = proto.Int32(int32(beginPort))
		}
		server.PortBindings = append(server.PortBindings, binding)
	}
	if len(server.PortBindings) == 0 {
		return nil, E.New("mieru: missing server_port or server_ports")
	}
	profile := &mierupb.ClientProfile{
		ProfileName: proto.String(name),
		User: &mierupb.User{
			Name:     proto.String(options.Username),
			Password: proto.String(options.Password),
		},
		Servers: []*mierupb.ServerEndpoint{server},
	}
	if options.Multiplexing != "" {
		level, loaded := mierupb.MultiplexingLevel_value[enumName("MULTIPLEXING_", options.Multiplexing)]
		if !loaded {
			return nil, E.New("mieru: unknown multiplexing ", options.Multiplexing, " (off, low, middle or high)")
		}
		profile.Multiplexing = &mierupb.MultiplexingConfig{Level: mierupb.MultiplexingLevel(level).Enum()}
	}
	if options.HandshakeMode != "" {
		mode, loaded := mierupb.HandshakeMode_value[enumName("HANDSHAKE_", options.HandshakeMode)]
		if !loaded {
			return nil, E.New("mieru: unknown handshake_mode ", options.HandshakeMode, " (standard or no_wait)")
		}
		profile.HandshakeMode = mierupb.HandshakeMode(mode).Enum()
	}
	if options.TrafficPattern != "" {
		pattern, err := mierutp.Decode(options.TrafficPattern)
		if err != nil {
			return nil, E.Cause(err, "mieru: traffic_pattern")
		}
		profile.TrafficPattern = pattern
	}
	if options.MTU != 0 {
		profile.Mtu = proto.Int32(int32(options.MTU))
	}
	return profile, nil
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || port < 1 || port > 65535 {
		return 0, E.New("bad port ", s)
	}
	return port, nil
}

// enumName: "no_wait" or "HANDSHAKE_NO_WAIT" -> "HANDSHAKE_NO_WAIT"
func enumName(prefix string, value string) string {
	value = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
	if strings.HasPrefix(value, prefix) {
		return value
	}
	return prefix + value
}

func (h *Outbound) start() error {
	h.access.Lock()
	defer h.access.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	if h.client.IsRunning() {
		return nil
	}
	return h.client.Start()
}

func (h *Outbound) dial(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	err := h.start()
	if err != nil {
		return nil, err
	}
	address := mierumodel.NetAddrSpec{Net: network, AddrSpec: mierumodel.AddrSpec{Port: int(destination.Port)}}
	if destination.IsFqdn() {
		address.FQDN = destination.Fqdn
	} else {
		address.IP = destination.Addr.Unmap().AsSlice()
	}
	// the library's handshake does not watch ctx: give up on it, and close what it gives later
	type dialResult struct {
		conn net.Conn
		err  error
	}
	done := make(chan dialResult, 1)
	go func() {
		conn, err := h.client.DialContext(ctx, address)
		done <- dialResult{conn, err}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			return nil, E.Cause(result.err, "mieru: dial ", destination)
		}
		return result.conn, nil
	case <-ctx.Done():
		go func() {
			if result := <-done; result.conn != nil {
				result.conn.Close()
			}
		}()
		return nil, E.Cause(ctx.Err(), "mieru: dial ", destination)
	}
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.dial(ctx, N.NetworkTCP, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		packetConn, err := h.listenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.listenPacket(ctx, destination)
}

// listenPacket: a socks5 UDP associate on a mieru stream, every packet a socks5 UDP datagram
// framed as mieru's PacketOverStreamTunnel does (0x00, length, datagram, 0xff).
func (h *Outbound) listenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := h.dial(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return &packetConn{Conn: conn}, nil
}

func (h *Outbound) Close() error {
	h.access.Lock()
	defer h.access.Unlock()
	h.closed = true
	if h.client.IsRunning() {
		return h.client.Stop()
	}
	return nil
}

type streamDialer struct {
	dialer N.Dialer
}

func (d streamDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
}

type packetDialer struct {
	dialer N.Dialer
}

func (d packetDialer) ListenPacket(ctx context.Context, network string, laddr string, raddr string) (net.PacketConn, error) {
	return d.dialer.ListenPacket(ctx, M.ParseSocksaddr(raddr))
}

type dnsResolver struct {
	router       adapter.DNSRouter
	queryOptions adapter.DNSQueryOptions
}

func (r *dnsResolver) LookupIP(ctx context.Context, network string, host string) ([]net.IP, error) {
	if r.router == nil {
		return nil, E.New("mieru: no DNS router to resolve ", host)
	}
	addresses, err := r.router.Lookup(ctx, host, r.queryOptions)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, address := range addresses {
		address = address.Unmap()
		if network == "ip4" && !address.Is4() || network == "ip6" && !address.Is6() {
			continue
		}
		ips = append(ips, address.AsSlice())
	}
	return ips, nil
}

type packetConn struct {
	net.Conn
	readAccess  sync.Mutex
	writeAccess sync.Mutex
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	var header [3]byte
	_, err := io.ReadFull(c.Conn, header[:])
	if err != nil {
		return 0, nil, err
	}
	if header[0] != 0x00 {
		return 0, nil, E.New("mieru: bad packet prefix ", header[0])
	}
	datagram := make([]byte, int(binary.BigEndian.Uint16(header[1:]))+1)
	_, err = io.ReadFull(c.Conn, datagram)
	if err != nil {
		return 0, nil, err
	}
	if datagram[len(datagram)-1] != 0xff {
		return 0, nil, E.New("mieru: bad packet suffix")
	}
	datagram = datagram[:len(datagram)-1]
	if len(datagram) < 4 || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0 {
		return 0, nil, E.New("mieru: bad UDP associate header")
	}
	reader := bytes.NewReader(datagram[3:])
	source, err := M.SocksaddrSerializer.ReadAddrPort(reader)
	if err != nil {
		return 0, nil, E.Cause(err, "mieru: read UDP associate header")
	}
	n, _ := reader.Read(p)
	if source.IsFqdn() {
		return n, source, nil
	}
	return n, source.UDPAddr(), nil
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	length := 3 + M.SocksaddrSerializer.AddrPortLen(destination) + len(p)
	if length > 65535 {
		return 0, E.New("mieru: packet too large")
	}
	var packet bytes.Buffer
	packet.Grow(length + 4)
	packet.WriteByte(0x00)
	packet.Write(binary.BigEndian.AppendUint16(nil, uint16(length)))
	packet.Write([]byte{0, 0, 0})
	err := M.SocksaddrSerializer.WriteAddrPort(&packet, destination)
	if err != nil {
		return 0, err
	}
	packet.Write(p)
	packet.WriteByte(0xff)
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	_, err = c.Conn.Write(packet.Bytes())
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *packetConn) Write(p []byte) (int, error) {
	return 0, E.New("mieru: write without a destination")
}

func (c *packetConn) Upstream() any {
	return c.Conn
}
