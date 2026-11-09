//go:build with_yggdrasil

// Package yggdrasil is an endpoint on the Yggdrasil mesh network (neko): the
// yggdrasil-go core (vendored in third_party, LGPLv3 with its linking exception)
// peers through sing-box dialers, and the WireGuard gVisor stack carries TCP and
// UDP to and from the node's 200::/7 address.
package yggdrasil

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.YggdrasilEndpointOptions](registry, C.TypeYggdrasil, NewEndpoint)
}

var _ adapter.Endpoint = (*Endpoint)(nil)

var (
	// the whole Yggdrasil address space
	yggdrasilPrefix = netip.MustParsePrefix("200::/7")
	localHost       = netip.AddrFrom4([4]byte{127, 0, 0, 1})
)

type Endpoint struct {
	endpoint.Adapter
	ctx       context.Context
	router    adapter.Router
	logger    logger.ContextLogger
	core      *core.Core
	rwc       *ipv6rwc.ReadWriteCloser
	device    wireguard.Device
	address   netip.Addr
	started   atomic.Bool
	closed    chan struct{}
	dnsRouter adapter.DNSRouter
	peers     []*url.URL
	// inboundListed: only packets from inboundSources reach the stack, and the answers to what this node dialled
	// ([dialed]: netip.Addr → struct{}), never a new flow from those (neko)
	inboundListed  bool
	inboundSources []netip.Prefix
	dialedAccess   sync.RWMutex
	dialed         map[netip.Addr]time.Time
}

const (
	// an address this node dialled: its answers come in for this long after the last packet this node sent it (a
	// connection that runs for hours keeps it), and at most this many at once (neko)
	dialedFor = 10 * time.Minute
	dialedMax = 4096
)

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.YggdrasilEndpointOptions) (adapter.Endpoint, error) {
	privateKey, err := parsePrivateKey(options.PrivateKey)
	if err != nil {
		return nil, err
	}
	certificate, err := selfSignedCertificate(privateKey)
	if err != nil {
		return nil, E.Cause(err, "create the node certificate")
	}
	peerDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: true,
	})
	if err != nil {
		return nil, err
	}
	tlsClient, err := linkTLSClient(options.TLSFingerprint)
	if err != nil {
		return nil, err
	}
	setup := []core.SetupOption{
		// before the peers: their links dial through it
		core.LinkDialer{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return peerDialer.DialContext(ctx, network, M.ParseSocksaddr(address))
			},
			ListenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
				return peerDialer.ListenPacket(ctx, M.ParseSocksaddr(address))
			},
			TLSClient: tlsClient,
		},
		core.NodeInfoPrivacy(options.NodeInfoPrivacy),
		core.DebugPrivacy(options.DebugPrivacy),
	}
	if len(options.NodeInfo) > 0 {
		setup = append(setup, core.NodeInfo(options.NodeInfo))
	}
	for _, rawKey := range options.AllowedPublicKeys {
		key, err := hex.DecodeString(rawKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, E.New("invalid allowed public key: ", rawKey)
		}
		setup = append(setup, core.AllowedPublicKey(key))
	}
	for _, listen := range options.Listen {
		setup = append(setup, core.ListenAddress(listen))
	}
	// peers are added in Start: the core dials them at once, and resolving a peer name
	// needs the DNS router, which is not running yet here
	peers := make([]*url.URL, 0, len(options.Peers))
	for _, peer := range options.Peers {
		peerURL, err := parsePeer(peer)
		if err != nil {
			return nil, err
		}
		peers = append(peers, peerURL)
	}
	yggCore, err := core.New(certificate, &coreLogger{logger}, setup...)
	if err != nil {
		return nil, E.Cause(err, "start the Yggdrasil core")
	}
	address, _ := netip.AddrFromSlice(yggCore.Address())
	rwc := ipv6rwc.NewReadWriteCloser(yggCore)
	ep := &Endpoint{
		Adapter:   endpoint.NewAdapterWithDialerOptions(C.TypeYggdrasil, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:       ctx,
		router:    router,
		logger:    logger,
		core:      yggCore,
		rwc:       rwc,
		address:   address,
		closed:    make(chan struct{}),
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		peers:     peers,
	}
	ep.inboundListed = options.InboundListed
	ep.inboundSources = options.InboundSources
	udpTimeout := time.Duration(options.UDPTimeout)
	if udpTimeout == 0 {
		udpTimeout = C.UDPTimeout
	}
	ep.device, err = wireguard.NewDevice(wireguard.DeviceOptions{
		Context:        ctx,
		Logger:         logger,
		Handler:        ep,
		UDPTimeout:     udpTimeout,
		ICMPTimeout:    C.ICMPTimeout,
		MTU:            uint32(rwc.MTU()),
		Address:        []netip.Prefix{netip.PrefixFrom(address, 128)},
		AllowedAddress: []netip.Prefix{yggdrasilPrefix},
	})
	if err != nil {
		yggCore.Stop()
		return nil, E.Cause(err, "create the network stack")
	}
	logger.Info("Yggdrasil address ", address, ", public key ", hex.EncodeToString(yggCore.PublicKey()))
	return ep, nil
}

// parsePrivateKey reads the 64-byte ed25519 key yggdrasil-go keeps in its config, or a 32-byte seed.
func parsePrivateKey(raw string) (ed25519.PrivateKey, error) {
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, E.New("private key is not hex")
	}
	switch len(key) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(key), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(key), nil
	default:
		return nil, E.New("private key must be 64 bytes (128 hex digits) or a 32-byte seed")
	}
}

// selfSignedCertificate is the node's TLS identity, as yggdrasil-go makes it from its key.
func selfSignedCertificate(privateKey ed25519.PrivateKey) (*tls.Certificate, error) {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hex.EncodeToString(publicKey)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, nil
}

func (e *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := e.device.Start(); err != nil {
		return err
	}
	scope.Add(e.Close)
	go e.pumpOut()
	go e.pumpIn()
	e.started.Store(true)
	for _, peer := range e.peers {
		err := e.core.AddPeer(peer, "")
		if err != nil && !errors.Is(err, core.ErrLinkAlreadyConfigured) {
			return E.Cause(err, "add peer ", peer.Redacted())
		}
	}
	return nil
}

// parsePeer checks a peer URI before the start, where the core would only refuse it later.
func parsePeer(raw string) (*url.URL, error) {
	peerURL, err := url.Parse(raw)
	if err != nil {
		return nil, E.Cause(err, "parse peer ", raw)
	}
	switch peerURL.Scheme {
	case "tcp", "tls", "quic", "ws", "wss", "socks", "sockstls":
	default:
		return nil, E.New("peer ", raw, ": unsupported scheme ", peerURL.Scheme)
	}
	if peerURL.Host == "" {
		return nil, E.New("peer ", raw, ": missing host:port")
	}
	for _, key := range peerURL.Query()["key"] {
		if decoded, err := hex.DecodeString(key); err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, E.New("peer ", raw, ": key must be 64 hex digits")
		}
	}
	return peerURL, nil
}

// pumpOut moves the stack's outgoing packets into the mesh.
func (e *Endpoint) pumpOut() {
	mtu := e.rwc.MTU()
	bufs := [][]byte{make([]byte, mtu)}
	sizes := make([]int, 1)
	for {
		count, err := e.device.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		if count == 0 {
			continue
		}
		e.sending(bufs[0][:sizes[0]])
		if _, err = e.rwc.Write(bufs[0][:sizes[0]]); err != nil {
			select {
			case <-e.closed:
				return
			default:
			}
		}
	}
}

// pumpIn hands packets from the mesh to the stack. One buffer for all of them (neko): the device takes a packet
// before Write returns (gVisor's stack copies it into its own buffer, a system tun writes it out), so a copy per
// packet would only cost the allocation.
func (e *Endpoint) pumpIn() {
	buf := make([]byte, e.rwc.MTU())
	packets := [][]byte{nil}
	for {
		n, err := e.rwc.Read(buf)
		if err != nil {
			return
		}
		if !e.admits(buf[:n]) {
			continue
		}
		packets[0] = buf[:n]
		if _, err = e.device.Write(packets, 0); err != nil {
			e.logger.Debug("yggdrasil: deliver: ", err)
		}
	}
}

// Peers is the state of the node's peer links (neko): the configured peers with whether each is up, its latency and
// its last error, and the inbound ones. A client checks public peers with a node of its own before it takes them.
func (e *Endpoint) Peers() []core.PeerInfo {
	return e.core.GetPeers()
}

func (e *Endpoint) Close() error {
	select {
	case <-e.closed:
		return nil
	default:
		close(e.closed)
	}
	e.started.Store(false)
	e.core.Stop()
	e.rwc.Close()
	return e.device.Close()
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !e.started.Load() {
		return nil, E.New("Yggdrasil is not ready yet")
	}
	if destination.IsDomain() {
		addresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv6Only})
		if err != nil {
			return nil, err
		}
		e.noteDialed(addresses...)
		return N.DialSerial(ctx, e.device, network, destination, addresses)
	}
	if !yggdrasilPrefix.Contains(destination.Addr) {
		return nil, E.New("yggdrasil: ", destination.Addr, " is not a Yggdrasil address (200::/7)")
	}
	e.logger.InfoContext(ctx, "outbound connection to ", destination)
	e.noteDialed(destination.Addr)
	return e.device.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !e.started.Load() {
		return nil, E.New("Yggdrasil is not ready yet")
	}
	e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsIP() {
		e.noteDialed(destination.Addr)
	}
	return e.device.ListenPacket(ctx, destination)
}

// noteDialed keeps the addresses this node dials: with inbound_sources their answers still come in (neko).
func (e *Endpoint) noteDialed(addresses ...netip.Addr) {
	if !e.inboundListed {
		return
	}
	now := time.Now()
	e.dialedAccess.Lock()
	defer e.dialedAccess.Unlock()
	if e.dialed == nil {
		e.dialed = make(map[netip.Addr]time.Time)
	}
	if len(e.dialed)+len(addresses) > dialedMax {
		for address, at := range e.dialed {
			if now.Sub(at) > dialedFor {
				delete(e.dialed, address)
			}
		}
	}
	for _, address := range addresses {
		address = address.Unmap()
		if _, ok := e.dialed[address]; !ok && len(e.dialed) >= dialedMax {
			// full of addresses dialled within dialedFor: the one longest quiet goes, the new dial is answered
			var oldest netip.Addr
			var oldestAt time.Time
			for a, at := range e.dialed {
				if !oldest.IsValid() || at.Before(oldestAt) {
					oldest, oldestAt = a, at
				}
			}
			delete(e.dialed, oldest)
		}
		e.dialed[address] = now
	}
}

// answering: an address this node dialled within dialedFor.
func (e *Endpoint) answering(address netip.Addr) bool {
	e.dialedAccess.RLock()
	defer e.dialedAccess.RUnlock()
	at, ok := e.dialed[address]
	return ok && time.Since(at) <= dialedFor
}

// sending renews a dialled address this node sends a packet to, at most once a minute: what it still talks to
// stays answered (neko).
func (e *Endpoint) sending(packet []byte) {
	if !e.inboundListed || len(packet) < 40 || packet[0]>>4 != 6 {
		return
	}
	destination := netip.AddrFrom16([16]byte(packet[24:40]))
	now := time.Now()
	e.dialedAccess.RLock()
	at, ok := e.dialed[destination]
	e.dialedAccess.RUnlock()
	if !ok || now.Sub(at) < time.Minute {
		return
	}
	e.dialedAccess.Lock()
	if _, ok = e.dialed[destination]; ok {
		e.dialed[destination] = now
	}
	e.dialedAccess.Unlock()
}

// listed: inbound_sources has the address.
func (e *Endpoint) listed(address netip.Addr) bool {
	return slices.ContainsFunc(e.inboundSources, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
}

// admits a packet from the mesh to the stack (neko): with inbound_sources, only from a listed address or one this
// node dialled. Any other sender gets no answer at all, not to a SYN (JudgeFlow), nor to a segment of no connection
// (the stack's reset) or an echo request, also at the node's /64.
func (e *Endpoint) admits(packet []byte) bool {
	if !e.inboundListed {
		return true
	}
	if len(packet) < 40 || packet[0]>>4 != 6 {
		return false
	}
	source := netip.AddrFrom16([16]byte(packet[8:24]))
	if e.listed(source) {
		return true
	}
	return e.answering(source)
}

// tun.Handler: connections from the mesh to this node's address

func (e *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	// from an address not listed, to any address of this node, the one this node dialled too: no answer at all,
	// not even a reset (neko)
	if e.inboundListed && !e.listed(source.Addr()) {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	if destination.Addr() != e.address {
		return tun.FlowVerdict{Action: tun.ActionReject}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

func (e *Endpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
}

func (e *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	// a connection to this node is a connection to the local host; IPv4 loopback, where
	// local services listen far more often than on ::1
	metadata.OriginDestination = destination
	metadata.Destination = M.SocksaddrFrom(localHost, destination.Port)
	e.logger.InfoContext(ctx, "inbound connection from ", source, " to port ", destination.Port)
	e.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	metadata.OriginDestination = destination
	metadata.Destination = M.SocksaddrFrom(localHost, destination.Port)
	conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
	e.logger.InfoContext(ctx, "inbound packet connection from ", source, " to port ", destination.Port)
	e.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// coreLogger hands the core's log lines to sing-box.
type coreLogger struct{ logger.ContextLogger }

func (l *coreLogger) Printf(format string, args ...any) { l.Info(fmt.Sprintf(format, args...)) }
func (l *coreLogger) Println(args ...any)               { l.Info(fmt.Sprint(args...)) }
func (l *coreLogger) Infof(format string, args ...any)  { l.Info(fmt.Sprintf(format, args...)) }
func (l *coreLogger) Infoln(args ...any)                { l.Info(fmt.Sprint(args...)) }
func (l *coreLogger) Warnf(format string, args ...any)  { l.Warn(fmt.Sprintf(format, args...)) }
func (l *coreLogger) Warnln(args ...any)                { l.Warn(fmt.Sprint(args...)) }
func (l *coreLogger) Errorf(format string, args ...any) { l.Error(fmt.Sprintf(format, args...)) }
func (l *coreLogger) Errorln(args ...any)               { l.Error(fmt.Sprint(args...)) }
func (l *coreLogger) Debugf(format string, args ...any) { l.Debug(fmt.Sprintf(format, args...)) }
func (l *coreLogger) Debugln(args ...any)               { l.Debug(fmt.Sprint(args...)) }
func (l *coreLogger) Traceln(args ...any)               { l.Trace(fmt.Sprint(args...)) }
