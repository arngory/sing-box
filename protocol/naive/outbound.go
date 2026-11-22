//go:build with_naive_outbound

package naive

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/sagernet/cronet-go"
	_ "github.com/sagernet/cronet-go/all"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/certificate"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/nikoicmp"
	"github.com/sagernet/sing-box/common/udpdesync"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	mDNS "github.com/miekg/dns"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.NaiveOutboundOptions](registry, C.TypeNaive, NewOutbound)
}

var _ adapter.OutboundWithMultiplex = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	logger    logger.ContextLogger
	client    *cronet.NaiveClient
	uotClient *uot.Client
	// neko: icmp-v1, nil without the icmp option
	icmp *nikoicmp.Port
	// neko: a TCP dial waits for the proxy's answer (the await_dial option)
	awaitDial bool
	// neko: UDP as HTTP/3 datagrams (the udp_datagram option), nil without it
	datagram *datagramClient
}

var _ adapter.FlowOutbound = (*Outbound)(nil)

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.TLS.DisableSNI {
		return nil, E.New("disable_sni is not supported on naive outbound")
	}
	if options.TLS.Insecure {
		return nil, E.New("insecure is not supported on naive outbound")
	}
	if len(options.TLS.ALPN) > 0 {
		return nil, E.New("alpn is not supported on naive outbound")
	}
	if options.TLS.MinVersion != "" {
		return nil, E.New("min_version is not supported on naive outbound")
	}
	if options.TLS.MaxVersion != "" {
		return nil, E.New("max_version is not supported on naive outbound")
	}
	if len(options.TLS.CipherSuites) > 0 {
		return nil, E.New("cipher_suites is not supported on naive outbound")
	}
	if len(options.TLS.CurvePreferences) > 0 {
		return nil, E.New("curve_preferences is not supported on naive outbound")
	}
	if len(options.TLS.ClientCertificate) > 0 || options.TLS.ClientCertificatePath != "" {
		return nil, E.New("client_certificate is not supported on naive outbound")
	}
	if len(options.TLS.ClientKey) > 0 || options.TLS.ClientKeyPath != "" {
		return nil, E.New("client_key is not supported on naive outbound")
	}
	if options.TLS.Fragment || options.TLS.RecordFragment {
		return nil, E.New("fragment is not supported on naive outbound")
	}
	if options.TLS.KernelTx || options.TLS.KernelRx {
		return nil, E.New("kernel TLS is not supported on naive outbound")
	}
	if options.TLS.UTLS != nil && options.TLS.UTLS.Enabled {
		return nil, E.New("uTLS is not supported on naive outbound")
	}
	if options.TLS.Reality != nil && options.TLS.Reality.Enabled {
		return nil, E.New("reality is not supported on naive outbound")
	}

	serverAddress := options.ServerOptions.Build()

	var serverName string
	if options.TLS.ServerName != "" {
		serverName = options.TLS.ServerName
	} else {
		serverName = serverAddress.AddrString()
	}

	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   true,
		ResolverOnDetour: true,
		NewDialer:        true,
	})
	if err != nil {
		return nil, err
	}

	// neko: the first datagrams of the outbound's QUIC connections (option.NaiveOutboundOptions.UDPDesync). The
	// resolver above keeps the dialer as it is: only what Chromium opens towards the server is shaped
	desyncOptions, err := udpdesync.OptionsFrom(options.UDPDesync)
	if err != nil {
		return nil, err
	}
	if desyncOptions.Enabled() && !options.QUIC && !options.UDPDatagram {
		// as Hysteria2 does for what cannot apply: said and left out, the profile still connects
		logger.Warn("udp_desync: no QUIC connection without quic or udp_datagram, ignored")
		desyncOptions = udpdesync.Options{}
	}
	// neko: names-v1, the node's name to the knock as it is (nodeDialer), not looked up before it
	cronetDialer := udpdesync.WrapSocketDialer(newNodeDialer(ctx, outboundDialer, options.Detour, serverAddress), desyncOptions, logger)

	var trustedRootCertificates string
	if len(options.TLS.Certificate) > 0 {
		trustedRootCertificates = strings.Join(options.TLS.Certificate, "\n")
	} else if options.TLS.CertificatePath != "" {
		content, err := filemanager.ReadFile(ctx, options.TLS.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		trustedRootCertificates = string(content)
	}

	// neko: Chromium is held to the list of the core's certificate store besides its own verification
	// (certificate.StorePublicKeyHashes): it verifies as it does, and a key of that list has to be in the chain: of
	// a root, or of an intermediate Chromium ends a chain at (an anchor of the library's store under a root of the
	// list, libraryAnchors).
	// Under "chrome" that is Chrome's list as the rest of the core takes it (Chromium's own store has roots the
	// core's list leaves out), under "mozilla" what the two lists share; under the system's store, nothing.
	// Only where nothing of the profile's own decides already: its pins are stricter and stay alone (a root's key
	// beside them would let any root of the list pass for the pinned leaf), its own certificate takes the place of
	// every list and is in none, and Chromium pins a name, never an address
	publicKeyPins := [][]byte(options.TLS.CertificatePublicKeySHA256)
	if _, addressErr := netip.ParseAddr(serverName); len(publicKeyPins) == 0 && trustedRootCertificates == "" && addressErr != nil {
		if store, isStore := service.FromContext[adapter.CertificateStore](ctx).(interface{ StoreKind() string }); isStore {
			publicKeyPins = certificate.StorePublicKeyHashes(store.StoreKind(), libraryAnchors())
			if len(publicKeyPins) > 0 {
				// said once per outbound: a server Chromium would take and this refuses is refused here
				logger.Info("the server's chain is held to the ", store.StoreKind(), " list besides Chromium's own (",
					len(publicKeyPins), " keys: its roots, and the intermediate anchors under them of the library's store ",
					cronet.ChromeRootStoreVersion, ")")
			}
		}
	}

	extraHeaders := make(map[string]string)
	for key, values := range options.ExtraHeaders.Build() {
		if len(values) > 0 {
			extraHeaders[key] = values[0]
		}
	}
	if options.AwaitDial {
		// asks the server to answer a CONNECT after its dial, not before (neko)
		extraHeaders[ackHeader] = "1"
	}

	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	// neko: names-v1, the node's name resolved as the knock outbound Chromium dials through resolves it (protocol/
	// knock/names.go): once per attempt, and only to the node's own addresses
	nodeAnswer := nodeResolverFor(ctx, options.Detour, serverAddress)
	var dnsResolver cronet.DNSResolverFunc
	if dnsRouter != nil {
		dnsResolver = func(dnsContext context.Context, request *mDNS.Msg) *mDNS.Msg {
			if response := nodeAnswer(dnsContext, request); response != nil {
				return response
			}
			response, err := dnsRouter.Exchange(dnsContext, request, outboundDialer.(dialer.ResolveDialer).QueryOptions())
			if err != nil {
				logger.Error("DNS exchange failed: ", err)
				return dns.FixedResponseStatus(request, mDNS.RcodeServerFailure)
			}
			return response
		}
	}

	var echEnabled bool
	var echConfigList []byte
	var echQueryServerName string
	if options.TLS.ECH != nil && options.TLS.ECH.Enabled {
		echEnabled = true
		echQueryServerName = options.TLS.ECH.QueryServerName
		var echConfig []byte
		if len(options.TLS.ECH.Config) > 0 {
			echConfig = []byte(strings.Join(options.TLS.ECH.Config, "\n"))
		} else if options.TLS.ECH.ConfigPath != "" {
			content, err := filemanager.ReadFile(ctx, options.TLS.ECH.ConfigPath)
			if err != nil {
				return nil, E.Cause(err, "read ECH config")
			}
			echConfig = content
		}
		if len(echConfig) > 0 {
			block, rest := pem.Decode(echConfig)
			if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
				return nil, E.New("invalid ECH configs pem")
			}
			echConfigList = block.Bytes
		}
	}
	var quicCongestionControl cronet.QUICCongestionControl
	switch options.QUICCongestionControl {
	case "":
		quicCongestionControl = cronet.QUICCongestionControlDefault
	case "bbr":
		quicCongestionControl = cronet.QUICCongestionControlBBR
	case "bbr2":
		quicCongestionControl = cronet.QUICCongestionControlBBRv2
	case "cubic":
		quicCongestionControl = cronet.QUICCongestionControlCubic
	case "reno":
		quicCongestionControl = cronet.QUICCongestionControlReno
	default:
		return nil, E.New("unknown quic congestion control: ", options.QUICCongestionControl)
	}
	clientOptions := cronet.NaiveClientOptions{
		Context:                  ctx,
		Logger:                   logger,
		ServerAddress:            serverAddress,
		ServerName:               serverName,
		Username:                 options.Username,
		Password:                 options.Password,
		InsecureConcurrency:      options.InsecureConcurrency,
		ExtraHeaders:             extraHeaders,
		ReceiveWindow:            options.ReceiveWindow.Value(),
		TrustedRootCertificates:  trustedRootCertificates,
		Dialer:                   cronetDialer,
		DNSResolver:              dnsResolver,
		ECHEnabled:               echEnabled,
		ECHConfigList:            echConfigList,
		ECHQueryServerName:       echQueryServerName,
		QUIC:                     options.QUIC,
		QUICCongestionControl:    quicCongestionControl,
		QUICSessionReceiveWindow: options.QUICSessionReceiveWindow.Value(),
		// neko: QUIC as HTTP/2 for a locally trusted root (option.NaiveOutboundOptions.QUICLocallyTrustedRoots)
		QUICAllowLocallyTrustedRoots: options.QUICLocallyTrustedRoots,
		// neko: the server's certificate pinned by its key (tls.certificate_public_key_sha256, as the other
		// outbounds take it; raycontrol's niko-pin). Chromium checks the pins besides the chain, where Go's TLS
		// takes them in place of it, and against every key of the chain: pin the leaf's. An address for a name
		// or a hash of another length fails here
		// Without pins of the profile's: the keys of the roots of the core's store, where it is a list (above)
		CertificatePublicKeySHA256: publicKeyPins,
	}
	client, err := cronet.NewNaiveClient(clientOptions)
	if err != nil {
		return nil, err
	}
	var uotClient *uot.Client
	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if uotOptions.Enabled {
		uotClient = &uot.Client{
			Dialer:  &naiveDialer{client},
			Version: uotOptions.Version,
		}
	}
	var datagram *datagramClient
	if options.UDPDatagram {
		if uotClient == nil {
			return nil, E.New("udp_datagram needs udp_over_tcp: UDP goes that way until the probe and after a refusal")
		}
		var authorization string
		if options.Username != "" {
			authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(options.Username+":"+options.Password))
		}
		datagram = newDatagramClient(ctx, logger, clientOptions, serverName, authorization)
		if options.UDPDatagramAllowed {
			datagram.allowedAlways = true
			datagram.allowed.Store(true)
		}
	}
	var networks []string
	if uotClient != nil {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	} else {
		networks = []string{N.NetworkTCP}
	}
	if options.ICMP {
		networks = append(networks, N.NetworkICMP)
	}
	naiveOutbound := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeNaive, tag, networks, options.DialerOptions),
		ctx:       ctx,
		logger:    logger,
		client:    client,
		uotClient: uotClient,
		awaitDial: options.AwaitDial,
		datagram:  datagram,
	}
	if options.ICMP {
		naiveOutbound.icmp = nikoicmp.NewPort(ctx, logger, func(ctx context.Context) (net.Conn, error) {
			return client.DialEarly(ctx, M.Socksaddr{Fqdn: nikoicmp.Name})
		})
	}
	return naiveOutbound, nil
}

// neko: ICMP echo through the node (icmp-v1): a flow of the TUN's, while the node takes it; else the TUN answers
// itself, as without it

func (h *Outbound) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	// a name (FakeDNS) is no address to ping: the router would refuse the flow without one resolved here, so the
	// TUN answers it, as without icmp
	if network == N.NetworkICMP && destination.IsValid() && h.icmp != nil && h.icmp.Available() {
		return adapter.PreMatchFlow
	}
	return adapter.PreMatchContinue
}

func (h *Outbound) PortAddresses() (netip.Addr, netip.Addr) { return h.icmp.PortAddresses() }

func (h *Outbound) PortMTU() uint32 { return h.icmp.PortMTU() }

func (h *Outbound) AttachReturn(returnPath tun.Return) error { return h.icmp.AttachReturn(returnPath) }

func (h *Outbound) DetachReturn(returnPath tun.Return) error { return h.icmp.DetachReturn(returnPath) }

func (h *Outbound) WritePackets(packets [][]byte) error { return h.icmp.WritePackets(packets) }

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := h.client.Start()
	if err != nil {
		return err
	}
	scope.Add(h.client.Close)
	if h.datagram != nil {
		scope.Add(h.datagram.Close)
	}
	if h.icmp != nil {
		scope.Add(h.icmp.Close)
	}
	h.logger.Info("NaiveProxy started, version: ", h.client.Engine().Version())
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		conn, err := h.client.DialEarly(ctx, destination)
		if err != nil {
			return nil, err
		}
		// the stream comes before the proxy's answer: a refusal (429: the node's connection limit) is told on the
		// first read, where it would read as a stream that ends (neko)
		stream, isStream := upstreamOf[*cronet.BidirectionalConn](conn)
		if !isStream {
			// a cronet that wraps its stream another way: said aloud, the refusals read as before
			h.logger.WarnContext(ctx, "naive: no stream under the connection, a refused CONNECT will read as its end")
			return conn, nil
		}
		checked := &statusConn{Conn: conn, ctx: ctx, logger: h.logger, headers: stream.WaitForHeadersContext, ack: h.awaitDial}
		if h.awaitDial {
			// the dial's outcome at the destination before the connection is handed out (neko)
			if err = checked.await(ctx); err != nil {
				conn.Close()
				return nil, err
			}
		}
		return checked, nil
	case N.NetworkUDP:
		if h.uotClient == nil {
			return nil, E.New("UDP is not supported unless UDP over TCP is enabled")
		}
		if packetConn := h.datagramPacketConn(ctx, destination); packetConn != nil {
			return bufio.NewBindPacketConn(packetConn, destination), nil
		}
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.uotClient == nil {
		return nil, E.New("UDP is not supported unless UDP over TCP is enabled")
	}
	if packetConn := h.datagramPacketConn(ctx, destination); packetConn != nil {
		return packetConn, nil
	}
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}

// datagramPacketConn opens the socket as HTTP/3 datagrams when this network allows them, nil for UoT: a socket that
// could not open goes over UoT as well (neko).
func (h *Outbound) datagramPacketConn(ctx context.Context, destination M.Socksaddr) net.PacketConn {
	if !h.datagram.usable() {
		return nil
	}
	packetConn, err := h.datagram.listenPacket(ctx)
	if err != nil {
		h.logger.WarnContext(ctx, "outbound datagram packet connection to ", destination, ", UoT instead: ", err)
		return nil
	}
	h.logger.InfoContext(ctx, "outbound datagram packet connection to ", destination)
	return packetConn
}

// SetDatagramAllowed lets new UDP sockets go as HTTP/3 datagrams on this network, or sends them over UoT: the app
// allows it once its probe through a request has passed (naive-udp-v1 §9.4). Without the udp_datagram option it
// does nothing. A refusal or a broken QUIC connection sends new sockets back over UoT until the network changes
// (neko). The allowance holds until the app takes it back or tells a new network (DatagramNetworkChanged).
func (h *Outbound) SetDatagramAllowed(allowed bool) {
	if h.datagram != nil {
		h.datagram.allowed.Store(allowed)
	}
}

// DatagramNetworkChanged forgets what the last network decided about datagrams, the app's allowance included: the
// app calls it on a network of its own reckoning, before it probes the network or allows datagrams there from a
// result it remembers. The core's own interface updates keep the app's allowance (neko).
func (h *Outbound) DatagramNetworkChanged() {
	h.datagram.networkChanged()
}

// DatagramProbe opens a UDP socket as HTTP/3 datagrams whether or not this network allows them yet: the app's probe
// of the path (naive-udp-v1 §9.4) sends its echo through it. A refusal it meets counts as any socket's would
// (neko).
func (h *Outbound) DatagramProbe(ctx context.Context) (net.PacketConn, error) {
	if h.datagram == nil {
		return nil, E.New("naive: no UDP datagrams (udp_datagram is off)")
	}
	return h.datagram.listenPacket(ctx)
}

// DatagramState tells how new UDP sockets go: "off" (no udp_datagram), "unsupported" (the library has no
// datagrams), "refused" (back over UoT on this network), "allowed" or "probing" (UoT until the app allows) (neko).
func (h *Outbound) DatagramState() string {
	d := h.datagram
	switch {
	case d == nil:
		return "off"
	case d.unsupported.Load():
		return "unsupported"
	case d.refused.Load():
		return "refused"
	case d.allowed.Load():
		return "allowed"
	default:
		return "probing"
	}
}

func (h *Outbound) MultiplexEnabled() bool {
	return true
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.CloseAllConnections()
	h.datagram.interfaceChanged()
}

func (h *Outbound) Client() *cronet.NaiveClient {
	return h.client
}

type naiveDialer struct {
	*cronet.NaiveClient
}

func (d *naiveDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.NaiveClient.DialEarly(ctx, destination)
}

// libraryAnchors are the intermediates the library's own store has as trust anchors, each with its root's key: the
// store the library verifies with, from the Chromium source it is built from (neko). An intermediate whose root the
// table does not hold is left out; the tests say so (anchors_neko_test.go).
var libraryAnchors = sync.OnceValue(func() []certificate.IntermediateAnchor {
	all := cronet.ChromeRootStoreAnchors()
	rootKeys := make(map[int][32]byte)
	for _, anchor := range all {
		if !anchor.Intermediate {
			rootKeys[anchor.RootID] = anchor.PublicKeySHA256
		}
	}
	var anchors []certificate.IntermediateAnchor
	for _, anchor := range all {
		rootKey, hasRoot := rootKeys[anchor.RootID]
		if anchor.Intermediate && hasRoot {
			anchors = append(anchors, certificate.IntermediateAnchor{Key: anchor.PublicKeySHA256, RootKey: rootKey})
		}
	}
	return anchors
})
