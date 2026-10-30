//go:build with_masterdnsvpn

package masterdnsvpn

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"

	"masterdnsvpn-go/embed"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MasterDNSVPNOutboundOptions](registry, C.TypeMasterDNSVPN, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

// Outbound runs the MasterDnsVPN client in process and hands it connections through
// in-memory pipes: no loopback port another app could use or take over.
type Outbound struct {
	outbound.Adapter
	ctx     context.Context
	logger  logger.ContextLogger
	options embed.Options
	tcpMode bool
	conns   chan net.Conn

	access sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MasterDNSVPNOutboundOptions) (adapter.Outbound, error) {
	if len(options.Domains) == 0 {
		return nil, E.New("missing domains")
	}
	if len(options.Resolvers) == 0 {
		return nil, E.New("missing resolvers")
	}
	mode := strings.ToLower(options.Mode)
	switch mode {
	case "", "socks5":
		mode = "SOCKS5"
	case "tcp":
		mode = "TCP"
	default:
		return nil, E.New("unknown mode ", options.Mode, " (expected socks5 or tcp)")
	}
	config := make(map[string]any, len(options.Extra)+5)
	for key, value := range options.Extra {
		config[strings.ToUpper(key)] = value
	}
	config["DOMAINS"] = options.Domains
	config["PROTOCOL_TYPE"] = mode
	config["DATA_ENCRYPTION_METHOD"] = options.EncryptionMethod
	config["ENCRYPTION_KEY"] = options.EncryptionKey
	if _, set := config["LOG_LEVEL"]; !set {
		config["LOG_LEVEL"] = "WARN"
	}
	workDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	conns := make(chan net.Conn)
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeMasterDNSVPN, tag, []string{N.NetworkTCP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,
		tcpMode: mode == "TCP",
		conns:   conns,
		options: embed.Options{
			Config:      config,
			Resolvers:   options.Resolvers,
			WorkDir:     workDir,
			Conns:       conns,
			ProtectPath: options.ProtectPath,
		},
	}, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	ctx, cancel := context.WithCancel(h.ctx)
	done := make(chan struct{})
	h.access.Lock()
	h.cancel, h.done = cancel, done
	h.access.Unlock()
	scope.Add(h.Close)
	go func() {
		defer close(done)
		if err := embed.Run(ctx, h.options); err != nil && ctx.Err() == nil {
			h.logger.Error("masterdnsvpn: ", err)
		}
	}()
	return nil
}

func (h *Outbound) Close() error {
	h.access.Lock()
	cancel, done := h.cancel, h.done
	h.access.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.New("masterdnsvpn: ", network, " is not supported")
	}
	h.access.Lock()
	done := h.done
	h.access.Unlock()
	if done == nil {
		return nil, E.New("masterdnsvpn client not started")
	}
	select {
	case <-done:
		return nil, E.New("masterdnsvpn client stopped, see the log")
	default:
	}
	// the client accepts only once its session is up; a detour or the router dial
	// without a deadline, which would wait here for as long as that takes
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, C.TCPTimeout)
		defer cancel()
	}
	local, remote := net.Pipe()
	select {
	case h.conns <- remote:
	case <-done:
		local.Close()
		remote.Close()
		return nil, E.New("masterdnsvpn client stopped, see the log")
	case <-ctx.Done():
		local.Close()
		remote.Close()
		return nil, ctx.Err()
	}
	if h.tcpMode {
		h.logger.InfoContext(ctx, "outbound connection through the masterdnsvpn upstream (requested ", destination, ")")
		return local, nil
	}
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	if deadline, ok := ctx.Deadline(); ok {
		local.SetDeadline(deadline)
	}
	_, err := socks.ClientHandshake5(local, socks5.CommandConnect, destination, "", "")
	local.SetDeadline(time.Time{})
	if err != nil {
		local.Close()
		return nil, E.Cause(err, "masterdnsvpn SOCKS5 handshake")
	}
	return local, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("masterdnsvpn: UDP is not supported")
}
