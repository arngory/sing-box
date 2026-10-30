//go:build with_masterdnsvpn

package masterdnsvpn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

	"masterdnsvpn-go/embed"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MasterDNSVPNOutboundOptions](registry, C.TypeMasterDNSVPN, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

// Outbound runs the MasterDnsVPN client in process on a loopback port with random
// SOCKS5 credentials and dials through it.
type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	logger    logger.ContextLogger
	options   embed.Options
	tcpMode   bool
	socks     *socks.Client
	localAddr M.Socksaddr

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
	user, pass := randomHex(8), randomHex(16)
	workDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeMasterDNSVPN, tag, []string{N.NetworkTCP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,
		tcpMode: mode == "TCP",
		options: embed.Options{
			Config:      config,
			Resolvers:   options.Resolvers,
			WorkDir:     workDir,
			SOCKSUser:   user,
			SOCKSPass:   pass,
			ProtectPath: options.ProtectPath,
		},
	}, nil
}

func randomHex(n int) string {
	buf := make([]byte, n)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	// a free loopback port for the client's listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	h.options.ListenPort = port
	h.localAddr = M.ParseSocksaddrHostPort("127.0.0.1", uint16(port))
	if !h.tcpMode {
		h.socks = socks.NewClient(N.SystemDialer, h.localAddr, socks.Version5, h.options.SOCKSUser, h.options.SOCKSPass)
	} else {
		h.options.SOCKSUser, h.options.SOCKSPass = "", ""
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
	if h.tcpMode {
		h.logger.InfoContext(ctx, "outbound connection through the masterdnsvpn upstream (requested ", destination, ")")
		return N.SystemDialer.DialContext(ctx, N.NetworkTCP, h.localAddr)
	}
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	return h.socks.DialContext(ctx, N.NetworkTCP, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("masterdnsvpn: UDP is not supported")
}
