package tls

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/common/tcpdesync"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// parseDesync parses the desync option of a TLS outbound: tcpdesync on the node's own handshake (neko, design
// §5.4: split, oob and tlsrec only).
func parseDesync(options option.OutboundTLSOptions) (*tcpdesync.Strategy, error) {
	strategy, err := tcpdesync.ParseOutbound(options.Desync)
	if err != nil || strategy == nil {
		return nil, err
	}
	if options.Fragment || options.RecordFragment {
		return nil, E.New("tls.desync and fragment/record_fragment are mutually exclusive")
	}
	if options.Spoof != "" {
		return nil, E.New("tls.desync and spoof are mutually exclusive")
	}
	return strategy, nil
}

func applyDesync(ctx context.Context, conn net.Conn, strategy *tcpdesync.Strategy, contextLogger logger.ContextLogger) net.Conn {
	if strategy == nil {
		return conn
	}
	return tcpdesync.NewConn(ctx, conn, strategy, contextLogger)
}
