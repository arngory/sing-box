//go:build !linux

package tcpdesync

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing/common/logger"
)

var warnDegraded sync.Once

// sendPieces without Linux socket tricks: each piece is its own write (Go sets TCP_NODELAY), with no check that
// it left as a segment of its own; disorder and oob are sent as split, without the OOB byte.
func sendPieces(ctx context.Context, conn *net.TCPConn, pieces []Piece, contextLogger logger.ContextLogger) error {
	for _, piece := range pieces {
		if piece.Mode != ModeSplit {
			warnDegraded.Do(func() {
				contextLogger.WarnContext(ctx, "tcp_desync: disorder and oob need Linux or Android, sent as split")
			})
		}
		if _, err := conn.Write(piece.Data); err != nil {
			return err
		}
	}
	return nil
}

func probe() PlatformCapabilities {
	return PlatformCapabilities{Error: "not supported on this platform"}
}
