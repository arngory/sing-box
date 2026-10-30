//go:build !with_dnstt

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerDNSTTOutbound(registry *outbound.Registry) {
	outbound.Register[option.DNSTTOutboundOptions](registry, C.TypeDNSTT, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DNSTTOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`dnstt is not included in this build, rebuild with -tags with_dnstt`)
	})
}
