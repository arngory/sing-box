//go:build !with_yggdrasil

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerYggdrasilEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.YggdrasilEndpointOptions](registry, C.TypeYggdrasil, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.YggdrasilEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New(`yggdrasil is not included in this build, rebuild with -tags with_yggdrasil`)
	})
}
