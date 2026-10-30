//go:build with_yggdrasil

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/yggdrasil"
)

func registerYggdrasilEndpoint(registry *endpoint.Registry) {
	yggdrasil.RegisterEndpoint(registry)
}
