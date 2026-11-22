package option

import "github.com/sagernet/sing/common/json/badoption"

// FallbackDNSServerOptions is a neko addition: the options of a DNS server of
// type fallback.
type FallbackDNSServerOptions struct {
	// Servers are the tags of the DNS servers to try, in order.
	Servers badoption.Listable[string] `json:"servers,omitempty"`
	// Timeout is how long one server may take to answer before the next is
	// tried. The last server tried is given the query's own deadline.
	Timeout badoption.Duration `json:"timeout,omitempty"`
}
