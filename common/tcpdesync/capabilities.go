package tcpdesync

import (
	"strings"
	"sync"
)

// PlatformCapabilities are the socket tricks this platform allows an unprivileged process, as probed on a
// loopback connection. The app offers only the strategies they allow (design §5.1).
type PlatformCapabilities struct {
	// TTL: IP_TTL can be set on a TCP socket (disorder, disoob).
	TTL bool `json:"ttl"`
	// OOB: send(MSG_OOB) works and a receiver without SO_OOBINLINE keeps the byte out of the stream (oob, disoob).
	OOB bool `json:"oob"`
	// NotSent: TCP_INFO reports tcpi_notsent_bytes, so a cut is a segment of its own without waiting for an ACK.
	NotSent bool `json:"notsent"`
	// Error is why the probe could not run, if it could not.
	Error string `json:"error,omitempty"`
}

func (c PlatformCapabilities) String() string {
	var parts []string
	for _, item := range []struct {
		name string
		ok   bool
	}{{"ttl", c.TTL}, {"oob", c.OOB}, {"notsent", c.NotSent}} {
		if item.ok {
			parts = append(parts, item.name)
		} else {
			parts = append(parts, "no-"+item.name)
		}
	}
	if c.Error != "" {
		parts = append(parts, "error="+c.Error)
	}
	return strings.Join(parts, " ")
}

var capabilities = sync.OnceValue(probe)

// Capabilities probes the platform once and returns the result.
func Capabilities() PlatformCapabilities {
	return capabilities()
}
