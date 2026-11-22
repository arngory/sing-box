//go:build with_utls

package tls

func (c *UTLSClientConfig) hasDesync() bool { return c.desync != nil }

func (e *RealityClientConfig) hasDesync() bool {
	return e.uClient != nil && e.uClient.desync != nil
}
