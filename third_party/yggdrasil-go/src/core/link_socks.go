package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

type linkSOCKS struct {
	*links
}

func (l *links) newLinkSOCKS() *linkSOCKS {
	lt := &linkSOCKS{
		links: l,
	}
	return lt
}

func (l *linkSOCKS) dial(_ context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	var proxyAuth *proxy.Auth
	if url.User != nil && url.User.Username() != "" {
		proxyAuth = &proxy.Auth{
			User: url.User.Username(),
		}
		proxyAuth.Password, _ = url.User.Password()
	}
	tlsconfig := l.tls.config.Clone()
	return l.findSuitableIP(url, func(hostname string, ip net.IP, port int) (net.Conn, error) {
		hostport := hookTarget(hostname, ip, port)
		var forward proxy.Dialer
		if hook := l.core.config.linkDialer.DialContext; hook != nil && !ip.IsLinkLocalUnicast() {
			forward = hookDialer(hook)
		} else {
			dialer, err := l.tcp.dialerFor(&net.TCPAddr{
				IP:   ip,
				Port: port,
			}, info.sintf)
			if err != nil {
				return nil, err
			}
			forward = dialer
		}
		proxy, err := proxy.SOCKS5("tcp", hostport, proxyAuth, forward)
		if err != nil {
			return nil, err
		}
		pathtokens := strings.Split(strings.Trim(url.Path, "/"), "/")
		conn, err := proxy.Dial("tcp", pathtokens[0])
		if err != nil {
			return nil, err
		}
		if url.Scheme == "sockstls" {
			tlsconfig.ServerName = hostname
			tlsconfig.MinVersion = tls.VersionTLS12
			tlsconfig.MaxVersion = tls.VersionTLS13
			if sni := options.tlsSNI; sni != "" {
				tlsconfig.ServerName = sni
			}
			conn = tls.Client(conn, tlsconfig)
		}
		return conn, nil
	})
}

func (l *linkSOCKS) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error) {
	return nil, fmt.Errorf("SOCKS listener not supported")
}

// hookDialer adapts a LinkDialer to golang.org/x/net/proxy (neko).
type hookDialer func(ctx context.Context, network, address string) (net.Conn, error)

func (d hookDialer) Dial(network, address string) (net.Conn, error) {
	return d(context.Background(), network, address)
}

func (d hookDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d(ctx, network, address)
}
