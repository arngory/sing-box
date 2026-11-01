//go:build with_yggdrasil

package yggdrasil

import (
	"context"
	"crypto/tls"
	"net"

	E "github.com/sagernet/sing/common/exceptions"

	utls "github.com/metacubex/utls"
)

// linkTLSClient returns the client handshake of tls:// links. crypto/tls has a
// ClientHello DPI tells apart from browsers (JA4); "chrome" sends uTLS's Chrome
// one instead. Yggdrasil checks nothing at the TLS layer (its own handshake
// authenticates the peer), so the certificate is not verified here either.
func linkTLSClient(fingerprint string) (func(ctx context.Context, conn net.Conn, config *tls.Config) (net.Conn, error), error) {
	switch fingerprint {
	case "", "chrome":
		return chromeTLSClient, nil
	case "go":
		return nil, nil
	default:
		return nil, E.New("yggdrasil: unknown tls_fingerprint ", fingerprint, " (chrome or go)")
	}
}

func chromeTLSClient(ctx context.Context, conn net.Conn, config *tls.Config) (net.Conn, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return nil, err
	}
	// node certificates are ed25519, which Chrome does not offer to verify
	for _, extension := range spec.Extensions {
		if algorithms, ok := extension.(*utls.SignatureAlgorithmsExtension); ok {
			algorithms.SupportedSignatureAlgorithms = append(algorithms.SupportedSignatureAlgorithms, utls.Ed25519)
		}
	}
	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: true,
		MinVersion:         utls.VersionTLS13,
	}, utls.HelloCustom)
	if err = uConn.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	if err = uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uConn, nil
}
