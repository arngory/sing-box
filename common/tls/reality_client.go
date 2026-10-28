//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tlsfragment"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"

	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

var _ ConfigCompat = (*RealityClientConfig)(nil)

type RealityClientConfig struct {
	ctx       context.Context
	uClient   *UTLSClientConfig
	publicKey []byte
	shortID   [8]byte
	keyShare  string
	// neko: for the default key_share, set after a verification failed with the hybrid share and
	// cleared after one failed without it. One per server and key, see realityClassicalFallbacks.
	classicalFallback *atomic.Bool
	logger            logger.ContextLogger
}

func NewRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	return newRealityClient(ctx, logger, serverAddress, options, false)
}

func newRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (Config, error) {
	if options.UTLS == nil || !options.UTLS.Enabled {
		return nil, E.New("uTLS is required by reality client")
	}
	if options.Spoof != "" || options.SpoofMethod != "" {
		return nil, E.New("spoof is unsupported in reality")
	}

	uClient, err := newUTLSClient(ctx, logger, serverAddress, options, allowEmptyServerName)
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(options.Reality.PublicKey)
	if err != nil {
		return nil, E.Cause(err, "decode public_key")
	}
	if len(publicKey) != 32 {
		return nil, E.New("invalid public_key")
	}
	// hex.Decode writes len(src)/2 bytes without checking dst: check the length first (from sing-box-lx)
	if len(options.Reality.ShortID) > 16 {
		return nil, E.New("invalid short_id")
	}
	var shortID [8]byte
	_, err = hex.Decode(shortID[:], []byte(options.Reality.ShortID))
	if err != nil {
		return nil, E.Cause(err, "decode short_id")
	}
	switch options.Reality.KeyShare {
	case C.RealityKeyShareDefault, C.RealityKeyShareHybrid, C.RealityKeyShareClassical:
	default:
		return nil, E.New("unknown reality key_share: ", options.Reality.KeyShare, " (expected \"hybrid\" or \"classical\")")
	}

	var config Config = &RealityClientConfig{ctx, uClient.(*UTLSClientConfig), publicKey, shortID, options.Reality.KeyShare, realityClassicalFallback(serverAddress, publicKey), logger}
	if options.KernelRx || options.KernelTx {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{
			Config:   config,
			logger:   logger,
			kernelTx: options.KernelTx,
			kernelRx: options.KernelRx,
		}
	}
	return config, nil
}

func (e *RealityClientConfig) ServerName() string {
	return e.uClient.ServerName()
}

func (e *RealityClientConfig) SetServerName(serverName string) {
	e.uClient.SetServerName(serverName)
}

func (e *RealityClientConfig) NextProtos() []string {
	return e.uClient.NextProtos()
}

func (e *RealityClientConfig) SetNextProtos(nextProto []string) {
	e.uClient.SetNextProtos(nextProto)
}

func (e *RealityClientConfig) HandshakeTimeout() time.Duration {
	return e.uClient.HandshakeTimeout()
}

func (e *RealityClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	e.uClient.SetHandshakeTimeout(timeout)
}

func (e *RealityClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for reality")
}

func (e *RealityClientConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, e)
}

func (e *RealityClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	verifier := &realityVerifier{
		serverName: e.uClient.ServerName(),
	}
	uConfig := e.uClient.config.Clone()
	uConfig.InsecureSkipVerify = true
	uConfig.SessionTicketsDisabled = true
	uConfig.VerifyPeerCertificate = verifier.VerifyPeerCertificate
	// neko: honour fragment/record_fragment like the plain uTLS client does
	if e.uClient.fragment || e.uClient.recordFragment {
		conn = tf.NewConn(conn, ctx, e.uClient.fragment, e.uClient.recordFragment, e.uClient.fragmentFallbackDelay)
	}
	uConn := utls.UClient(conn, uConfig, e.uClient.id)
	verifier.UConn = uConn
	err := uConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}
	// From sing-box-lx (SPEC 083/089): upstream stripped X25519MLKEM768 here, a workaround for
	// utls versions that did not keep the hybrid and plain X25519 keys apart. Xray >= v26.9.8
	// (XTLS/REALITY@8cdf7bf) rejects a ClientHello without the hybrid share by silently proxying
	// to the dest ("reality verification failed"). metacubex/utls >= 1.8 keeps them apart, so the
	// fingerprint's own shares go out unless key_share asks for the classical ClientHello.
	// neko: servers on older Xray or sagernet/reality can not take the hybrid share once the dest
	// picks it, which is why upstream stripped it. With the default key_share a failed
	// verification switches this outbound to the other ClientHello for the next handshakes.
	classical := e.keyShare == C.RealityKeyShareClassical
	switchable := e.keyShare == C.RealityKeyShareDefault && realityHelloCarriesHybridShare(uConn)
	if switchable {
		classical = e.classicalFallback.Load()
	}
	switch {
	case classical:
		for _, extension := range uConn.Extensions {
			if ce, ok := extension.(*utls.SupportedCurvesExtension); ok {
				ce.Curves = common.Filter(ce.Curves, func(curveID utls.CurveID) bool {
					return curveID != utls.X25519MLKEM768
				})
			}
			if ks, ok := extension.(*utls.KeyShareExtension); ok {
				ks.KeyShares = common.Filter(ks.KeyShares, func(share utls.KeyShare) bool {
					return share.Group != utls.X25519MLKEM768
				})
			}
		}
		err = uConn.BuildHandshakeState()
		if err != nil {
			return nil, err
		}
	case e.keyShare == C.RealityKeyShareHybrid:
		if !realityHelloCarriesHybridShare(uConn) {
			return nil, E.New("reality key_share \"hybrid\": fingerprint ", e.uClient.id.Client, " ", e.uClient.id.Version, " carries no X25519MLKEM768 key share")
		}
	}

	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				break
			}
		}
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	var nowTime time.Time
	if uConfig.Time != nil {
		nowTime = uConfig.Time()
	} else {
		nowTime = time.Now()
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(nowTime.Unix()))

	// From sing-box-lx (SPEC 053): Xray v26.7.11 (XTLS/Xray-core@af7eb68) defaults to
	// minClientVer=26.3.27 and silently proxies older clients to the dest. Announce exactly that.
	hello.SessionId[0] = 26
	hello.SessionId[1] = 3
	hello.SessionId[2] = 27
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], e.shortID[:])
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId[:16]: %v\n", hello.SessionId[:16])
	}
	publicKey, err := ecdh.X25519().NewPublicKey(e.publicKey)
	if err != nil {
		return nil, err
	}
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil {
		return nil, E.New("nil KeyShareKeys")
	}
	// the AuthKey uses the share the server takes: plain X25519 when the ClientHello has it,
	// otherwise the X25519 part of X25519MLKEM768 (XTLS/REALITY@8cdf7bf, from sing-box-lx)
	ecdheKey := keyShareKeys.Ecdhe
	if ecdheKey == nil {
		ecdheKey = keyShareKeys.MlkemEcdhe
	}
	if ecdheKey == nil {
		return nil, E.New("nil ecdheKey")
	}
	authKey, err := ecdheKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	if authKey == nil {
		return nil, E.New("nil auth_key")
	}
	verifier.authKey = authKey
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	if err != nil {
		return nil, err
	}
	aesBlock, _ := aes.NewCipher(authKey)
	aesGcmCipher, _ := cipher.NewGCM(aesBlock)
	aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId: %v\n", hello.SessionId)
		fmt.Printf("REALITY uConn.AuthKey: %v\n", authKey)
	}

	err = uConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}

	if debug.Enabled {
		fmt.Printf("REALITY Conn.Verified: %v\n", verifier.verified)
	}

	if !verifier.verified {
		if switchable && e.classicalFallback.CompareAndSwap(classical, !classical) && e.logger != nil {
			if classical {
				e.logger.WarnContext(ctx, "reality verification failed with the classical key share, next handshakes offer X25519MLKEM768 again")
			} else {
				e.logger.WarnContext(ctx, "reality verification failed with the X25519MLKEM768 key share, next handshakes use classical X25519 (set key_share to pin one)")
			}
		}
		go realityClientFallback(e.ctx, uConn, e.uClient.ServerName(), e.uClient.id)
		return nil, E.New("reality verification failed")
	}

	return &realityClientConnWrapper{uConn}, nil
}

func realityClientFallback(ctx context.Context, uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
	}
	serverAddress := M.ParseSocksaddrHostPort(serverName, 0)
	host := serverAddress.AddrString()
	if serverAddress.IsIPv6() {
		host = "[" + host + "]"
	}
	request, err := http.NewRequest("GET", "https://"+host, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", mRand.Intn(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

func (e *RealityClientConfig) Clone() Config {
	return &RealityClientConfig{
		e.ctx,
		e.uClient.Clone().(*UTLSClientConfig),
		e.publicKey,
		e.shortID,
		e.keyShare,
		e.classicalFallback,
		e.logger,
	}
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeFor[utls.Conn]().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Add(unsafe.Pointer(c.Conn), p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type realityClientConnWrapper struct {
	*utls.UConn
}

func (c *realityClientConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *realityClientConnWrapper) Upstream() any {
	return c.UConn
}

// Due to low implementation quality, the reality server intercepted half close and caused memory leaks.
// We fixed it by calling Close() directly.
func (c *realityClientConnWrapper) CloseWrite() error {
	return c.Close()
}

func (c *realityClientConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *realityClientConnWrapper) WriterReplaceable() bool {
	return false
}

// realityClassicalFallbacks keeps the learned ClientHello per server address and public key for
// the life of the process: a latency test or restart builds a new box and outbound, and would
// otherwise fail its first handshake to the same server again.
var realityClassicalFallbacks sync.Map

func realityClassicalFallback(serverAddress string, publicKey []byte) *atomic.Bool {
	value, _ := realityClassicalFallbacks.LoadOrStore(serverAddress+"/"+hex.EncodeToString(publicKey), new(atomic.Bool))
	return value.(*atomic.Bool)
}

// realityHelloCarriesHybridShare reports whether the built ClientHello offers an
// X25519MLKEM768 key share. From sing-box-lx (SPEC 089).
func realityHelloCarriesHybridShare(uConn *utls.UConn) bool {
	for _, extension := range uConn.Extensions {
		if keyShares, isKeyShares := extension.(*utls.KeyShareExtension); isKeyShares {
			for _, share := range keyShares.KeyShares {
				if share.Group == utls.X25519MLKEM768 {
					return true
				}
			}
		}
	}
	return false
}
