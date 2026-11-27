package slipstream

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	dnstt "github.com/sagernet/sing-box/transport/dnstt"
)

// Native Go Slipstream (QUIC over DNS) transport codec — Variant B foundation.
// Encodes raw QUIC packets into base32 lowercase DNS query labels (split <=63 chars/label)
// under a configured zone with optional dnsauth-v2 8-byte HMAC prefix (reusing transport/dnstt.AuthTag),
// fans out UDP queries across up to 4 resolvers, and unpacks TXT response payloads back into QUIC datagrams.

const (
	maxLabelLen = 63
	maxNameLen  = 253
	ednsUDPSize = 1232
)

var labelB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// AuthConfig configures optional dnsauth-v2 per-query authentication for slipstream-v1.
type AuthConfig struct {
	Key       []byte
	ClockSkew time.Duration
}

// EncodeQueryName encodes a raw QUIC packet (with optional 8-byte dnsauth-v2 tag) into a valid
// DNS query name under zone (FQDN). Returns an error if the encoded name exceeds 253 bytes.
func EncodeQueryName(payload []byte, zone string, auth *AuthConfig, now time.Time) (string, error) {
	if len(payload) == 0 {
		return "", errors.New("slipstream: empty payload")
	}
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zone == "" {
		return "", errors.New("slipstream: empty zone")
	}
	wire := payload
	if auth != nil && len(auth.Key) == 32 {
		// dnsauth-v2: 8-byte tag = HMAC-SHA256(K, "dnsauth1" || epoch || payload)[:8] with version hint.
		ts := now.Add(auth.ClockSkew)
		tag := dnstt.AuthTag(auth.Key, ts, payload)
		framed := make([]byte, len(tag)+len(payload))
		copy(framed, tag)
		copy(framed[len(tag):], payload)
		wire = framed
	}
	encoded := strings.ToLower(labelB32.EncodeToString(wire))
	var labels []string
	for len(encoded) > 0 {
		n := maxLabelLen
		if len(encoded) < n {
			n = len(encoded)
		}
		labels = append(labels, encoded[:n])
		encoded = encoded[n:]
	}
	name := strings.Join(labels, ".") + "." + zone
	if len(name) > maxNameLen {
		return "", errors.New("slipstream: encoded DNS query name exceeds 253 bytes")
	}
	return dns.Fqdn(name), nil
}

// DecodeQueryName extracts the raw payload (and optional 8-byte dnsauth tag) from a DNS query name
// under zone. Used both for testing and server-side verification.
func DecodeQueryName(qname string, zone string, hasAuth bool) (tag []byte, payload []byte, err error) {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	z := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	suffix := "." + z
	if !strings.HasSuffix(q, suffix) {
		return nil, nil, errors.New("slipstream: query name outside zone")
	}
	prefix := strings.TrimSuffix(q, suffix)
	joined := strings.ToUpper(strings.ReplaceAll(prefix, ".", ""))
	raw, err := labelB32.DecodeString(joined)
	if err != nil {
		return nil, nil, err
	}
	if hasAuth {
		if len(raw) <= 8 {
			return nil, nil, errors.New("slipstream: truncated authenticated payload")
		}
		return raw[:8], raw[8:], nil
	}
	return nil, raw, nil
}

// PackTXTResponse packs a raw QUIC response payload into DNS TXT record strings (<=255 bytes each).
func PackTXTResponse(req *dns.Msg, payload []byte) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.SetEdns0(ednsUDPSize, false)
	if len(payload) > 0 {
		// Base64url-encode binary QUIC datagram safely inside TXT chunks for universal resolver pass-through.
		enc := base64.RawURLEncoding.EncodeToString(payload)
		var chunks []string
		for len(enc) > 0 {
			n := 255
			if len(enc) < n {
				n = len(enc)
			}
			chunks = append(chunks, enc[:n])
			enc = enc[n:]
		}
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			Txt: chunks,
		})
	}
	return resp, nil
}

// UnpackTXTResponse extracts a raw QUIC payload from a DNS TXT response.
func UnpackTXTResponse(resp *dns.Msg) ([]byte, error) {
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return nil, errors.New("slipstream: non-success DNS response")
	}
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok || len(txt.Txt) == 0 {
			continue
		}
		joined := strings.Join(txt.Txt, "")
		return base64.RawURLEncoding.DecodeString(joined)
	}
	return nil, nil
}

// VerifySPKIPin checks that cert's SubjectPublicKeyInfo SHA-256 matches expectedPin (43-char base64url).
func VerifySPKIPin(cert *x509.Certificate, expectedPin string) error {
	if cert == nil {
		return errors.New("slipstream: missing server certificate")
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if got != strings.TrimSpace(expectedPin) {
		return errors.New("slipstream: server SPKI pin mismatch")
	}
	return nil
}

// DNSPacketConn wraps a UDP net.PacketConn to tunnel QUIC datagrams inside DNS TXT queries/responses
// across one or more UDP resolvers (Variant B core transport).
type DNSPacketConn struct {
	udp       net.PacketConn
	resolvers []*net.UDPAddr
	zone      string
	auth      *AuthConfig
	rr        atomic.Uint32
	peerAddr  net.Addr
	closeOnce sync.Once
	closed    chan struct{}
	incoming  chan []byte
}

// NewDNSPacketConn creates a DNS-encapsulated PacketConn targeting resolvers under zone.
func NewDNSPacketConn(udp net.PacketConn, resolvers []*net.UDPAddr, zone string, auth *AuthConfig) (*DNSPacketConn, error) {
	if len(resolvers) == 0 {
		return nil, errors.New("slipstream: at least one resolver is required")
	}
	c := &DNSPacketConn{
		udp:       udp,
		resolvers: resolvers,
		zone:      zone,
		auth:      auth,
		peerAddr:  resolvers[0],
		closed:    make(chan struct{}),
		incoming:  make(chan []byte, 128),
	}
	go c.readLoop()
	return c, nil
}

func (c *DNSPacketConn) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, _, err := c.udp.ReadFrom(buf)
		if err != nil {
			select {
			case <-c.closed:
				return
			default:
				continue
			}
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		payload, err := UnpackTXTResponse(msg)
		if err != nil || len(payload) == 0 {
			continue
		}
		select {
		case c.incoming <- payload:
		case <-c.closed:
			return
		}
	}
}

func (c *DNSPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case data := <-c.incoming:
		n := copy(p, data)
		return n, c.peerAddr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *DNSPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	qname, err := EncodeQueryName(p, c.zone, c.auth, time.Now())
	if err != nil {
		return 0, err
	}
	msg := new(dns.Msg)
	msg.Id = uint16(binary.BigEndian.Uint16([]byte{byte(c.rr.Add(1)), byte(time.Now().UnixNano())}))
	msg.RecursionDesired = true
	msg.SetQuestion(qname, dns.TypeTXT)
	msg.SetEdns0(ednsUDPSize, false)
	wire, err := msg.Pack()
	if err != nil {
		return 0, err
	}
	target := c.resolvers[int(c.rr.Add(1))%len(c.resolvers)]
	if _, err := c.udp.WriteTo(wire, target); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *DNSPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		err = c.udp.Close()
	})
	return err
}

func (c *DNSPacketConn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *DNSPacketConn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *DNSPacketConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *DNSPacketConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }
