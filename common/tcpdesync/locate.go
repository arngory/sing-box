package tcpdesync

import (
	"bytes"
	"encoding/binary"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
)

const (
	recordHeaderLen = 5
	// MaxRecordLen is the largest TLS plaintext record payload (RFC 8446 §5.1).
	MaxRecordLen          = 16384
	recordTypeHandshake   = 22
	handshakeClientHello  = 1
	sniExtensionHeaderLen = 5
)

// Protocol is what the first write was recognised as.
type Protocol uint8

const (
	ProtocolUnknown Protocol = iota
	ProtocolTLS
	ProtocolHTTP
)

func (p Protocol) String() string {
	switch p {
	case ProtocolTLS:
		return "tls"
	case ProtocolHTTP:
		return "http"
	default:
		return "unknown"
	}
}

// Positions are the anchors the markers count from, as offsets into the first write; -1 = absent.
type Positions struct {
	Protocol Protocol
	// RecordEnd is the end of the first TLS record (header included); 0 when not TLS.
	RecordEnd int
	Host      int
	EndHost   int
	SNIExt    int
}

// recordLength reports whether b starts with a TLS handshake record holding a ClientHello, and the length of that
// record with its header. b may hold only the start of the record (at least the header).
func recordLength(b []byte) (int, bool) {
	if len(b) < recordHeaderLen || b[0] != recordTypeHandshake || b[1] != 3 || b[2] > 4 {
		return 0, false
	}
	if len(b) > recordHeaderLen && b[recordHeaderLen] != handshakeClientHello {
		return 0, false
	}
	length := int(binary.BigEndian.Uint16(b[3:5]))
	if length == 0 || length > MaxRecordLen {
		return 0, false
	}
	return recordHeaderLen + length, true
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("CONNECT "), []byte("PATCH "), []byte("TRACE "),
}

func isHTTPRequest(b []byte) bool {
	for _, method := range httpMethods {
		if bytes.HasPrefix(b, method) {
			return true
		}
	}
	return false
}

// Locate finds the host name in the first write: the SNI of a whole ClientHello record, or the Host header of a
// plain HTTP request.
func Locate(b []byte) Positions {
	positions := Positions{Host: -1, EndHost: -1, SNIExt: -1}
	if recordEnd, ok := recordLength(b); ok {
		if len(b) < recordEnd {
			return positions
		}
		positions.Protocol = ProtocolTLS
		positions.RecordEnd = recordEnd
		if serverName := tf.IndexTLSServerName(b[:recordEnd]); serverName != nil && serverName.Length > 0 {
			positions.Host = serverName.Index
			positions.EndHost = serverName.Index + serverName.Length
			positions.SNIExt = serverName.Index - sniExtensionHeaderLen
		}
		return positions
	}
	if isHTTPRequest(b) {
		positions.Protocol = ProtocolHTTP
		positions.Host, positions.EndHost = locateHTTPHost(b)
	}
	return positions
}

// locateHTTPHost finds the value of the Host header, without a port.
func locateHTTPHost(b []byte) (int, int) {
	headerEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = len(b)
	}
	const name = "\r\nhost:"
	for i := 0; i+len(name) <= headerEnd; i++ {
		if b[i] != '\r' || !bytes.EqualFold(b[i:i+len(name)], []byte(name)) {
			continue
		}
		start := i + len(name)
		for start < headerEnd && (b[start] == ' ' || b[start] == '\t') {
			start++
		}
		end := start
		for end < headerEnd && b[end] != '\r' && b[end] != '\n' && b[end] != ' ' && b[end] != '\t' {
			end++
		}
		if end > start && b[start] != '[' {
			if colon := bytes.LastIndexByte(b[start:end], ':'); colon >= 0 {
				end = start + colon
			}
		}
		if end <= start {
			return -1, -1
		}
		return start, end
	}
	return -1, -1
}

// sld finds the second-level label of the host name: the label before the last dot, as zapret does.
func (p Positions) sld(b []byte) (int, int, bool) {
	if p.Host < 0 || p.EndHost > len(b) {
		return 0, 0, false
	}
	host := b[p.Host:p.EndHost]
	host = bytes.TrimSuffix(host, []byte("."))
	last := bytes.LastIndexByte(host, '.')
	if last <= 0 {
		return 0, 0, false
	}
	start := bytes.LastIndexByte(host[:last], '.') + 1
	if start >= last {
		return 0, 0, false
	}
	return p.Host + start, p.Host + last, true
}

// Resolve gives the cut position of the marker in b, or false when the marker is not in this protocol or falls
// outside (0, len(b)).
func (m Marker) Resolve(b []byte, p Positions) (int, bool) {
	var base int
	switch m.Base {
	case BaseAbsolute:
		if m.Offset < 0 {
			base = len(b)
		}
	case BaseHost:
		base = p.Host
	case BaseEndHost:
		base = p.EndHost
	case BaseMidHost:
		if p.Host >= 0 {
			base = p.Host + (p.EndHost-p.Host)/2
		} else {
			base = -1
		}
	case BaseSLD, BaseMidSLD, BaseEndSLD:
		start, end, ok := p.sld(b)
		if !ok {
			return 0, false
		}
		switch m.Base {
		case BaseSLD:
			base = start
		case BaseMidSLD:
			base = start + (end-start)/2
		default:
			base = end
		}
	case BaseSNIExt:
		base = p.SNIExt
	default:
		return 0, false
	}
	if base < 0 {
		return 0, false
	}
	position := base + m.Offset
	if position <= 0 || position >= len(b) {
		return 0, false
	}
	return position, true
}
