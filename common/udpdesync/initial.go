package udpdesync

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/hkdf"
)

// QUIC v1 initial salt (RFC 9001 §5.2)
var initialSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

const initialSize = 1200

// FakeInitial builds a QUIC v1 client Initial (random connection IDs) whose
// ClientHello names sni. A DPI box decrypts it like any Initial and reads the
// name; the server it reaches either drops it (niko-server: no route for sni)
// or never sees it (low TTL).
func FakeInitial(sni string) []byte {
	dcid := randomBytes(8)
	scid := randomBytes(8)
	hello := clientHello(sni)

	// CRYPTO frame: type, offset 0, length, data
	payload := []byte{0x06, 0x00}
	payload = appendVarint(payload, uint64(len(hello)))
	payload = append(payload, hello...)

	const pnLength = 4
	header := []byte{0xc0 | (pnLength - 1)}
	header = binary.BigEndian.AppendUint32(header, 1)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00) // token length
	// pad the payload (PADDING frames are zero bytes) so the datagram is initialSize
	lengthFieldSize := 2
	payloadSize := initialSize - len(header) - lengthFieldSize - pnLength - 16
	if payloadSize > len(payload) {
		payload = append(payload, make([]byte, payloadSize-len(payload))...)
	}
	header = append(header, byte(0x40|(pnLength+len(payload)+16)>>8), byte(pnLength+len(payload)+16))
	pnOffset := len(header)
	packetNumber := uint32(0)
	header = binary.BigEndian.AppendUint32(header, packetNumber)

	key, iv, hp := initialClientKeys(dcid)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
	}
	packet := aead.Seal(header, nonce, payload, header)

	// header protection (RFC 9001 §5.4): sample 16 bytes 4 after the packet number start
	hpBlock, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	hpBlock.Encrypt(mask, packet[pnOffset+4:pnOffset+20])
	packet[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLength; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet
}

func initialClientKeys(dcid []byte) (key, iv, hp []byte) {
	initialSecret := hkdf.Extract(sha256.New, dcid, initialSaltV1)
	clientSecret := expandLabel(initialSecret, "client in", 32)
	return expandLabel(clientSecret, "quic key", 16), expandLabel(clientSecret, "quic iv", 12), expandLabel(clientSecret, "quic hp", 16)
}

// expandLabel is TLS 1.3 HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, length int) []byte {
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len("tls13 "+label)))
	info = append(info, "tls13 "+label...)
	info = append(info, 0)
	out := make([]byte, length)
	hkdf.Expand(sha256.New, secret, info).Read(out)
	return out
}

// clientHello is a small TLS 1.3 ClientHello for QUIC: SNI, ALPN h3, an X25519 share
// and transport parameters, which is what SNI-reading DPI parses.
func clientHello(sni string) []byte {
	var ext []byte
	addExt := func(kind uint16, data []byte) {
		ext = binary.BigEndian.AppendUint16(ext, kind)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
		ext = append(ext, data...)
	}
	// server_name
	name := []byte{0x00}
	name = binary.BigEndian.AppendUint16(name, uint16(len(sni)))
	name = append(name, sni...)
	addExt(0x0000, append(binary.BigEndian.AppendUint16(nil, uint16(len(name))), name...))
	// supported_groups: x25519, secp256r1
	addExt(0x000a, []byte{0x00, 0x04, 0x00, 0x1d, 0x00, 0x17})
	// signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256, ed25519
	addExt(0x000d, []byte{0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x08, 0x07})
	// application_layer_protocol_negotiation: h3
	addExt(0x0010, []byte{0x00, 0x03, 0x02, 'h', '3'})
	// supported_versions: TLS 1.3
	addExt(0x002b, []byte{0x02, 0x03, 0x04})
	// key_share: x25519
	share := []byte{0x00, 0x1d, 0x00, 0x20}
	share = append(share, randomBytes(32)...)
	addExt(0x0033, append(binary.BigEndian.AppendUint16(nil, uint16(len(share))), share...))
	// psk_key_exchange_modes: psk_dhe_ke
	addExt(0x002d, []byte{0x01, 0x01})
	// quic_transport_parameters: initial_max_data, initial_source_connection_id (empty)
	addExt(0x0039, []byte{0x04, 0x04, 0x80, 0x10, 0x00, 0x00, 0x0f, 0x00})

	body := []byte{0x03, 0x03}
	body = append(body, randomBytes(32)...)
	body = append(body, 0x00)                                           // session id
	body = append(body, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03) // TLS 1.3 suites
	body = append(body, 0x01, 0x00)                                     // compression: null
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hello := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hello, body...)
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(0x40|v>>8), byte(v))
	default:
		return binary.BigEndian.AppendUint32(b, uint32(0x80000000|v))
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
