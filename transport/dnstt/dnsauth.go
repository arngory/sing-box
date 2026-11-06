package dnstt

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// raycontrol dnsauth-v1 (docs/spec/dnsauth-v1.md): an 8-byte tag before the ClientID of every query,
// HMAC-SHA256(K, "dnsauth1" || uint32_be(epoch) || payload)[:8], epoch = unix time / 600. A node in
// optional or required mode answers a query with a wrong tag like garbage in an empty zone (NXDOMAIN).

const (
	authTagLen   = 8
	authEpochLen = 600
)

// DeviceKeys resolves a device key reference (DNSTTAuthOptions.DeviceKeyRef) to the 32-byte SPA key; the
// embedding app sets it (Niko: libcore, the keys of its raycontrol nodes).
var DeviceKeys func(ref string) ([]byte, error)

// AuthKey derives K = HKDF-SHA256(ikm = device key, salt = node id, info = "raycontrol-dnsauth-v1" ||
// uint16_be(service id), 32 bytes) (§2).
func AuthKey(deviceKey []byte, nodeIDHex string, serviceID uint16) ([]byte, error) {
	if len(deviceKey) != 32 {
		return nil, E.New("dnsauth: device key of ", len(deviceKey), " bytes, want 32")
	}
	nodeID, err := hex.DecodeString(nodeIDHex)
	if err != nil || len(nodeID) != 16 {
		return nil, E.New("dnsauth: node id must be 32 hex digits")
	}
	info := binary.BigEndian.AppendUint16([]byte("raycontrol-dnsauth-v1"), serviceID)
	return hkdf.Key(sha256.New, deviceKey, nodeID, string(info), 32)
}

// ResolveDeviceKey is the device key of options: given, or by reference.
func ResolveDeviceKey(key, ref string) ([]byte, error) {
	if key != "" {
		b, err := hex.DecodeString(key)
		if err != nil {
			return nil, E.Cause(err, "dnsauth: device_key")
		}
		return b, nil
	}
	if ref == "" {
		return nil, E.New("dnsauth: no device key")
	}
	if DeviceKeys == nil {
		return nil, E.New("dnsauth: no resolver for device_key_ref")
	}
	return DeviceKeys(ref)
}

// authTag is the tag of payload (ClientID, padding and packets) at time now.
func authTag(key, payload []byte, now time.Time) []byte {
	return AuthTag(key, now, payload)
}

// AuthVersion is the dnsauth version of options: 1 (also 0, unset) or 2.
func AuthVersion(version uint8) (int, error) {
	switch version {
	case 0, 1:
		return 1, nil
	case 2:
		return 2, nil
	}
	return 0, E.New("dnsauth: version ", version, " (expected 1 or 2)")
}

// AuthField is the 8 bytes a query carries under dnsauth version 1 (the tag, AuthTag) or 2 (hint || tag,
// AuthHintTag), of the message parts at time now (the node's).
func AuthField(key []byte, version int, now time.Time, parts ...[]byte) []byte {
	if version == 2 {
		return AuthHintTag(key, now, parts...)
	}
	return AuthTag(key, now, parts...)
}

// AuthHintTag is dnsauth-v2's field (docs/spec/dnsauth-v2.md §2): hint (2) || tag (6),
// hint = HMAC-SHA256(K, "dnsauth2-hint" || uint32_be(epoch))[:2], tag = HMAC-SHA256(K, "dnsauth2-tag" ||
// uint32_be(epoch) || msg)[:6]. The hint is the device's for the epoch: the node finds the key by it, without trying
// every device's.
func AuthHintTag(key []byte, now time.Time, parts ...[]byte) []byte {
	var epoch [4]byte
	binary.BigEndian.PutUint32(epoch[:], uint32(now.Unix()/authEpochLen))
	hint := hmac.New(sha256.New, key)
	hint.Write([]byte("dnsauth2-hint"))
	hint.Write(epoch[:])
	tag := hmac.New(sha256.New, key)
	tag.Write([]byte("dnsauth2-tag"))
	tag.Write(epoch[:])
	for _, part := range parts {
		tag.Write(part)
	}
	return append(hint.Sum(nil)[:2], tag.Sum(nil)[:authTagLen-2]...)
}

// AuthTag is dnsauth-v1's tag of the message parts at time now (the node's: the device's clock with the skew the
// subscription gave), for the other tunnels that carry it (masterdns: nonce, frame).
func AuthTag(key []byte, now time.Time, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	var epoch [4]byte
	binary.BigEndian.PutUint32(epoch[:], uint32(now.Unix()/authEpochLen))
	mac.Write([]byte("dnsauth1"))
	mac.Write(epoch[:])
	for _, part := range parts {
		mac.Write(part)
	}
	return mac.Sum(nil)[:authTagLen]
}
