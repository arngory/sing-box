package security

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	baseCodec "masterdnsvpn-go/internal/basecodec"
)

// neko: dnsauth for masterdns (raycontrol docs/spec/dnsauth-masterdns.md §2). A tagger puts the device's tag before
// each query's frame, inside AES-GCM: the plaintext is tag (8) || frame, the tag
// HMAC-SHA256(K, "dnsauth1" || uint32_be(epoch) || nonce || frame)[:8] (the embedding program computes it: the key
// is the device's). The nonce under the tag keeps a seen frame from going out again under another nonce.

// AuthTagLen is the length of a query's tag.
const AuthTagLen = 8

// ErrAuthNeedsAEAD is a tag asked for under a method that does not authenticate the query (0-2): from a seen probe,
// flipping bits makes a new one without the key, and a tag under such a cipher says nothing (§3).
var ErrAuthNeedsAEAD = errors.New("dnsauth: needs DATA_ENCRYPTION_METHOD 3-5 (AES-GCM)")

// Tagger is the tag of a query's frame under its nonce.
type Tagger func(nonce, frame []byte) [AuthTagLen]byte

// randRead fills a nonce; tests set their own
var randRead = defaultRandRead

func defaultRandRead(b []byte) (int, error) { return rand.Read(b) }

// SetTagger makes the codec tag every query it encrypts.
func (c *Codec) SetTagger(tagger Tagger) error {
	if c == nil || c.aead == nil {
		return ErrAuthNeedsAEAD
	}
	if tagger == nil {
		c.encrypt = c.makeAESEncryptor(c.aead)
		return nil
	}
	c.encrypt = makeTaggedAESEncryptor(c.aead, tagger)
	return nil
}

func makeTaggedAESEncryptor(aead cipher.AEAD, tagger Tagger) func(dst, src []byte) ([]byte, error) {
	return func(dst, src []byte) ([]byte, error) {
		reqSize := aesNonceSize + AuthTagLen + len(src) + aead.Overhead()
		if cap(dst) < reqSize {
			dst = make([]byte, aesNonceSize, reqSize)
		} else {
			dst = dst[:aesNonceSize]
		}
		nonce := dst[:aesNonceSize]
		if _, err := randRead(nonce); err != nil {
			return nil, fmt.Errorf("generate aes-gcm nonce: %w", err)
		}
		tag := tagger(nonce, src)
		plain := make([]byte, 0, AuthTagLen+len(src))
		plain = append(append(plain, tag[:]...), src...)
		return aead.Seal(dst, nonce, plain, nil), nil
	}
}

// DecodeStringAndOpen is DecodeStringAndDecrypt keeping the query's nonce, for its tag: AES-GCM only.
func (c *Codec) DecodeStringAndOpen(data string) (nonce, plaintext []byte, err error) {
	if c == nil || c.aead == nil {
		return nil, nil, ErrAuthNeedsAEAD
	}
	decoded, err := baseCodec.DecodeString(data)
	if err != nil {
		return nil, nil, err
	}
	if len(decoded) <= aesNonceSize {
		return nil, nil, ErrInvalidCiphertext
	}
	plaintext, err = c.decrypt(nil, decoded)
	if err != nil {
		return nil, nil, err
	}
	return decoded[:aesNonceSize], plaintext, nil
}
