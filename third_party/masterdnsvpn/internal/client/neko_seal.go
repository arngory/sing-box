package client

import (
	"errors"
	"sync"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mdseal"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// neko: mdseal-v1 (raycontrol docs/spec/mdseal-v1.md). A client whose link gives the seal (NIKO_MDSEAL) asks for it
// with bit 7 of its probes' and SESSION_INIT's response mode byte, and opens every answer with the service's key; an
// answer whose seal does not hold is dropped as lost, never a reason to restart the session.

// configuredResponseMode is the response mode byte this client asks for: its encoding, bit 7 when it seals. A reset
// session asks for it again (upstream reset it to raw, so a base64 client could not read the next SESSION_ACCEPT).
func (c *Client) configuredResponseMode() uint8 {
	var mode uint8
	if c.cfg.BaseEncodeData {
		mode = mtuProbeBase64Reply
	}
	if c.sealKeys != nil {
		mode |= mdseal.ModeBit
	}
	return mode
}

// initSeal takes the seal from the config: the key's text as the link gives it (validated with the config).
func (c *Client) initSeal() {
	if c.cfg.NikoSeal == "" {
		return
	}
	keys, err := mdseal.NewKeys(c.cfg.EncryptionKey)
	if err != nil {
		// the config's validation asks for the key with the seal
		panic("masterdnsvpn: " + err.Error())
	}
	c.sealKeys = keys
	c.sealRequired = c.cfg.NikoSeal == "required"
}

// extractResponse is the packet an answer carries for the response mode mode (base64 by its low bit, sealed by bit 7).
//   - Sealed: the answer opened. In `optional` the node seals only what was asked for, so an open ERROR_DROP (to a
//     session it no longer knows) is taken; in `required` nothing open is.
//   - Open: as upstream, and an ERROR_DROP in the other encoding too: the node answers a session it does not know raw,
//     whatever the session's encoding.
func (c *Client) extractResponse(data []byte, mode uint8) (VpnProto.Packet, error) {
	base := mode&^mdseal.ModeBit == mtuProbeBase64Reply
	if mode&mdseal.ModeBit != 0 && c.sealKeys != nil {
		packet, q, err := DnsParser.ExtractSealedVPNResponse(data, base, c.sealKeys)
		if err == nil {
			return c.answerToOurs(packet, q)
		}
		if errors.Is(err, DnsParser.ErrTXTAnswerMissing) {
			return packet, err
		}
		// the ERROR_DROP to a session the node does not know comes raw: sealed in required, open in optional
		if drop, q, dropErr := DnsParser.ExtractSealedVPNResponse(data, !base, c.sealKeys); dropErr == nil &&
			drop.PacketType == Enums.PACKET_ERROR_DROP {
			return c.answerToOurs(drop, q)
		}
		if c.sealRequired {
			return packet, err
		}
		if drop, ok := openErrorDrop(data, base); ok {
			return c.answerToOurs(drop, DnsParser.QueryNameOf(data))
		}
		return packet, err
	}
	packet, err := DnsParser.ExtractVPNResponse(data, base)
	if err == nil || errors.Is(err, DnsParser.ErrTXTAnswerMissing) {
		return packet, err
	}
	if drop, ok := openErrorDrop(data, !base); ok {
		return drop, nil
	}
	return packet, err
}

// ErrNotOurs is a sealed answer whose question is no query this client sent lately: an answer seen on the path and
// sent again as it was (its question and seal with it), dropped as lost.
var ErrNotOurs = errors.New("masterdnsvpn: an answer to no query of ours")

// answerToOurs is packet when q is a query this client sent lately, else ErrNotOurs (mdseal-v1 §3, the reader). The
// seal binds an answer to its question; this binds the question to a query of this client's. A second answer to a
// query still waiting is a resolver's repeat, taken: the node answers each copy with what it has queued. An ERROR_DROP
// answers its query for good, so its repeat restarts nothing more.
func (c *Client) answerToOurs(packet VpnProto.Packet, q string) (VpnProto.Packet, error) {
	if q == "" || !c.sentQueries.has(q, time.Now()) {
		return VpnProto.Packet{}, ErrNotOurs
	}
	if packet.PacketType == Enums.PACKET_ERROR_DROP {
		c.sentQueries.forget(q)
	}
	return packet, nil
}

// noteSentQuery keeps the name of a query this client sends, when it seals: its answers are taken for sentQueryWindow
// to sentQueryWindow*2.
func (c *Client) noteSentQuery(query []byte) {
	if c.sealKeys == nil {
		return
	}
	if q := DnsParser.QueryNameOf(query); q != "" {
		c.sentQueries.note(q, time.Now())
	}
}

// sentQueries are the names of the queries a sealing client sent lately, in two generations of sentQueryWindow. The
// client alone writes them, so their bound only keeps memory: a generation full turns early.
type sentQueries struct {
	mu                sync.Mutex
	current, previous map[string]struct{}
	turnedAt          time.Time
}

const (
	// longer than any answer worth taking takes to come (a resolver's own timeout is seconds)
	sentQueryWindow = 30 * time.Second
	sentQueryCap    = 1 << 16
)

func (s *sentQueries) turnLocked(now time.Time) {
	if s.current == nil {
		s.current, s.previous, s.turnedAt = make(map[string]struct{}), make(map[string]struct{}), now
		return
	}
	if now.Sub(s.turnedAt) >= sentQueryWindow || len(s.current) >= sentQueryCap {
		s.previous, s.current, s.turnedAt = s.current, make(map[string]struct{}), now
	}
}

func (s *sentQueries) note(q string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turnLocked(now)
	s.current[q] = struct{}{}
}

// has is whether q was sent lately
func (s *sentQueries) has(q string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turnLocked(now)
	if _, ok := s.current[q]; ok {
		return true
	}
	_, ok := s.previous[q]
	return ok
}

// forget answers q for good
func (s *sentQueries) forget(q string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.current, q)
	delete(s.previous, q)
}

// openErrorDrop is an open ERROR_DROP in data, read in the encoding given first, then in the other
func openErrorDrop(data []byte, base bool) (VpnProto.Packet, bool) {
	for _, b := range []bool{base, !base} {
		if packet, err := DnsParser.ExtractVPNResponse(data, b); err == nil && packet.PacketType == Enums.PACKET_ERROR_DROP {
			return packet, true
		}
	}
	return VpnProto.Packet{}, false
}

// SetQueryTagger tags every query with the device's tag (neko: raycontrol docs/spec/dnsauth-masterdns.md §2), inside
// AES-GCM before the frame; the sizes the client computes count its 8 bytes. Before Run.
func (c *Client) SetQueryTagger(tagger security.Tagger) error {
	if err := c.codec.SetTagger(tagger); err != nil {
		return err
	}
	if tagger != nil {
		c.mtuCryptoOverhead = mtuCryptoOverhead(c.cfg.DataEncryptionMethod) + security.AuthTagLen
	}
	return nil
}
