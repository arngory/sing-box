package client

import (
	"errors"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mdseal"
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
		packet, err := DnsParser.ExtractSealedVPNResponse(data, base, c.sealKeys)
		if err == nil || errors.Is(err, DnsParser.ErrTXTAnswerMissing) {
			return packet, err
		}
		// the ERROR_DROP to a session the node does not know comes raw: sealed in required, open in optional
		if drop, dropErr := DnsParser.ExtractSealedVPNResponse(data, !base, c.sealKeys); dropErr == nil &&
			drop.PacketType == Enums.PACKET_ERROR_DROP {
			return drop, nil
		}
		if c.sealRequired {
			return packet, err
		}
		if drop, ok := openErrorDrop(data, base); ok {
			return drop, nil
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

// openErrorDrop is an open ERROR_DROP in data, read in the encoding given first, then in the other
func openErrorDrop(data []byte, base bool) (VpnProto.Packet, bool) {
	for _, b := range []bool{base, !base} {
		if packet, err := DnsParser.ExtractVPNResponse(data, b); err == nil && packet.PacketType == Enums.PACKET_ERROR_DROP {
			return packet, true
		}
	}
	return VpnProto.Packet{}, false
}
