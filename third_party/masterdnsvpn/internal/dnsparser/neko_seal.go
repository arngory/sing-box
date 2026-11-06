package dnsparser

import (
	"errors"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/mdseal"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// neko: mdseal-v1 (raycontrol docs/spec/mdseal-v1.md §3). An answer's frame F sealed into S = R || T || C lies in the
// TXT data where F lay, raw or in base64 as the session chose: one string while S fits one (255 bytes raw, 191 before
// base64), otherwise in parts as F is today, part 0 `00 N` and the start of S, part i `i` and the next bytes. S is
// cut by bytes: part 0 holds no frame header of its own. T covers the question's name (Q), so an answer seen on the
// path fits no other query.

// ErrSealTag is an answer whose seal does not hold: not the node's, another key, an open answer.
var ErrSealTag = errors.New("dns txt answer: the seal does not hold")

// BuildSealedVPNResponsePacket is BuildVPNResponsePacket with the frame sealed. S is padded to a multiple of
// mdseal.Block as far as the requester takes the answer (RequesterUDPSize) and, in a session, no longer than capS,
// the S of its probe answer at its download MTU (0: no cap, the probes' own answers). An answer too large even
// unpadded is built whole: FitRequester sends it truncated.
func BuildSealedVPNResponsePacket(questionPacket []byte, answerName string, packet VpnProto.Packet, baseEncode bool, keys *mdseal.Keys, capS int) ([]byte, error) {
	if keys == nil {
		return nil, mdseal.ErrNoKey
	}
	rawFrame, err := buildResponseFrame(packet)
	if err != nil {
		return nil, err
	}
	q, err := sealQueryName(questionPacket)
	if err != nil {
		return nil, err
	}
	layout, err := newAnswerLayout(questionPacket, answerName, baseEncode)
	if err != nil {
		return nil, err
	}
	least := mdseal.Overhead + len(rawFrame)
	room := mdseal.SealedLen(len(rawFrame), -1)
	if capS > 0 {
		room = min(room, max(capS, least))
	}
	// the longest S up to room whose answer the requester takes; the answer's length grows with S's
	if limit := RequesterUDPSize(questionPacket); layout.size(room) > limit {
		lo, hi := least, room
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if layout.size(mid) <= limit {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		room = lo
	}
	chunks, err := sealedTXTChunks(keys.Seal(q, rawFrame, room), baseEncode)
	if err != nil {
		return nil, err
	}
	return BuildTXTResponsePacket(questionPacket, answerName, chunks)
}

// SealedAnswerLen is the length of the answer to questionPacket that carries an S of sLen bytes, as
// BuildSealedVPNResponsePacket builds it.
func SealedAnswerLen(questionPacket []byte, answerName string, sLen int, baseEncode bool) (int, error) {
	layout, err := newAnswerLayout(questionPacket, answerName, baseEncode)
	if err != nil {
		return 0, err
	}
	return layout.size(sLen), nil
}

// answerLayout is what an answer's length is made of apart from its TXT data, as BuildTXTResponsePacket writes it.
type answerLayout struct {
	fixed      int // header, question, OPT
	nameLen    int
	pointable  bool // later answers point to the first one's owner name
	baseEncode bool
}

func newAnswerLayout(questionPacket []byte, answerName string, baseEncode bool) (answerLayout, error) {
	if len(questionPacket) < dnsHeaderSize {
		return answerLayout{}, ErrPacketTooShort
	}
	header := parseHeader(questionPacket)
	questionBytes, _, questionEndOffset := extractQuestionSection(questionPacket, header)
	optStart, optLen := findOPTRecordRange(questionPacket, header, questionEndOffset)
	nameBytes, err := responseAnswerNameBytes(questionPacket, answerName, len(questionBytes) > 0)
	if err != nil {
		return answerLayout{}, err
	}
	return answerLayout{
		fixed:      dnsHeaderSize + len(questionBytes) + len(answerOPT(questionPacket, optStart, optLen)),
		nameLen:    len(nameBytes),
		pointable:  len(nameBytes) > 2 && dnsHeaderSize+len(questionBytes) <= 0x3FFF,
		baseEncode: baseEncode,
	}, nil
}

// size is the answer's length for an S of sLen bytes: each part one TXT record of one string
func (l answerLayout) size(sLen int) int {
	parts := sealedPartLens(sLen, l.baseEncode)
	total := l.fixed
	for i, n := range parts {
		nameLen := l.nameLen
		if i > 0 && len(parts) > 1 && l.pointable {
			nameLen = 2
		}
		if l.baseEncode {
			n = baseCodec.EncodedRawBase64Len(n)
		}
		total += nameLen + 10 + 1 + n
	}
	return total
}

func sealedMaxChunk(baseEncode bool) int {
	if baseEncode {
		return maxTXTEncodedChunk
	}
	return maxTXTAnswerPayload
}

// sealedPartLens are the lengths of the parts S of sLen bytes goes in, their prefixes in
func sealedPartLens(sLen int, baseEncode bool) []int {
	maxChunk := sealedMaxChunk(baseEncode)
	if sLen <= maxChunk {
		return []int{sLen}
	}
	parts := []int{maxChunk}
	for rest := sLen - (maxChunk - 2); rest > 0; rest -= maxChunk - 1 {
		parts = append(parts, 1+min(rest, maxChunk-1))
	}
	return parts
}

// sealedTXTChunks are the TXT data of S: one string, or the parts with their prefixes
func sealedTXTChunks(s []byte, baseEncode bool) ([][]byte, error) {
	maxChunk := sealedMaxChunk(baseEncode)
	if len(s) <= maxChunk {
		return [][]byte{buildTXTAnswerChunk(s, baseEncode)}, nil
	}
	lens := sealedPartLens(len(s), baseEncode)
	if len(lens) > 255 {
		return nil, ErrTXTAnswerTooLarge
	}
	chunks := make([][]byte, 0, len(lens))
	cursor := 0
	for id, n := range lens {
		var part []byte
		if id == 0 {
			part = append([]byte{0, byte(len(lens))}, s[:n-2]...)
			cursor = n - 2
		} else {
			part = append([]byte{byte(id)}, s[cursor:cursor+n-1]...)
			cursor += n - 1
		}
		chunks = append(chunks, buildTXTAnswerChunk(part, baseEncode))
	}
	return chunks, nil
}

// ExtractSealedVPNResponse is the packet a sealed answer carries: S gathered from its parts, its seal checked and the
// frame inside parsed. ErrSealTag for an answer that is not sealed with keys.
func ExtractSealedVPNResponse(packet []byte, baseEncoded bool, keys *mdseal.Keys) (VpnProto.Packet, error) {
	if keys == nil {
		return VpnProto.Packet{}, mdseal.ErrNoKey
	}
	parsed, err := ParsePacket(packet)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	rawAnswers := extractTXTAnswerPayloads(parsed)
	if len(rawAnswers) == 0 {
		return VpnProto.Packet{}, ErrTXTAnswerMissing
	}
	if len(parsed.Questions) == 0 {
		return VpnProto.Packet{}, ErrTXTAnswerMalformed
	}
	s, err := assembleSealed(rawAnswers, baseEncoded)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	frame, ok := keys.Open(mdseal.QueryName(parsed.Questions[0].Name), s)
	if !ok {
		return VpnProto.Packet{}, ErrSealTag
	}
	return VpnProto.ParseInflated(frame)
}

// assembleSealed is S from an answer's TXT data: the one string, or parts 0…N−1 each once, in order
func assembleSealed(rawAnswers [][]byte, baseEncoded bool) ([]byte, error) {
	decode := func(raw []byte) ([]byte, error) {
		if baseEncoded {
			return baseCodec.DecodeRawBase64(raw)
		}
		return raw, nil
	}
	if len(rawAnswers) == 1 {
		return decode(rawAnswers[0])
	}
	var parts [256][]byte
	var seen [256]bool
	total := 0
	for _, raw := range rawAnswers {
		data, err := decode(raw)
		if err != nil {
			return nil, err
		}
		if len(data) < 1 {
			return nil, ErrTXTAnswerMalformed
		}
		id := int(data[0])
		if id == 0 {
			if len(data) < 2 {
				return nil, ErrTXTAnswerMalformed
			}
			total = int(data[1])
			data = data[2:]
		} else {
			data = data[1:]
		}
		if seen[id] {
			return nil, ErrTXTAnswerMalformed
		}
		seen[id], parts[id] = true, data
	}
	if total < 2 || total != len(rawAnswers) {
		return nil, ErrTXTAnswerMalformed
	}
	size := 0
	for id := range total {
		if !seen[id] {
			return nil, ErrTXTAnswerMalformed
		}
		size += len(parts[id])
	}
	s := make([]byte, 0, size)
	for id := range total {
		s = append(s, parts[id]...)
	}
	return s, nil
}

// sealQueryName is Q of the answer to questionPacket: its first question's name, as the parser gives it (lower case
// ASCII, no trailing dot) and the reader folds it
func sealQueryName(questionPacket []byte) (string, error) {
	lite, err := ParsePacketLite(questionPacket)
	if err != nil {
		return "", err
	}
	if !lite.HasQuestion {
		return "", ErrTXTAnswerMalformed
	}
	return mdseal.QueryName(lite.FirstQuestion.Name), nil
}
