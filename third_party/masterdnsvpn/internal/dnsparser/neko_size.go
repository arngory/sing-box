package dnsparser

import "encoding/binary"

// neko: an answer within its requester's size. The most the sender of a query takes over UDP is its OPT's size, at
// least 512, and 512 without an OPT (RFC 6891 §6.2.3, §6.2.5). A larger answer goes as TC with its question and the
// OPT and no records, as niko-server's DNS front sends it: masterdns answered its MTU probes with kilobytes whatever
// the requester took.

const minRequesterUDPSize = 512

const flagTruncated uint16 = 1 << 9

// RequesterUDPSize is the most the query's sender takes over UDP.
func RequesterUDPSize(query []byte) int {
	if len(query) < dnsHeaderSize {
		return minRequesterUDPSize
	}
	header := parseHeader(query)
	questionEnd, err := skipQuestions(query, dnsHeaderSize, int(header.QDCount))
	if err != nil {
		return minRequesterUDPSize
	}
	start, length := findOPTRecordRange(query, header, questionEnd)
	if length == 0 {
		return minRequesterUDPSize
	}
	nameEnd, err := skipName(query, start)
	if err != nil || nameEnd+4 > len(query) {
		return minRequesterUDPSize
	}
	return max(minRequesterUDPSize, int(binary.BigEndian.Uint16(query[nameEnd+2:nameEnd+4])))
}

// FitRequester is the answer as the query's sender takes it: the answer itself when it fits, otherwise its header with
// TC set, its question and the OPT, no records. Nil when an answer too large does not parse.
func FitRequester(query, answer []byte) []byte {
	if len(answer) <= RequesterUDPSize(query) {
		return answer
	}
	return truncatedAnswer(query, answer)
}

func truncatedAnswer(query, answer []byte) []byte {
	if len(answer) < dnsHeaderSize || len(query) < dnsHeaderSize {
		return nil
	}
	header := parseHeader(answer)
	questionEnd, err := skipQuestions(answer, dnsHeaderSize, int(header.QDCount))
	if err != nil {
		return nil
	}
	queryHeader := parseHeader(query)
	var opt []byte
	if queryQuestionEnd, err := skipQuestions(query, dnsHeaderSize, int(queryHeader.QDCount)); err == nil {
		start, length := findOPTRecordRange(query, queryHeader, queryQuestionEnd)
		opt = answerOPT(query, start, length)
	}
	out := make([]byte, 0, questionEnd+len(opt))
	out = append(out, answer[:dnsHeaderSize]...)
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(answer[2:4])|flagTruncated)
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], uint16(getARCount(len(opt))))
	out = append(out, answer[dnsHeaderSize:questionEnd]...)
	return append(out, opt...)
}

// responderUDPSize is the size an answer's OPT gives as this server's (what most servers give since 2020).
const responderUDPSize = 1232

// answerOPT is the OPT of an answer to a query whose OPT is query[start:start+length], nil without one (neko). It is
// the responder's (RFC 6891 §6.1.2, §7): the root, responderUDPSize, the query's DO bit (RFC 3225 §3), no options.
// Upstream echoed the query's OPT whole, options and all: an echoed client cookie without a server cookie is a
// malformed COOKIE, for which a resolver must discard the answer (RFC 7873 §5.3), and an echo is a mark.
func answerOPT(query []byte, start, length int) []byte {
	if length == 0 {
		return nil
	}
	opt := []byte{0, 0, 41, responderUDPSize >> 8, responderUDPSize & 0xff, 0, 0, 0, 0, 0, 0}
	// the OPT's TTL: extended RCODE, version, then the flags, DO their first bit
	if nameEnd, err := skipName(query, start); err == nil && nameEnd+8 <= start+length && nameEnd+8 <= len(query) {
		opt[7] = query[nameEnd+6] & 0x80
	}
	return opt
}
