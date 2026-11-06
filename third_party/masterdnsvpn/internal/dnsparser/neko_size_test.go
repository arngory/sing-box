package dnsparser

import (
	"bytes"
	"encoding/binary"
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestNekoRequesterUDPSize(t *testing.T) {
	plain, err := BuildTXTQuestionPacket("a.example.com", Enums.DNS_RECORD_TYPE_TXT, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := RequesterUDPSize(plain); got != 512 {
		t.Fatalf("no OPT: %d", got)
	}
	for size, want := range map[uint16]int{1232: 1232, 4096: 4096, 100: 512} {
		query, err := BuildTXTQuestionPacket("a.example.com", Enums.DNS_RECORD_TYPE_TXT, size)
		if err != nil {
			t.Fatal(err)
		}
		if got := RequesterUDPSize(query); got != want {
			t.Fatalf("OPT %d: %d, want %d", size, got, want)
		}
	}
	if got := RequesterUDPSize([]byte{1, 2, 3}); got != 512 {
		t.Fatalf("short: %d", got)
	}
}

func TestNekoFitRequester(t *testing.T) {
	query, err := BuildTXTQuestionPacket("a.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	small, err := BuildTXTResponsePacket(query, "a.example.com", [][]byte{bytes.Repeat([]byte{'x'}, 200)})
	if err != nil {
		t.Fatal(err)
	}
	if got := FitRequester(query, small); !bytes.Equal(got, small) {
		t.Fatal("an answer that fits was changed")
	}
	large, err := BuildTXTResponsePacket(query, "a.example.com", [][]byte{
		bytes.Repeat([]byte{'x'}, 255), bytes.Repeat([]byte{'y'}, 255), bytes.Repeat([]byte{'z'}, 255),
		bytes.Repeat([]byte{'w'}, 255), bytes.Repeat([]byte{'v'}, 255),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(large) <= 1232 {
		t.Fatalf("answer of %d bytes", len(large))
	}
	cut := FitRequester(query, large)
	if len(cut) > 1232 || len(cut) >= len(large) {
		t.Fatalf("cut to %d bytes", len(cut))
	}
	header := parseHeader(cut)
	if header.ID != parseHeader(query).ID || header.QR != 1 || header.TC != 1 || header.QDCount != 1 ||
		header.ANCount != 0 || header.NSCount != 0 || header.ARCount != 1 {
		t.Fatalf("header %+v", header)
	}
	// the question as asked, the query's OPT after it
	queryEnd, _ := skipQuestions(query, dnsHeaderSize, 1)
	cutEnd, _ := skipQuestions(cut, dnsHeaderSize, 1)
	if !bytes.Equal(cut[dnsHeaderSize:cutEnd], query[dnsHeaderSize:queryEnd]) {
		t.Fatal("question changed")
	}
	if RequesterUDPSize(cut) != 1232 || binary.BigEndian.Uint16(cut[2:4])&0x000f != 0 {
		t.Fatal("OPT or RCODE lost")
	}
	// to a requester without an OPT: 512, and no OPT in the cut answer
	plain, _ := BuildTXTQuestionPacket("a.example.com", Enums.DNS_RECORD_TYPE_TXT, 0)
	medium, _ := BuildTXTResponsePacket(plain, "a.example.com", [][]byte{bytes.Repeat([]byte{'x'}, 255), bytes.Repeat([]byte{'y'}, 255)})
	if len(medium) <= 512 {
		t.Fatalf("answer of %d bytes", len(medium))
	}
	if cut := FitRequester(plain, medium); len(cut) > 512 || parseHeader(cut).TC != 1 || parseHeader(cut).ARCount != 0 {
		t.Fatalf("no OPT: %d bytes, %+v", len(cut), parseHeader(cut))
	}
	// a large answer whose question runs past its end
	broken := bytes.Repeat([]byte{0x3f}, 2000)
	copy(broken, []byte{0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0})
	if FitRequester(query, broken) != nil {
		t.Fatal("a large answer that does not parse was sent")
	}
}

// neko: answers in several chunks size the packet as they write it, whatever the owner name: the pointer to the
// question, the name of another (pointed to by the later answers), the root.
func TestNekoTXTAnswersExact(t *testing.T) {
	query, err := BuildTXTQuestionPacket("a.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	chunks := [][]byte{bytes.Repeat([]byte{'x'}, 100), bytes.Repeat([]byte{'y'}, 100), bytes.Repeat([]byte{'z'}, 100)}
	for _, name := range []string{"a.example.com", "b.example.com", "."} {
		answer, err := BuildTXTResponsePacket(query, name, chunks)
		if err != nil {
			t.Fatal(name, err)
		}
		if _, err := ParseDNSDatagramLite(answer); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		parsed, err := ParsePacket(answer)
		if err != nil || len(parsed.Answers) != 3 {
			t.Fatalf("%s: %v, %d answers", name, err, len(parsed.Answers))
		}
	}
}

// neko: an answer's OPT is the responder's: the root, 1232, the query's DO bit, no options; the query's own (here a
// client cookie, which echoed alone is a malformed COOKIE) never goes back.
func TestNekoAnswerOPT(t *testing.T) {
	plain, err := BuildTXTQuestionPacket("a.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for _, do := range []bool{true, false} {
		// the query's OPT (its last 11 bytes) with DO, and a COOKIE option of a client cookie
		query := append([]byte(nil), plain...)
		opt := query[len(query)-11:]
		if do {
			opt[7] |= 0x80
		}
		binary.BigEndian.PutUint16(opt[9:11], 12)
		query = append(query, 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8)
		if RequesterUDPSize(query) != 4096 {
			t.Fatal("query's OPT")
		}
		single, err := BuildTXTResponsePacket(query, "a.example.com", [][]byte{[]byte("x")})
		if err != nil {
			t.Fatal(err)
		}
		multi, err := BuildTXTResponsePacket(query, "a.example.com", [][]byte{[]byte("x"), []byte("y")})
		if err != nil {
			t.Fatal(err)
		}
		empty, err := BuildEmptyNoErrorResponse(query)
		if err != nil {
			t.Fatal(err)
		}
		large, err := BuildTXTResponsePacket(query, "a.example.com", [][]byte{bytes.Repeat([]byte{'x'}, 255), bytes.Repeat([]byte{'y'}, 255)})
		if err != nil {
			t.Fatal(err)
		}
		small := append([]byte(nil), query...)
		binary.BigEndian.PutUint16(small[len(small)-12-11+3:], 512) // the query's size to 512: its answer cut
		cut := FitRequester(small, large)
		if parseHeader(cut).TC != 1 {
			t.Fatal("not cut")
		}
		want := []byte{0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0}
		if do {
			want[7] = 0x80
		}
		for name, answer := range map[string][]byte{"single": single, "multi": multi, "empty": empty, "cut": cut} {
			if _, err := ParseDNSDatagramLite(answer); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !bytes.Equal(answer[len(answer)-11:], want) || parseHeader(answer).ARCount != 1 {
				t.Fatalf("%s (DO %v): OPT % x", name, do, answer[len(answer)-11:])
			}
		}
	}
}
