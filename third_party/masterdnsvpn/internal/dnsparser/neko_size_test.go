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
