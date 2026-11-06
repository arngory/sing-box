package udpserver

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"

	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const nekoTestDomain = "t.example.com"

func nekoTestServer(t *testing.T, values map[string]any) (*Server, *security.Codec) {
	t.Helper()
	base := map[string]any{"DOMAIN": []string{nekoTestDomain}, "PROTOCOL_TYPE": "TCP", "DATA_ENCRYPTION_METHOD": 5}
	for key, value := range values {
		base[key] = value
	}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadServerConfigFromJSONBase64WithOverrides(base64.StdEncoding.EncodeToString(raw), config.ServerConfigOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := security.NewCodec(5, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, logger.NewWithWriter("test", "ERROR", io.Discard), codec), codec
}

// nekoMTUDownQuery is a client's MTU_DOWN_REQ for an answer of size bytes, raw, its payload padded to pad bytes (a
// client pads it to its upload MTU), with an OPT of edns.
func nekoMTUDownQuery(t *testing.T, codec *security.Codec, size, pad int, edns uint16) []byte {
	t.Helper()
	payload := make([]byte, max(mtuProbeDownMinSize, pad))
	payload[0] = mtuProbeModeRaw
	copy(payload[1:], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(payload[mtuProbeUpMinSize:], uint16(size))
	frame, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		SessionID: 255, PacketType: Enums.PACKET_MTU_DOWN_REQ, StreamID: 1, SequenceNum: 1, TotalFragments: 1, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := codec.EncryptAndEncodeBytes(frame)
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTunnelTXTQuestionPacket(nekoTestDomain, encoded, Enums.DNS_RECORD_TYPE_TXT, edns)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

// neko: an MTU probe asks no more than a session may take, nor more than 4 times its query; what the server answers
// goes within its requester's size.
func TestNekoMTUDownBounded(t *testing.T) {
	server, codec := nekoTestServer(t, map[string]any{"MAX_ALLOWED_CLIENT_DOWNLOAD_MTU": 1232})

	// as Niko probes: padded to its upload MTU
	query := nekoMTUDownQuery(t, codec, 1000, 100, 4096)
	if len(query) < 250 {
		t.Fatalf("padded probe of %d bytes", len(query))
	}
	answer := server.handlePacket(query)
	packet, err := DnsParser.ExtractVPNResponse(answer, false)
	if err != nil || packet.PacketType != Enums.PACKET_MTU_DOWN_RES || len(packet.Payload) != 1000 {
		t.Fatalf("probe for 1000: %v %d %d", err, packet.PacketType, len(packet.Payload))
	}
	nekoEmpty := func(name string, answer []byte) {
		t.Helper()
		if len(answer) < 12 || binary.BigEndian.Uint16(answer[6:8]) != 0 || len(answer) > len(query)+64 {
			t.Fatalf("%s: %d bytes", name, len(answer))
		}
	}
	// past the session's most: the empty answer (as for a probe past 4096 before)
	nekoEmpty("probe for 1233", server.handlePacket(nekoMTUDownQuery(t, codec, 1233, 100, 4096)))
	nekoEmpty("probe for 4096", server.handlePacket(nekoMTUDownQuery(t, codec, 4096, 100, 4096)))
	// a probe crafted short (about 100 bytes) gets 4 times its query at most
	short := nekoMTUDownQuery(t, codec, 1000, 0, 4096)
	nekoEmpty("short probe for 1000", server.handlePacket(short))
	if _, err := DnsParser.ExtractVPNResponse(server.handlePacket(nekoMTUDownQuery(t, codec, 4*len(short)-8, 0, 4096)), false); err != nil {
		t.Fatalf("short probe within 4 times: %v", err)
	}
	// the server's own default, 4096, bounds a probe by its query all the same
	wide, codec := nekoTestServer(t, nil)
	nekoEmpty("probe for 4000 of a server of 4096", wide.handlePacket(nekoMTUDownQuery(t, codec, 4000, 100, 4096)))

	// a requester of 1232: the probe's answer for 1000 does not fit it and goes as TC
	query = nekoMTUDownQuery(t, codec, 1000, 100, 1232)
	answer = server.handlePacket(query)
	if len(answer) <= 1232 {
		t.Fatalf("answer of %d bytes", len(answer))
	}
	answer = DnsParser.FitRequester(query, answer)
	if len(answer) > 1232 || answer[2]&0x02 == 0 || binary.BigEndian.Uint16(answer[6:8]) != 0 {
		t.Fatalf("to a requester of 1232: %d bytes, flags % x", len(answer), answer[2:4])
	}
}

// neko: the answer's owner name points to the question (C0 0C), as every DNS server answers.
func TestNekoAnswerNamePointer(t *testing.T) {
	server, codec := nekoTestServer(t, nil)
	query := nekoMTUDownQuery(t, codec, 200, 100, 4096)
	answer := server.handlePacket(query)
	questionEnd := len(query) - 11 // the query's OPT is 11 bytes
	if len(answer) < questionEnd+2 || answer[questionEnd] != 0xC0 || answer[questionEnd+1] != 12 {
		t.Fatalf("owner name % x", answer[questionEnd:questionEnd+2])
	}
	if _, err := DnsParser.ExtractVPNResponse(answer, false); err != nil {
		t.Fatal(err)
	}
}
