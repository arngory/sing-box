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

// nekoMTUDownQuery is a client's MTU_DOWN_REQ for an answer of size bytes, raw, with an OPT of edns.
func nekoMTUDownQuery(t *testing.T, codec *security.Codec, size int, edns uint16) []byte {
	t.Helper()
	payload := make([]byte, mtuProbeDownMinSize)
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

// neko: an MTU probe asks no more than a session may take; what the server answers goes within its requester's size.
func TestNekoMTUDownBounded(t *testing.T) {
	server, codec := nekoTestServer(t, map[string]any{"MAX_ALLOWED_CLIENT_DOWNLOAD_MTU": 1232})

	answer := server.handlePacket(nekoMTUDownQuery(t, codec, 1000, 4096))
	packet, err := DnsParser.ExtractVPNResponse(answer, false)
	if err != nil || packet.PacketType != Enums.PACKET_MTU_DOWN_RES || len(packet.Payload) != 1000 {
		t.Fatalf("probe for 1000: %v %d %d", err, packet.PacketType, len(packet.Payload))
	}
	// past the session's most: no answer but an empty one (as for a probe past 4096 before)
	for _, size := range []int{1233, 4096} {
		answer := server.handlePacket(nekoMTUDownQuery(t, codec, size, 4096))
		if len(answer) < 12 || binary.BigEndian.Uint16(answer[6:8]) != 0 || len(answer) > 200 {
			t.Fatalf("probe for %d: %d bytes", size, len(answer))
		}
	}
	// the default before: 4096 bytes of answer to a query of about 100
	wide, codec := nekoTestServer(t, nil)
	query := nekoMTUDownQuery(t, codec, 4096, 4096)
	if answer := wide.handlePacket(query); len(answer) < 4096 {
		t.Fatalf("server default: %d bytes", len(answer))
	}

	// a requester of 1232: the probe's answer for 1200 does not fit it and goes as TC
	query = nekoMTUDownQuery(t, codec, 1200, 1232)
	answer = DnsParser.FitRequester(query, server.handlePacket(query))
	if len(answer) > 1232 || answer[2]&0x02 == 0 || binary.BigEndian.Uint16(answer[6:8]) != 0 {
		t.Fatalf("to a requester of 1232: %d bytes, flags % x", len(answer), answer[2:4])
	}
}
