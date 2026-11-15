package knock

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// relay-v1 §3 (raycontrol TestDerivedKeyVectors), checked outside Go too
func TestRelayKeyVector(t *testing.T) {
	device := make([]byte, 32)
	exit := make([]byte, 16)
	relay := make([]byte, 16)
	for i := range device {
		device[i] = byte(i)
	}
	for i := range exit {
		exit[i], relay[i] = 0xa0+byte(i), 0xb0+byte(i)
	}
	key, err := RelayKey(device, exit, relay, "r1")
	if err != nil || hex.EncodeToString(key) != "6e84ab4641da09239a34c5b76756ecd3787291e57d2eb34ece0433bee3a1a504" {
		t.Fatalf("%x %v", key, err)
	}
	// the relay's parameters: the device key gives way to K_relay
	o := SPAv2Options{NodeID: hex.EncodeToString(relay), EpochLen: 600, SlotLen: 30, PortKey: hex.EncodeToString(make([]byte, 32)),
		PortBase: 20000, PortRange: 1000, LenMin: 96, LenMax: 160, DeviceKey: hex.EncodeToString(device),
		Relay: &SPARelay{ExitNodeID: hex.EncodeToString(exit), ID: "r1"}}
	p, err := parseSPAv2(o)
	if err != nil || !bytes.Equal(p.deviceKey[:], key) {
		t.Fatalf("%x %v", p.deviceKey, err)
	}
	o.Relay.ID = ""
	if _, err = parseSPAv2(o); err == nil {
		t.Fatal("a relay without an id")
	}
}
