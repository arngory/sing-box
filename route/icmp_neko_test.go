package route

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// With route.icmp_no_local_reply an echo no outbound takes is refused; one an outbound carries, one a rule already
// refused or bypassed, and TCP and UDP left to the stack stay as they were. Without the option nothing changes.
func TestNekoICMPNoLocalReply(t *testing.T) {
	left := adapter.PreMatchResult{Action: adapter.PreMatchContinue}
	for _, c := range []struct {
		name    string
		option  bool
		network string
		result  adapter.PreMatchResult
		want    adapter.PreMatchAction
	}{
		{"an echo nobody carries", true, N.NetworkICMP, left, adapter.PreMatchReject},
		{"the same without the option", false, N.NetworkICMP, left, adapter.PreMatchContinue},
		{"an echo an outbound carries", true, N.NetworkICMP, adapter.PreMatchResult{Action: adapter.PreMatchFlow}, adapter.PreMatchFlow},
		{"an echo bypassed", true, N.NetworkICMP, adapter.PreMatchResult{Action: adapter.PreMatchBypass}, adapter.PreMatchBypass},
		{"an echo dropped by a rule", true, N.NetworkICMP, adapter.PreMatchResult{Action: adapter.PreMatchDrop}, adapter.PreMatchDrop},
		{"TCP left to the stack", true, N.NetworkTCP, left, adapter.PreMatchContinue},
		{"UDP left to the stack", true, N.NetworkUDP, left, adapter.PreMatchContinue},
	} {
		if got := icmpUnanswered(c.option, c.network, c.result).Action; got != c.want {
			t.Errorf("%s: action %v, want %v", c.name, got, c.want)
		}
	}
}
