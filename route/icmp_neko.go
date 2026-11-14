package route

import (
	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// icmpUnanswered is what becomes of a flow's verdict with route.icmp_no_local_reply (neko): an echo request that
// no rule sends to an outbound carrying ICMP (direct, a naive with icmp) is left to the TUN, which answers it
// itself in the destination's name. With the option it is refused instead: nothing comes back on the gVisor stack,
// an unreachable on the system one. Everything else stays as the rules made it.
func icmpUnanswered(noLocalReply bool, network string, result adapter.PreMatchResult) adapter.PreMatchResult {
	if noLocalReply && network == N.NetworkICMP && result.Action == adapter.PreMatchContinue {
		return adapter.PreMatchResult{Action: adapter.PreMatchReject}
	}
	return result
}
