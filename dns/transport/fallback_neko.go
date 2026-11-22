package transport

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// The fallback DNS server is a neko addition. It asks other DNS servers in
// the order given and moves on to the next when one fails: an error, no
// answer within the timeout, or an answer of SERVFAIL, REFUSED and the like.
// NOERROR (an empty one too) and NXDOMAIN are answers and end the query.
//
// A server that has just failed outright (an error or a timeout, not an
// rcode) and was followed by one that answered is skipped for a while: for
// fallbackStickyDuration queries go to the server that answered first, so a
// dead first server does not add its timeout to every query. After that the
// order given is tried again.

const (
	fallbackDefaultTimeout = 4 * time.Second
	fallbackStickyDuration = 5 * time.Minute
)

var _ adapter.DNSTransport = (*FallbackTransport)(nil)

func RegisterFallback(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.FallbackDNSServerOptions](registry, C.DNSTypeFallback, NewFallback)
}

type FallbackTransport struct {
	dns.TransportAdapter
	logger         logger.ContextLogger
	manager        adapter.DNSTransportManager
	serverTags     []string
	timeout        time.Duration
	stickyDuration time.Duration
	now            func() time.Time

	servers []adapter.DNSTransport

	access         sync.Mutex
	preferred      int
	preferredUntil time.Time
}

func NewFallback(ctx context.Context, logger log.ContextLogger, tag string, options option.FallbackDNSServerOptions) (adapter.DNSTransport, error) {
	if len(options.Servers) == 0 {
		return nil, E.New("missing servers")
	}
	seen := make(map[string]bool, len(options.Servers))
	for _, serverTag := range options.Servers {
		if serverTag == "" {
			return nil, E.New("empty server tag")
		}
		if serverTag == tag {
			return nil, E.New("server lists itself: ", serverTag)
		}
		if seen[serverTag] {
			return nil, E.New("duplicate server: ", serverTag)
		}
		seen[serverTag] = true
	}
	timeout := time.Duration(options.Timeout)
	if timeout < 0 {
		return nil, E.New("negative timeout")
	}
	if timeout == 0 {
		timeout = fallbackDefaultTimeout
	}
	serverTags := slices.Clone([]string(options.Servers))
	return &FallbackTransport{
		TransportAdapter: dns.NewTransportAdapter(C.DNSTypeFallback, tag, serverTags),
		logger:           logger,
		manager:          service.FromContext[adapter.DNSTransportManager](ctx),
		serverTags:       serverTags,
		timeout:          timeout,
		stickyDuration:   fallbackStickyDuration,
		now:              time.Now,
	}, nil
}

func (t *FallbackTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if t.manager == nil {
		return E.New("missing DNS transport manager")
	}
	servers := make([]adapter.DNSTransport, 0, len(t.serverTags))
	for _, serverTag := range t.serverTags {
		server, loaded := t.manager.Transport(serverTag)
		if !loaded {
			return E.New("server not found: ", serverTag)
		}
		if server.Type() == C.DNSTypeFakeIP {
			return E.New("server is fakeip: ", serverTag)
		}
		servers = append(servers, server)
	}
	t.servers = servers
	return nil
}

// Reset forgets the server that was skipped: after a change of network the
// first server may well answer again. The servers are reset on their own.
func (t *FallbackTransport) Reset() {
	t.access.Lock()
	t.preferred = 0
	t.preferredUntil = time.Time{}
	t.access.Unlock()
}

func (t *FallbackTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

func (t *FallbackTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	servers := t.servers
	if len(servers) == 0 {
		return nil, E.New("fallback DNS server not started")
	}
	order := t.order(len(servers))
	var (
		firstResponse *mDNS.Msg
		errors        []error
		serverFailed  bool
	)
	for i, index := range order {
		err := ctx.Err()
		if err != nil {
			return nil, err
		}
		server := servers[index]
		response, err := t.exchangeOne(ctx, server, message, i < len(order)-1)
		if err == nil && fallbackAccepts(response) {
			if i > 0 {
				t.answered(ctx, index, serverFailed)
			}
			return response, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			serverFailed = true
			t.logger.DebugContext(ctx, "server[", server.Tag(), "] failed: ", err)
			errors = append(errors, E.Cause(err, "server[", server.Tag(), "]"))
			continue
		}
		t.logger.DebugContext(ctx, "server[", server.Tag(), "] answered ", mDNS.RcodeToString[response.Rcode])
		if firstResponse == nil {
			firstResponse = response
		}
	}
	if firstResponse != nil {
		return firstResponse, nil
	}
	return nil, E.Errors(errors...)
}

// order is the order the servers are tried in for one query: the one that
// answered after a failure first while that is remembered, then the rest in
// the order given.
func (t *FallbackTransport) order(count int) []int {
	t.access.Lock()
	preferred := t.preferred
	if preferred != 0 && !t.now().Before(t.preferredUntil) {
		t.preferred = 0
		t.preferredUntil = time.Time{}
		preferred = 0
	}
	t.access.Unlock()
	if preferred >= count {
		preferred = 0
	}
	order := make([]int, 0, count)
	order = append(order, preferred)
	for i := 0; i < count; i++ {
		if i != preferred {
			order = append(order, i)
		}
	}
	return order
}

// answered records that the server at index answered after the ones tried
// before it did not.
func (t *FallbackTransport) answered(ctx context.Context, index int, serverFailed bool) {
	t.access.Lock()
	defer t.access.Unlock()
	if index == 0 {
		if t.preferred != 0 {
			t.logger.DebugContext(ctx, "server[", t.serverTags[0], "] answers again")
		}
		t.preferred = 0
		t.preferredUntil = time.Time{}
		return
	}
	if !serverFailed || t.preferred == index {
		return
	}
	t.preferred = index
	t.preferredUntil = t.now().Add(t.stickyDuration)
	t.logger.InfoContext(ctx, "server[", t.serverTags[index], "] is used first for ", t.stickyDuration, ", the servers before it failed")
}

type fallbackResult struct {
	response *mDNS.Msg
	err      error
}

func (t *FallbackTransport) exchangeOne(ctx context.Context, server adapter.DNSTransport, message *mDNS.Msg, limited bool) (*mDNS.Msg, error) {
	var (
		exchangeCtx context.Context
		cancel      context.CancelFunc
	)
	if limited {
		exchangeCtx, cancel = context.WithTimeout(ctx, t.timeout)
	} else {
		exchangeCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	resultCh := make(chan fallbackResult, 1)
	server.ExchangeAsync(exchangeCtx, message.Copy(), func(response *mDNS.Msg, err error) {
		select {
		case resultCh <- fallbackResult{response, err}:
		default:
		}
	})
	select {
	case result := <-resultCh:
		return fallbackResultOf(result)
	case <-exchangeCtx.Done():
		select {
		case result := <-resultCh:
			return fallbackResultOf(result)
		default:
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, E.Cause(exchangeCtx.Err(), "no answer within ", t.timeout)
	}
}

func fallbackResultOf(result fallbackResult) (*mDNS.Msg, error) {
	if result.err != nil {
		return nil, result.err
	}
	if result.response == nil {
		return nil, E.New("empty response")
	}
	return result.response, nil
}

// fallbackAccepts tells an answer from a failure: NOERROR, an empty one
// too, and NXDOMAIN are answers; SERVFAIL, REFUSED and the other rcodes say
// the server could not answer, so the next server is asked.
func fallbackAccepts(response *mDNS.Msg) bool {
	return response.Rcode == mDNS.RcodeSuccess || response.Rcode == mDNS.RcodeNameError
}
