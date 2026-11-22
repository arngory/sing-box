package transport

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type fallbackFakeBehaviour int

const (
	fallbackFakeAnswer fallbackFakeBehaviour = iota
	fallbackFakeError
	fallbackFakeHang
	fallbackFakeRcode
	// an rcode as an error, as tailscale's, openvpn's and the platforms' local transports give it
	fallbackFakeRcodeError
)

type fallbackFakeServer struct {
	tag           string
	transportType string
	address       netip.Addr

	access    sync.Mutex
	behaviour fallbackFakeBehaviour
	rcode     int
	delay     time.Duration
	queries   atomic.Int32
}

func (s *fallbackFakeServer) set(behaviour fallbackFakeBehaviour, rcode int) {
	s.access.Lock()
	s.behaviour = behaviour
	s.rcode = rcode
	s.access.Unlock()
}

func (s *fallbackFakeServer) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (s *fallbackFakeServer) Type() string {
	if s.transportType != "" {
		return s.transportType
	}
	return "fake"
}

func (s *fallbackFakeServer) Tag() string            { return s.tag }
func (s *fallbackFakeServer) Dependencies() []string { return nil }
func (s *fallbackFakeServer) Reset()                 {}

func (s *fallbackFakeServer) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	s.queries.Add(1)
	s.access.Lock()
	behaviour, rcode, delay := s.behaviour, s.rcode, s.delay
	s.access.Unlock()
	if behaviour == fallbackFakeHang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	switch behaviour {
	case fallbackFakeError:
		return nil, errors.New(s.tag + " is down")
	case fallbackFakeRcode:
		return boxDNS.FixedResponseStatus(message, rcode), nil
	case fallbackFakeRcodeError:
		return nil, boxDNS.RcodeError(rcode)
	default:
		return boxDNS.FixedResponse(message.Id, message.Question[0], []netip.Addr{s.address}, 300), nil
	}
}

func (s *fallbackFakeServer) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(s.Exchange(ctx, message))
	}()
}

type fallbackFakeManager struct {
	adapter.DNSTransportManager
	transports map[string]adapter.DNSTransport
}

func (m *fallbackFakeManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}

type fallbackClock struct {
	access sync.Mutex
	now    time.Time
}

func (c *fallbackClock) Now() time.Time {
	c.access.Lock()
	defer c.access.Unlock()
	return c.now
}

func (c *fallbackClock) Advance(duration time.Duration) {
	c.access.Lock()
	c.now = c.now.Add(duration)
	c.access.Unlock()
}

type fallbackFixture struct {
	transport *FallbackTransport
	servers   []*fallbackFakeServer
	clock     *fallbackClock
}

func newFallbackFixture(t *testing.T, timeout time.Duration, count int) *fallbackFixture {
	t.Helper()
	manager := &fallbackFakeManager{transports: make(map[string]adapter.DNSTransport)}
	var (
		servers []*fallbackFakeServer
		tags    []string
	)
	for i := 0; i < count; i++ {
		server := &fallbackFakeServer{
			tag:     "server-" + string(rune('a'+i)),
			address: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}),
		}
		servers = append(servers, server)
		tags = append(tags, server.tag)
		manager.transports[server.tag] = server
	}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	rawTransport, err := NewFallback(ctx, log.NewNOPFactory().Logger(), "fallback", option.FallbackDNSServerOptions{
		Servers: tags,
		Timeout: badoption.Duration(timeout),
	})
	require.NoError(t, err)
	transport := rawTransport.(*FallbackTransport)
	clock := &fallbackClock{now: time.Unix(1700000000, 0)}
	transport.now = clock.Now
	require.NoError(t, transport.Start(adapter.StartStateInitialize, nil))
	require.Equal(t, tags, transport.Dependencies())
	return &fallbackFixture{transport: transport, servers: servers, clock: clock}
}

func fallbackQuery() *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	return message
}

// answeredBy tells which fake server an answer came from.
func (f *fallbackFixture) answeredBy(t *testing.T, response *mDNS.Msg) string {
	t.Helper()
	require.NotNil(t, response)
	require.Len(t, response.Answer, 1)
	address, ok := netip.AddrFromSlice(response.Answer[0].(*mDNS.A).A)
	require.True(t, ok)
	for _, server := range f.servers {
		if server.address == address.Unmap() {
			return server.tag
		}
	}
	t.Fatalf("answer from no known server: %s", address)
	return ""
}

func (f *fallbackFixture) queries() []int32 {
	counts := make([]int32, len(f.servers))
	for i, server := range f.servers {
		counts[i] = server.queries.Load()
	}
	return counts
}

func TestFallbackAsksTheFirstServerFirst(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 2)
	for i := 0; i < 3; i++ {
		response, err := f.transport.Exchange(context.Background(), fallbackQuery())
		require.NoError(t, err)
		require.Equal(t, "server-a", f.answeredBy(t, response))
	}
	require.Equal(t, []int32{3, 0}, f.queries())
}

func TestFallbackKeepsTheMessageID(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 2)
	f.servers[0].set(fallbackFakeError, 0)
	message := fallbackQuery()
	message.Id = 4242
	response, err := f.transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.Equal(t, uint16(4242), response.Id)
	require.Equal(t, uint16(4242), message.Id)
}

func TestFallbackMovesOnOnError(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 3)
	f.servers[0].set(fallbackFakeError, 0)
	f.servers[1].set(fallbackFakeError, 0)
	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-c", f.answeredBy(t, response))
	require.Equal(t, []int32{1, 1, 1}, f.queries())
}

func TestFallbackMovesOnOnTimeout(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, 50*time.Millisecond, 2)
	f.servers[0].set(fallbackFakeHang, 0)
	startAt := time.Now()
	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-b", f.answeredBy(t, response))
	elapsed := time.Since(startAt)
	require.GreaterOrEqual(t, elapsed, 50*time.Millisecond)
	require.Less(t, elapsed, 2*time.Second)
}

func TestFallbackGivesTheLastServerTheQueryDeadline(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, 30*time.Millisecond, 2)
	f.servers[0].set(fallbackFakeError, 0)
	f.servers[1].delay = 120 * time.Millisecond
	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-b", f.answeredBy(t, response))
}

func TestFallbackSticksToTheServerThatAnswered(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, 50*time.Millisecond, 2)
	f.servers[0].set(fallbackFakeHang, 0)

	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-b", f.answeredBy(t, response))
	require.Equal(t, []int32{1, 1}, f.queries())

	// The dead first server is skipped: no timeout to wait out.
	for i := 0; i < 3; i++ {
		startAt := time.Now()
		response, err = f.transport.Exchange(context.Background(), fallbackQuery())
		require.NoError(t, err)
		require.Equal(t, "server-b", f.answeredBy(t, response))
		require.Less(t, time.Since(startAt), 40*time.Millisecond)
		f.clock.Advance(time.Minute)
	}
	require.Equal(t, []int32{1, 4}, f.queries())

	// More answers from the second server do not stretch the time.
	f.clock.Advance(fallbackStickyDuration - 3*time.Minute)
	f.servers[0].set(fallbackFakeAnswer, 0)
	response, err = f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-a", f.answeredBy(t, response))
	require.Equal(t, []int32{2, 4}, f.queries())

	response, err = f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-a", f.answeredBy(t, response))
	require.Equal(t, []int32{3, 4}, f.queries())
}

func TestFallbackStickyServerFailingGoesBackToTheOrder(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 3)
	f.servers[0].set(fallbackFakeError, 0)
	f.servers[1].set(fallbackFakeError, 0)
	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-c", f.answeredBy(t, response))

	// server-c is asked first now; when it fails, the order given is
	// tried, and the first server that answers is the one remembered.
	f.servers[2].set(fallbackFakeError, 0)
	f.servers[1].set(fallbackFakeAnswer, 0)
	response, err = f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-b", f.answeredBy(t, response))
	require.Equal(t, []int32{2, 2, 2}, f.queries())

	response, err = f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-b", f.answeredBy(t, response))
	require.Equal(t, []int32{2, 3, 2}, f.queries())

	// The first server answering again ends the detour at once.
	f.servers[1].set(fallbackFakeError, 0)
	f.servers[0].set(fallbackFakeAnswer, 0)
	response, err = f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-a", f.answeredBy(t, response))
	response, err = f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-a", f.answeredBy(t, response))
	require.Equal(t, []int32{4, 4, 2}, f.queries())
}

func TestFallbackResetForgetsTheStickyServer(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 2)
	f.servers[0].set(fallbackFakeError, 0)
	_, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	f.transport.Reset()
	f.servers[0].set(fallbackFakeAnswer, 0)
	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-a", f.answeredBy(t, response))
}

func TestFallbackNXDOMAINIsAnAnswer(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 2)
	f.servers[0].set(fallbackFakeRcode, mDNS.RcodeNameError)
	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeNameError, response.Rcode)
	require.Equal(t, []int32{1, 0}, f.queries())
}

func TestFallbackNXDOMAINAsAnErrorIsAnAnswer(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 2)
	f.servers[0].set(fallbackFakeRcodeError, mDNS.RcodeNameError)
	message := fallbackQuery()
	message.Id = 777
	response, err := f.transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeNameError, response.Rcode)
	require.Equal(t, uint16(777), response.Id)
	require.Equal(t, message.Question, response.Question)
	// the name is not handed to the next server, and nothing is remembered against the first
	require.Equal(t, []int32{1, 0}, f.queries())
	_, err = f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, []int32{2, 0}, f.queries())
}

func TestFallbackSERVFAILAsAnErrorMovesOnWithoutSticking(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 2)
	f.servers[0].set(fallbackFakeRcodeError, mDNS.RcodeServerFailure)
	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-b", f.answeredBy(t, response))
	_, err = f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, []int32{2, 2}, f.queries(), "an rcode is about the query: the first server is asked again")

	// all of them failing so: the first failing answer, not an error
	f.servers[1].set(fallbackFakeRcodeError, mDNS.RcodeRefused)
	response, err = f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeServerFailure, response.Rcode)
}

func TestFallbackEmptyNOERRORIsAnAnswer(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 2)
	f.servers[0].set(fallbackFakeRcode, mDNS.RcodeSuccess)
	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
	require.Empty(t, response.Answer)
	require.Equal(t, []int32{1, 0}, f.queries())
}

func TestFallbackMovesOnOnServfailAndRefused(t *testing.T) {
	t.Parallel()
	for _, rcode := range []int{mDNS.RcodeServerFailure, mDNS.RcodeRefused} {
		f := newFallbackFixture(t, time.Second, 2)
		f.servers[0].set(fallbackFakeRcode, rcode)
		response, err := f.transport.Exchange(context.Background(), fallbackQuery())
		require.NoError(t, err)
		require.Equal(t, "server-b", f.answeredBy(t, response))
		// An rcode is about this query, not the server being down: the
		// next query asks the first server again.
		_, err = f.transport.Exchange(context.Background(), fallbackQuery())
		require.NoError(t, err)
		require.Equal(t, []int32{2, 2}, f.queries())
	}
}

func TestFallbackAllFailing(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 2)
	f.servers[0].set(fallbackFakeError, 0)
	f.servers[1].set(fallbackFakeError, 0)
	_, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.ErrorContains(t, err, "server-a is down")
	require.ErrorContains(t, err, "server-b is down")

	// An answer that failed is better than none.
	f.servers[1].set(fallbackFakeRcode, mDNS.RcodeServerFailure)
	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeServerFailure, response.Rcode)
}

func TestFallbackContextCancel(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, 5*time.Second, 2)
	f.servers[0].set(fallbackFakeHang, 0)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)
	startAt := time.Now()
	_, err := f.transport.Exchange(ctx, fallbackQuery())
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(startAt), 2*time.Second)
	require.Equal(t, []int32{1, 0}, f.queries())

	// A cancelled query says nothing about the servers.
	f.servers[0].set(fallbackFakeAnswer, 0)
	response, err := f.transport.Exchange(context.Background(), fallbackQuery())
	require.NoError(t, err)
	require.Equal(t, "server-a", f.answeredBy(t, response))
}

func TestFallbackContextDeadline(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 2)
	f.servers[0].set(fallbackFakeHang, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := f.transport.Exchange(ctx, fallbackQuery())
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, []int32{1, 0}, f.queries())
}

func TestFallbackExchangeAsync(t *testing.T) {
	t.Parallel()
	f := newFallbackFixture(t, time.Second, 2)
	f.servers[0].set(fallbackFakeError, 0)
	done := make(chan *mDNS.Msg, 1)
	f.transport.ExchangeAsync(context.Background(), fallbackQuery(), func(response *mDNS.Msg, err error) {
		require.NoError(t, err)
		done <- response
	})
	select {
	case response := <-done:
		require.Equal(t, "server-b", f.answeredBy(t, response))
	case <-time.After(5 * time.Second):
		t.Fatal("no callback")
	}
}

func TestFallbackOptions(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	for _, servers := range [][]string{nil, {""}, {"a", "a"}, {"a", "fallback"}} {
		_, err := NewFallback(context.Background(), logger, "fallback", option.FallbackDNSServerOptions{Servers: servers})
		require.Error(t, err, servers)
	}
	_, err := NewFallback(context.Background(), logger, "fallback", option.FallbackDNSServerOptions{
		Servers: []string{"a"},
		Timeout: badoption.Duration(-time.Second),
	})
	require.Error(t, err)

	rawTransport, err := NewFallback(context.Background(), logger, "fallback", option.FallbackDNSServerOptions{Servers: []string{"a"}})
	require.NoError(t, err)
	require.Equal(t, fallbackDefaultTimeout, rawTransport.(*FallbackTransport).timeout)
	require.Equal(t, C.DNSTypeFallback, rawTransport.Type())
}

func TestFallbackStartChecksServers(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	manager := &fallbackFakeManager{transports: map[string]adapter.DNSTransport{
		"a":      &fallbackFakeServer{tag: "a"},
		"fakeip": &fallbackFakeServer{tag: "fakeip", transportType: C.DNSTypeFakeIP},
	}}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	for _, servers := range [][]string{{"a", "missing"}, {"a", "fakeip"}} {
		transport, err := NewFallback(ctx, logger, "fallback", option.FallbackDNSServerOptions{Servers: servers})
		require.NoError(t, err)
		require.Error(t, transport.Start(adapter.StartStateInitialize, nil), servers)
	}
}

func TestFallbackOptionsJSON(t *testing.T) {
	t.Parallel()
	var options option.FallbackDNSServerOptions
	require.NoError(t, json.Unmarshal([]byte(`{"servers":["a","b"],"timeout":"2s"}`), &options))
	require.Equal(t, []string{"a", "b"}, []string(options.Servers))
	require.Equal(t, 2*time.Second, time.Duration(options.Timeout))
	require.NoError(t, json.Unmarshal([]byte(`{"servers":"a"}`), &options))
	require.Equal(t, []string{"a"}, []string(options.Servers))
}
