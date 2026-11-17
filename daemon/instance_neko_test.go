package daemon

import (
	"context"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/protocol/direct"
)

// a core of a direct outbound alone: include's registries import this package (service/api)
func directContext() context.Context {
	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	return box.Context(context.Background(), inbound.NewRegistry(), outbounds, endpoint.NewRegistry(),
		dns.NewTransportRegistry(), service.NewRegistry(), certificate.NewRegistry())
}

// niko: a request holding the core outside the daemon's lifecycle lock (Hold): Close cancels the core's context first,
// waits for the holder to let go, then closes; once stopping, the core is not held again.
func TestNekoInstanceHold(t *testing.T) {
	s := NewStartedService(ServiceOptions{Context: directContext(), LogMaxLines: 10})
	instance, err := s.newInstance(context.Background(), `{"log": {"level": "error"}, "outbounds": [{"type": "direct"}]}`, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	release, held := instance.Hold()
	if !held {
		t.Fatal("a fresh core: not held")
	}
	closed := make(chan error, 1)
	go func() { closed <- instance.Close() }()
	select {
	case <-instance.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel the core's context first")
	}
	select {
	case err := <-closed:
		t.Fatalf("closed under a holder: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if _, again := instance.Hold(); again {
		t.Fatal("a stopping core held again")
	}
	release()
	release()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end after the holder let go")
	}
}
