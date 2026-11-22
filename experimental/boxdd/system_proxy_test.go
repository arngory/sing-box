package boxdd

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/powerreport"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// niko: the system proxy of an added service's start (Host.StartService's SystemProxy), set by the daemon's platform
// for the owner: what the daemon asks of the platform at a start, a stop, a restart and a session change.

// recordingPlatform is a daemon's platform that sets nothing and notes what it was asked; the core is not given it.
type recordingPlatform struct {
	adapter.PlatformInterface
	calls []string
}

func (p *recordingPlatform) note(format string, args ...any) { p.calls = append(p.calls, fmt.Sprintf(format, args...)) }

func (p *recordingPlatform) ProcessPlatformOptions(options option.TunPlatformOptions) error {
	proxy := options.HTTPProxy
	p.note("set %v %s:%d %v", proxy.Enabled, proxy.Server, proxy.ServerPort, []string(proxy.BypassDomain))
	return nil
}

func (p *recordingPlatform) ResetPlatformOptions() error {
	p.note("reset")
	return nil
}

func (p *recordingPlatform) SetSystemProxyPreference(enabled bool) { p.note("prefer %v", enabled) }

func (p *recordingPlatform) SetSystemProxyEnabled(enabled bool) error {
	p.note("enable %v", enabled)
	return nil
}

func (p *recordingPlatform) PrepareOwner(identity peerIdentity) error { return nil }

func (p *recordingPlatform) RestoreOwner(state ownerState) error {
	p.note("restore owner %s", state.UserID)
	return nil
}

func (p *recordingPlatform) ReleaseOwner() error { return nil }

func (p *recordingPlatform) SystemProxyStatus() (*daemon.SystemProxyStatus, error) {
	return &daemon.SystemProxyStatus{}, nil
}

func (p *recordingPlatform) HandleSessionChange(eventType uint32, sessionID uint32, state ownerState) (uint32, bool, error) {
	p.note("session %d of %s", sessionID, state.UserID)
	return sessionID, true, nil
}

func (p *recordingPlatform) Close() error { return nil }

// take is what the platform was asked since the last take.
func (p *recordingPlatform) take() []string {
	calls := p.calls
	p.calls = nil
	return calls
}

// proxyDaemon is a daemon that starts a core, with the recording platform; the owner's directory taken as the
// daemon's own, so a start neither changes the test's directory nor redirects its stderr (libbox.Setup).
func proxyDaemon(t *testing.T, owner string) (*Daemon, *recordingPlatform) {
	t.Helper()
	platform := &recordingPlatform{}
	d := &Daemon{platform: platform}
	d.ctx = include.Context(context.Background())
	d.logger = log.StdLogger()
	d.startedService = daemon.NewStartedService(daemon.ServiceOptions{Context: d.ctx})
	d.powerManager = powerreport.NewManager()
	d.runtimeWorkingDirectory = userWorkingDirectory(owner)
	if err := os.MkdirAll(d.runtimeWorkingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.startedService.CloseService() })
	return d, platform
}

func caller(userID string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: &peerAuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		identity:       peerIdentity{UserID: userID, SessionID: 1},
	}})
}

func TestNekoSystemProxy(t *testing.T) {
	previous := workingDirectory
	workingDirectory = t.TempDir()
	t.Cleanup(func() { workingDirectory = previous })
	d, platform := proxyDaemon(t, "1000")
	const config = `{"log": {"level": "error"}, "outbounds": [{"type": "direct", "tag": "direct"}]}`
	expect := func(what string, want ...string) {
		t.Helper()
		if got := platform.take(); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: the platform was asked %q, want %q", what, got, want)
		}
	}
	proxy := &SystemProxy{Server: "127.0.0.1", Port: 2080, BypassDomain: []string{"localhost"}}
	const set = "set true 127.0.0.1:2080 [localhost]"

	// a start: the stored preference (on by default), the previous platform options gone, the proxy set after the core
	if err := d.StartService(caller("1000"), config, proxy); err != nil {
		t.Fatal(err)
	}
	expect("the start", "prefer true", "reset", set)
	if options, err := loadStartOptions("1000"); err != nil || !reflect.DeepEqual(options.SystemProxy, proxy) {
		t.Fatalf("the stored options %+v: %v", options, err)
	}

	// turned off by the owner, kept off for the next starts
	if err := (&managedHandler{daemon: d}).SetSystemProxyEnabled(false); err != nil {
		t.Fatal(err)
	}
	expect("turned off", "enable false")

	// a stop takes it away, and keeps it for the next start
	d.lifecycleAccess.Lock()
	err := d.stopServiceLocked("1000")
	d.lifecycleAccess.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	expect("the stop", "reset")
	if err = d.StartService(caller("1000"), config, proxy); err != nil {
		t.Fatal(err)
	}
	expect("started again", "prefer false", "reset", set)

	// the daemon restarted: the owner restored, the core started again with its proxy
	_ = d.startedService.CloseService()
	again, platform2 := proxyDaemon(t, "1000")
	again.restore()
	if again.startedService.Instance() == nil {
		t.Fatal("the core was not started again")
	}
	if got, want := platform2.take(), []string{"prefer false", "restore owner 1000", "prefer false", "reset", set}; !reflect.DeepEqual(got, want) {
		t.Fatalf("the restart: the platform was asked %q, want %q", got, want)
	}
	d, platform = again, platform2

	// a session change of the owner's (on Windows): the platform's alone, which sets the proxy for the new session
	sessionChange(t, d, expect)

	// a start without one (DesktopService's): none set, and none kept
	if err = d.StartService(caller("1000"), config, nil); err != nil {
		t.Fatal(err)
	}
	expect("a start without", "prefer false", "reset")
	if options, err := loadStartOptions("1000"); err != nil || options.SystemProxy != nil {
		t.Fatalf("the stored options %+v: %v", options, err)
	}
}
