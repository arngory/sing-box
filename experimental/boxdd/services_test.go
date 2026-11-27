//go:build linux

package boxdd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/service/powerreport"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// niko: a program's added services: their registration and who may call their methods (services.go).

func probeDesc(name string) *grpc.ServiceDesc {
	handler := func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error) {
		return nil, nil
	}
	return &grpc.ServiceDesc{
		ServiceName: name,
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "Open", Handler: handler},
			{MethodName: "Own", Handler: handler},
			{MethodName: "Shut", Handler: handler},
			{MethodName: "Read", Handler: handler},
		},
	}
}

func probeService(name string) Service {
	return Service{
		Desc:    probeDesc(name),
		New:     func(Host) (any, error) { return struct{}{}, nil },
		Policy:  PolicyCaller,
		Methods: map[string]MethodPolicy{"Own": PolicyOwner, "Shut": PolicyRefuse, "Read": PolicyOwnerUnlocked},
	}
}

func testDaemon(t *testing.T, services ...Service) (*Daemon, error) {
	t.Helper()
	previous := workingDirectory
	workingDirectory = t.TempDir()
	t.Cleanup(func() { workingDirectory = previous })
	d := &Daemon{server: grpc.NewServer()}
	RegisterDesktopServiceServer(d.server, &desktopService{daemon: d})
	grpc_health_v1.RegisterHealthServer(d.server, nil)
	var serving []string
	err := d.registerServices(services, func(name string) { serving = append(serving, name) })
	if err == nil && len(serving) != len(services) {
		t.Fatalf("serving %v", serving)
	}
	return d, err
}

func verified(userID string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: &peerAuthInfo{identity: peerIdentity{UserID: userID}}})
}

func TestNekoAddedServicePolicy(t *testing.T) {
	if listenAddress != "" {
		t.Skip("development mode allows every call")
	}
	d, err := testDaemon(t, probeService("niko.test.Probe"))
	if err != nil {
		t.Fatal(err)
	}
	a := &daemonAuthorizer{daemon: d}
	code := func(ctx context.Context, method string) codes.Code {
		t.Helper()
		return status.Code(a.Authorize(ctx, method))
	}
	// a verified caller: the service's policy; without an identity nothing passes
	if c := code(verified("1000"), "/niko.test.Probe/Open"); c != codes.OK {
		t.Fatalf("caller method, verified: %v", c)
	}
	if c := code(context.Background(), "/niko.test.Probe/Open"); c != codes.Unauthenticated {
		t.Fatalf("caller method, no identity: %v", c)
	}
	if c := code(verified("1000"), "/niko.test.Probe/Shut"); c != codes.PermissionDenied {
		t.Fatalf("refused method: %v", c)
	}
	// a service no one added: refused, as before
	if c := code(verified("1000"), "/niko.test.Other/Open"); c != codes.PermissionDenied {
		t.Fatalf("unknown service: %v", c)
	}
	// the owner's method: the daemon's owner only
	if !d.ownerProtected("/niko.test.Probe/Own") || d.ownerProtected("/niko.test.Probe/Open") {
		t.Fatal("owner protection")
	}
	if c := code(verified("1000"), "/niko.test.Probe/Own"); c != codes.PermissionDenied {
		t.Fatalf("owner method, no owner: %v", c)
	}
	if err := saveOwner("1000", 0); err != nil {
		t.Fatal(err)
	}
	if c := code(verified("1000"), "/niko.test.Probe/Own"); c != codes.OK {
		t.Fatalf("owner method, the owner: %v", c)
	}
	if c := code(verified("1001"), "/niko.test.Probe/Own"); c != codes.PermissionDenied {
		t.Fatalf("owner method, another user: %v", c)
	}
	// a unary call runs its handler only when allowed
	ran := false
	if _, err := a.InvokeUnary(verified("1000"), "/niko.test.Probe/Shut", func() (any, error) { ran = true; return nil, nil }); err == nil || ran {
		t.Fatalf("refused method ran: %v", err)
	}
	if _, err := a.InvokeUnary(verified("1001"), "/niko.test.Probe/Open", func() (any, error) { ran = true; return nil, nil }); err != nil || !ran {
		t.Fatalf("caller method did not run: %v", err)
	}
	// the daemon's own services keep their rules
	if c := code(verified("1001"), "/desktop.DesktopService/GetDaemonInfo"); c != codes.OK {
		t.Fatalf("DesktopService: %v", c)
	}
	if c := code(verified("1001"), "/daemon.StartedService/GetVersion"); c != codes.PermissionDenied {
		t.Fatalf("StartedService, not the owner: %v", c)
	}
}

func TestNekoAddedServiceRegistration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service Service
	}{
		{"the daemon's own name", probeService(DesktopService_ServiceDesc.ServiceName)},
		{"the health service's name", probeService(grpc_health_v1.Health_ServiceDesc.ServiceName)},
		{"a policy for a method it has not", func() Service {
			s := probeService("niko.test.Probe")
			s.Methods = map[string]MethodPolicy{"Gone": PolicyCaller}
			return s
		}()},
		{"no constructor", func() Service { s := probeService("niko.test.Probe"); s.New = nil; return s }()},
		{"a constructor's error", func() Service {
			s := probeService("niko.test.Probe")
			s.New = func(Host) (any, error) { return nil, os.ErrInvalid }
			return s
		}()},
	} {
		if _, err := testDaemon(t, tc.service); err == nil {
			t.Errorf("%s: registered", tc.name)
		}
	}
	if _, err := testDaemon(t, probeService("niko.test.Probe"), probeService("niko.test.Probe")); err == nil {
		t.Error("the same name twice: registered")
	}
}

// An owner's method run outside the lifecycle lock: checked as the owner's, and a slow one holds up no other owner's
// call (a stop, a start) while it runs.
func TestNekoAddedServiceUnlocked(t *testing.T) {
	if listenAddress != "" {
		t.Skip("development mode allows every call")
	}
	d, err := testDaemon(t, probeService("niko.test.Probe"))
	if err != nil {
		t.Fatal(err)
	}
	a := &daemonAuthorizer{daemon: d}
	if d.ownerProtected("/niko.test.Probe/Read") || !d.ownerChecked("/niko.test.Probe/Read") {
		t.Fatal("Read: owner protection")
	}
	if c := status.Code(a.Authorize(verified("1000"), "/niko.test.Probe/Read")); c != codes.PermissionDenied {
		t.Fatalf("no owner: %v", c)
	}
	if err := saveOwner("1000", 0); err != nil {
		t.Fatal(err)
	}
	if c := status.Code(a.Authorize(verified("1001"), "/niko.test.Probe/Read")); c != codes.PermissionDenied {
		t.Fatalf("another user: %v", c)
	}
	hold := make(chan struct{})
	running := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := a.InvokeUnary(verified("1000"), "/niko.test.Probe/Read", func() (any, error) {
			close(running)
			<-hold
			return nil, nil
		})
		done <- err
	}()
	select {
	case <-running:
	case err := <-done:
		t.Fatalf("Read did not run: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not start")
	}
	// the slow read runs; an owner's call under the lock goes through meanwhile
	owned := make(chan error, 1)
	go func() {
		_, err := a.InvokeUnary(verified("1000"), "/niko.test.Probe/Own", func() (any, error) { return nil, nil })
		owned <- err
	}()
	select {
	case err := <-owned:
		if err != nil {
			t.Fatalf("Own: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Own waited for the read: the lock was held")
	}
	close(hold)
	if err := <-done; err != nil {
		t.Fatalf("Read: %v", err)
	}
}

// startingDaemon is testDaemon with a core to start: the daemon's context, its StartedService and power manager. The
// owner's directory is taken as the daemon's own already, so that a start neither changes the test's directory nor
// redirects its stderr (libbox.Setup).
func startingDaemon(t *testing.T, owner string) *Daemon {
	t.Helper()
	d, err := testDaemon(t)
	if err != nil {
		t.Fatal(err)
	}
	d.ctx = include.Context(context.Background())
	d.logger = log.StdLogger()
	d.startedService = daemon.NewStartedService(daemon.ServiceOptions{Context: d.ctx})
	d.powerManager = powerreport.NewManager()
	d.runtimeWorkingDirectory = userWorkingDirectory(owner)
	if err = os.MkdirAll(d.runtimeWorkingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.startedService.CloseService() })
	return d
}

// An added service's start (Host.StartService) is DesktopService.StartService's with no options: the caller made the
// owner, the core started, the config and the stored options kept with WasRunning; another user refused.
func TestNekoHostStartService(t *testing.T) {
	d := startingDaemon(t, "1000")
	const config = `{"log": {"level": "error"}, "outbounds": [{"type": "direct", "tag": "direct"}]}`
	stored := startOptions{OOMMemoryLimit: 123}
	if err := saveStartOptions("1000", stored); err != nil {
		t.Fatal(err)
	}
	if err := d.StartService(verified("1000"), config, nil); err != nil {
		t.Fatal(err)
	}
	if d.startedService.Instance() == nil {
		t.Fatal("no core runs")
	}
	if owner, err := loadOwner(); err != nil || owner != "1000" {
		t.Fatalf("owner %q: %v", owner, err)
	}
	if kept, err := loadServiceConfig("1000"); err != nil || kept != config {
		t.Fatalf("config %q: %v", kept, err)
	}
	if options, err := loadStartOptions("1000"); err != nil || !options.WasRunning || options.OOMMemoryLimit != 123 {
		t.Fatalf("options %+v: %v", options, err)
	}

	// another user: refused, the owner's core as it was
	running := d.startedService.Instance()
	if err := d.StartService(verified("1001"), config, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another user: %v", err)
	}
	if d.startedService.Instance() != running {
		t.Fatal("another user's start touched the core")
	}

	// a config the core refuses: its error, nothing runs, not to be started again with the daemon
	if err := d.StartService(verified("1000"), `{"inbounds": [{"type": "no-such-inbound"}]}`, nil); err == nil {
		t.Fatal("a refused config started")
	}
	if d.startedService.Instance() != nil {
		t.Fatal("a core runs after a refused config")
	}
	if options, err := loadStartOptions("1000"); err != nil || options.WasRunning {
		t.Fatalf("options after a refused config %+v: %v", options, err)
	}

	// DesktopService.StartService as before: its options replace the stored ones
	request := &StartServiceRequest{ConfigContent: config, Options: &StartOptions{OomMemoryLimit: 456}}
	if _, err := (&desktopService{daemon: d}).StartService(verified("1000"), request); err != nil {
		t.Fatal(err)
	}
	if options, err := loadStartOptions("1000"); err != nil || !options.WasRunning || options.OOMMemoryLimit != 456 {
		t.Fatalf("options from the request %+v: %v", options, err)
	}
}

type fakeRestorePreparer struct {
	called   bool
	stopped  bool
	owner    string
	stopUser string
	config   string
	err      error
}

func (f *fakeRestorePreparer) BeforeRestore(ctx context.Context, ownerUserID string) (string, bool, error) {
	f.called = true
	f.owner = ownerUserID
	if f.err != nil {
		return "", false, f.err
	}
	return f.config, f.config != "", nil
}

func (f *fakeRestorePreparer) AfterStop(ownerUserID string) {
	f.stopped = true
	f.stopUser = ownerUserID
}

func TestRestorePreparerAndStopRemovesPlaintextConfig(t *testing.T) {
	d := startingDaemon(t, "1000")
	const initialConfig = `{"log": {"level": "error"}, "outbounds": [{"type": "direct", "tag": "direct"}]}`
	const rebuiltConfig = `{"log": {"level": "warn"}, "outbounds": [{"type": "direct", "tag": "direct"}]}`
	prep := &fakeRestorePreparer{config: rebuiltConfig}
	d.serviceImpls = []any{prep}

	if err := d.StartService(verified("1000"), initialConfig, nil); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(userWorkingDirectory("1000"), serviceConfigFileName)
	snapPath := filepath.Join(userWorkingDirectory("1000"), configSnapshotFileName)
	// When a RestorePreparer is registered, Host.StartService must not persist plaintext config snapshots on disk.
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatalf("expected no plaintext config.json with RestorePreparer, err=%v", err)
	}
	if _, err := os.Stat(snapPath); !os.IsNotExist(err) {
		t.Fatalf("expected no plaintext configuration.json with RestorePreparer, err=%v", err)
	}

	if err := d.stopServiceLocked("1000"); err != nil {
		t.Fatal(err)
	}
	if !prep.stopped || prep.stopUser != "1000" {
		t.Fatalf("AfterStop hook not called properly: %+v", prep)
	}

	// Simulate daemon restart with WasRunning=true: RestorePreparer supplies fresh config even without config.json.
	if err := saveStartOptions("1000", startOptions{WasRunning: true}); err != nil {
		t.Fatal(err)
	}
	d.restore()
	if !prep.called || prep.owner != "1000" {
		t.Fatalf("BeforeRestore not called properly: %+v", prep)
	}
	if d.startedService.Instance() == nil {
		t.Fatal("expected core to be running after restore via RestorePreparer")
	}

	// If BeforeRestore fails, restore must fall back to saved config.json when present.
	if err := d.stopServiceLocked("1000"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(initialConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	prep.err = os.ErrPermission
	if err := saveStartOptions("1000", startOptions{WasRunning: true}); err != nil {
		t.Fatal(err)
	}
	d.restore()
	if d.startedService.Instance() == nil {
		t.Fatal("expected fallback to saved config.json when BeforeRestore returns error")
	}
}
