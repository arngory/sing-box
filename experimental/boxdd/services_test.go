//go:build linux

package boxdd

import (
	"context"
	"os"
	"testing"
	"time"

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
