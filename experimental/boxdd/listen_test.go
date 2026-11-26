package boxdd

import (
	"context"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestNekoValidateListenAddress(t *testing.T) {
	origOpts := activeOptions
	t.Cleanup(func() { activeOptions = origOpts })

	activeOptions.DevelopmentListen = true
	for _, valid := range []string{"127.0.0.1:1024", "127.0.0.1:2080", "127.0.0.1:65535"} {
		ap, err := validateListenAddress(valid)
		if err != nil {
			t.Errorf("validateListenAddress(%q) unexpected error: %v", valid, err)
		} else if ap.String() != valid {
			t.Errorf("validateListenAddress(%q) = %q", valid, ap.String())
		}
	}
	for _, invalid := range []string{
		"",
		"0.0.0.0:2080",
		"127.0.0.2:2080",
		"[::1]:2080",
		"[::ffff:127.0.0.1]:2080",
		"[fe80::1%eth0]:2080",
		"localhost:2080",
		"127.0.0.1:0",
		"127.0.0.1:80",
		"127.0.0.1:1023",
		"127.0.0.1:65536",
		":8080",
		"127.0.0.1:",
		" 127.0.0.1:2080",
		"127.0.0.1:2080 ",
	} {
		if _, err := validateListenAddress(invalid); err == nil {
			t.Errorf("validateListenAddress(%q) succeeded, want error", invalid)
		}
	}

	activeOptions.DevelopmentListen = false
	if _, err := validateListenAddress("127.0.0.1:2080"); err == nil {
		t.Fatal("expected error when DevelopmentListen=false")
	}
}

func TestNekoHostCallerAndDirectories(t *testing.T) {
	origDir := workingDirectory
	origListen := listenAddress
	t.Cleanup(func() {
		workingDirectory = origDir
		listenAddress = origListen
	})

	root := t.TempDir()
	other := t.TempDir()
	workingDirectory = root
	listenAddress = ""

	d := &Daemon{rootDirectory: root}

	// Verified peer identity round-trips through Host.Caller.
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: &peerAuthInfo{identity: peerIdentity{UserID: "S-1-5-21-1000", SessionID: 2, ProcessID: 4242}},
	})
	caller, err := d.Caller(ctx)
	if err != nil {
		t.Fatalf("Caller(verified): %v", err)
	}
	if caller.UserID != "S-1-5-21-1000" || caller.SessionID != 2 || caller.ProcessID != 4242 {
		t.Fatalf("unexpected caller: %+v", caller)
	}

	// Missing credentials must fail with Unauthenticated.
	if _, err := d.Caller(context.Background()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Caller(empty) = %v, want Unauthenticated", err)
	}

	// Development listen fallback returns "local".
	listenAddress = "127.0.0.1:2080"
	devCaller, err := d.Caller(context.Background())
	if err != nil || devCaller.UserID != "local" {
		t.Fatalf("Caller(dev) = (%+v, %v), want UserID=local", devCaller, err)
	}
	listenAddress = ""

	// WorkingDirectory and UserDirectory remain pinned to root even after os.Chdir.
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })
	if err := os.Chdir(other); err != nil {
		t.Fatal(err)
	}
	if got := d.WorkingDirectory(); got != root {
		t.Fatalf("WorkingDirectory() after Chdir = %q, want %q", got, root)
	}
	if got, want := d.UserDirectory("alice"), userWorkingDirectoryAt(root, "alice"); got != want {
		t.Fatalf("UserDirectory(alice) = %q, want %q", got, want)
	}
	if got := d.UserDirectory(""); got != "" {
		t.Fatalf("UserDirectory(\"\") = %q, want empty", got)
	}
}
