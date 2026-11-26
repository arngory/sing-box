//go:build windows

package boxdd

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNekoWindowsServiceSIDMatchesSC(t *testing.T) {
	origNames := activeNames
	t.Cleanup(func() { activeNames = origNames })
	activeNames = nikoTestNames()

	sid, err := windowsServiceSID()
	if err != nil {
		t.Fatalf("windowsServiceSID: %v", err)
	}
	out, err := exec.Command("sc.exe", "showsid", "niko-daemon").CombinedOutput()
	if err != nil {
		t.Fatalf("sc.exe showsid: %v (%s)", err, string(out))
	}
	if !strings.Contains(string(out), sid.String()) {
		t.Fatalf("sc.exe showsid output %q does not contain computed SID %q", string(out), sid.String())
	}
}

func TestNekoUnixWorkerPeerPIDAndReconnect(t *testing.T) {
	if target := os.Getenv("NIKO_BOXDD_TEST_ROGUE_UNIX"); target != "" {
		conn, err := net.DialTimeout("unix", target, 2*time.Second)
		if err != nil {
			os.Exit(0)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write(make([]byte, len(workerHandshakeMagic)+workerNonceSize))
		buf := make([]byte, workerNonceSize+workerMACSize)
		n, err := io.ReadFull(conn, buf)
		if err == nil || n > 0 {
			fmt.Fprintf(os.Stderr, "rogue peer unexpectedly received %d bytes\n", n)
			os.Exit(2)
		}
		os.Exit(0)
	}

	selfHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenProcess(self): %v", err)
	}
	parent := &windowsWorkerParent{
		process: selfHandle,
		pid:     uint32(os.Getpid()),
		exited:  make(chan struct{}),
	}
	t.Cleanup(func() { _ = windows.CloseHandle(selfHandle) })

	// Include Cyrillic + spaces in socket path and leave a stale AF_UNIX socket beforehand.
	base, err := os.MkdirTemp("", "nk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	dir := filepath.Join(base, "тест юзер", "niko")
	sockPath := filepath.Join(dir, "w-01234567.sock")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	staleBind, err := resolveUnixSocketBindPath(sockPath)
	if err != nil {
		t.Fatalf("resolveUnixSocketBindPath: %v", err)
	}
	staleLn, err := net.Listen("unix", staleBind)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	staleLn.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = staleLn.Close()

	ln, bindPath, err := listenWorkerUnixEndpoint(sockPath, parent)
	if err != nil {
		t.Fatalf("listenWorkerUnixEndpoint: %v", err)
	}
	defer ln.Close()

	// Verify protected DACL on socket directory (only current user, TokenOwner if distinct, and SYSTEM).
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	ctrl, _, err := sd.Control()
	if err != nil || ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("socket dir DACL is not protected: ctrl=%#x err=%v", ctrl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("socket dir DACL missing: %v", err)
	}
	userSID, ownerSID, err := currentWindowsTokenSIDs()
	if err != nil {
		t.Fatal(err)
	}
	sysSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !windows.EqualSid(sid, userSID) && !windows.EqualSid(sid, sysSID) && (ownerSID == nil || !windows.EqualSid(sid, ownerSID)) {
			t.Fatalf("unexpected principal in socket dir DACL: %s", sid.String())
		}
	}

	var key [workerKeySize]byte
	for i := range key {
		key[i] = byte(i + 7)
	}
	workerPID := uint32(os.Getpid())

	// Accept loop performing mutual HMAC and echoing 4 bytes.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if err := workerServerHandshake(c, &key, parent.pid, workerPID); err != nil {
					return
				}
				var buf [4]byte
				if _, err := io.ReadFull(c, buf[:]); err != nil {
					return
				}
				_, _ = c.Write(buf[:])
			}(conn)
		}
	}()

	// Rogue child process (different PID) must be rejected without receiving handshake bytes.
	rogue := exec.Command(os.Args[0], "-test.run=^TestNekoUnixWorkerPeerPIDAndReconnect$")
	rogue.Env = append(os.Environ(), "NIKO_BOXDD_TEST_ROGUE_UNIX="+bindPath)
	if out, err := rogue.CombinedOutput(); err != nil {
		t.Fatalf("rogue peer test failed: %v\n%s", err, string(out))
	}

	// 3 sequential reconnects + 2 concurrent connections must all succeed on the same listener.
	dialAndEcho := func(msg string) error {
		conn, err := net.DialTimeout("unix", bindPath, 3*time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := workerClientHandshake(conn, &key, parent.pid, workerPID); err != nil {
			return err
		}
		if _, err := conn.Write([]byte(msg)); err != nil {
			return err
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, got); err != nil {
			return err
		}
		if string(got) != msg {
			return fmt.Errorf("got %q, want %q", got, msg)
		}
		return nil
	}
	for i := 0; i < 3; i++ {
		if err := dialAndEcho(fmt.Sprintf("seq%d", i)); err != nil {
			t.Fatalf("sequential reconnect %d: %v", i, err)
		}
	}
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(idx int) {
			errCh <- dialAndEcho(fmt.Sprintf("par%d", idx))
		}(i)
	}
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent connection %d: %v", i, err)
		}
	}

	_ = ln.Close()
	wg.Wait()
}

func TestNekoUnixNonSocketRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(dir, "keep.sock")
	if err := os.WriteFile(regular, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareWorkerSocketPath(regular); err == nil {
		t.Fatal("expected refusal for existing regular file")
	}
	data, err := os.ReadFile(regular)
	if err != nil || string(data) != "keep-me" {
		t.Fatalf("regular file was modified or deleted: (%q, %v)", data, err)
	}
}
