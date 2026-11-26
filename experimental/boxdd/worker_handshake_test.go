package boxdd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNekoWorkerHandshake(t *testing.T) {
	var key [workerKeySize]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	var badKey [workerKeySize]byte
	badKey[0] = 0xff

	runPair := func(serverKey, clientKey *[workerKeySize]byte, sWin, sWork, cWin, cWork uint32) (error, error) {
		sConn, cConn := net.Pipe()
		defer sConn.Close()
		defer cConn.Close()
		sErrCh := make(chan error, 1)
		go func() {
			sErrCh <- workerServerHandshake(sConn, serverKey, sWin, sWork)
		}()
		cErr := workerClientHandshake(cConn, clientKey, cWin, cWork)
		if cErr != nil {
			_ = cConn.Close()
		}
		sErr := <-sErrCh
		return sErr, cErr
	}

	// Valid handshake + payload delivery after handshake.
	sConn, cConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		if err := workerServerHandshake(sConn, &key, 1234, 5678); err != nil {
			done <- err
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(sConn, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != "hello" {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err := sConn.Write([]byte("world"))
		done <- err
	}()
	if err := workerClientHandshake(cConn, &key, 1234, 5678); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := cConn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(cConn, reply); err != nil || string(reply) != "world" {
		t.Fatalf("post-handshake reply = (%q, %v)", reply, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server side: %v", err)
	}
	_ = sConn.Close()
	_ = cConn.Close()

	// Wrong key, wrong window PID, wrong worker PID all fail.
	if sErr, cErr := runPair(&key, &badKey, 100, 200, 100, 200); sErr == nil || cErr == nil {
		t.Fatalf("bad key: sErr=%v cErr=%v", sErr, cErr)
	}
	if sErr, cErr := runPair(&key, &key, 100, 200, 101, 200); sErr == nil || cErr == nil {
		t.Fatalf("mismatched window PID: sErr=%v cErr=%v", sErr, cErr)
	}
	if sErr, cErr := runPair(&key, &key, 100, 200, 100, 201); sErr == nil || cErr == nil {
		t.Fatalf("mismatched worker PID: sErr=%v cErr=%v", sErr, cErr)
	}

	// Invalid magic is rejected immediately.
	sConn2, cConn2 := net.Pipe()
	sErrCh := make(chan error, 1)
	go func() {
		sErrCh <- workerServerHandshake(sConn2, &key, 10, 20)
	}()
	_, _ = cConn2.Write(bytes.Repeat([]byte("X"), len(workerHandshakeMagic)+workerNonceSize))
	_ = cConn2.Close()
	if err := <-sErrCh; err == nil {
		t.Fatal("expected error for invalid magic")
	}
	_ = sConn2.Close()

	// Truncated client hello is rejected cleanly.
	sConn3, cConn3 := net.Pipe()
	sErrCh3 := make(chan error, 1)
	go func() {
		sErrCh3 <- workerServerHandshake(sConn3, &key, 10, 20)
	}()
	_, _ = cConn3.Write([]byte(workerHandshakeMagic))
	_ = cConn3.Close()
	if err := <-sErrCh3; err == nil {
		t.Fatal("expected error for truncated hello")
	}
	_ = sConn3.Close()
}

type workerHandshakeVector struct {
	Name        string `json:"name"`
	KeyHex      string `json:"key_hex"`
	ClientNonce string `json:"client_nonce_hex"`
	ServerNonce string `json:"server_nonce_hex"`
	WindowPID   uint32 `json:"window_pid"`
	WorkerPID   uint32 `json:"worker_pid"`
	ServerMAC   string `json:"server_mac_hex"`
	ClientMAC   string `json:"client_mac_hex"`
}

func TestNekoWorkerHandshakeVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "worker_handshake_vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors []workerHandshakeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("empty vector list")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			keyBytes, err := hex.DecodeString(v.KeyHex)
			if err != nil || len(keyBytes) != workerKeySize {
				t.Fatalf("invalid key_hex: %v", err)
			}
			var key [workerKeySize]byte
			copy(key[:], keyBytes)
			nc, err := hex.DecodeString(v.ClientNonce)
			if err != nil || len(nc) != workerNonceSize {
				t.Fatalf("invalid client_nonce_hex: %v", err)
			}
			ns, err := hex.DecodeString(v.ServerNonce)
			if err != nil || len(ns) != workerNonceSize {
				t.Fatalf("invalid server_nonce_hex: %v", err)
			}
			gotServer := hex.EncodeToString(computeWorkerMAC(&key, workerDomainServer, nc, ns, v.WindowPID, v.WorkerPID))
			gotClient := hex.EncodeToString(computeWorkerMAC(&key, workerDomainClient, nc, ns, v.WindowPID, v.WorkerPID))
			if gotServer != v.ServerMAC {
				t.Fatalf("server MAC = %s, want %s", gotServer, v.ServerMAC)
			}
			if gotClient != v.ClientMAC {
				t.Fatalf("client MAC = %s, want %s", gotClient, v.ClientMAC)
			}
		})
	}
}

func TestNekoReadWorkerKey(t *testing.T) {
	validHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	r, w := io.Pipe()
	go func() {
		_, _ = io.WriteString(w, validHex+"\n")
		// Leave pipe open briefly, then close (mimics window keeping stdin open until exit).
		time.Sleep(20 * time.Millisecond)
		_ = w.Close()
	}()
	key, err := readWorkerKey(r, time.Second)
	if err != nil {
		t.Fatalf("readWorkerKey valid: %v", err)
	}
	if hex.EncodeToString(key[:]) != validHex {
		t.Fatalf("decoded key = %x, want %s", key[:], validHex)
	}
	// Remainder must hit EOF cleanly once writer closes.
	rest, err := io.ReadAll(r)
	if err != nil || len(rest) != 0 {
		t.Fatalf("rest = (%q, %v)", rest, err)
	}

	for _, tc := range []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"short", validHex[:62] + "\n"},
		{"crlf", validHex + "\r\n"},
		{"no lf", validHex + "x"},
		{"non-hex", strings.Repeat("z", 64) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readWorkerKey(strings.NewReader(tc.input), time.Second); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}

	// Timeout when writer sends nothing.
	r2, w2 := io.Pipe()
	defer w2.Close()
	if _, err := readWorkerKey(r2, 30*time.Millisecond); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestNekoValidateWorkerFlags(t *testing.T) {
	unixPath := `C:\Users\Alice\AppData\Local\Niko\run\w-0123456789abcdef.sock`
	pipePath := `\\.\pipe\sing-box-worker.app`
	relayPipe := `\\.\pipe\sing-box-worker.relay`

	if err := validateWorkerFlags(WorkerTransportUnix, "", "", unixPath, 123); err != nil {
		t.Fatalf("valid unix flags: %v", err)
	}
	if err := validateWorkerFlags(WorkerTransportPipe, pipePath, relayPipe, "", 123); err != nil {
		t.Fatalf("valid pipe flags: %v", err)
	}
	for _, tc := range []struct {
		name        string
		transport   WorkerTransport
		socket      string
		relaySocket string
		relayUnix   string
		pid         uint32
	}{
		{"missing pid", WorkerTransportUnix, "", "", unixPath, 0},
		{"unix missing path", WorkerTransportUnix, "", "", "", 123},
		{"unix with socket", WorkerTransportUnix, pipePath, "", unixPath, 123},
		{"unix with relay pipe", WorkerTransportUnix, "", relayPipe, unixPath, 123},
		{"unix bad path", WorkerTransportUnix, "", "", `\\.\pipe\foo.sock`, 123},
		{"pipe with unix", WorkerTransportPipe, pipePath, relayPipe, unixPath, 123},
		{"pipe missing socket", WorkerTransportPipe, "", relayPipe, "", 123},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateWorkerFlags(tc.transport, tc.socket, tc.relaySocket, tc.relayUnix, tc.pid); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestNekoValidateWorkerUnixSocketPath(t *testing.T) {
	for _, valid := range []string{
		`C:\Users\Alice\AppData\Local\Niko\run\w-0123456789abcdef.sock`,
		`D:\Users\Тест Пользователь\AppData\Local\Niko\run\w-abcdef.sock`,
	} {
		if err := validateWorkerUnixSocketPath(valid); err != nil {
			t.Errorf("valid path %q failed: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"",
		`\\.\pipe\niko-worker.sock`,
		`\\?\C:\Users\a\w.sock`,
		`\\server\share\w.sock`,
		`C:/Users/Alice/w.sock`,
		`C:\w.sock`,
		`C:\Users\..\w.sock`,
		`C:\Users\.\w.sock`,
		`C:\Users\Alice\w.txt`,
		`C:\Users\Alice\.sock`,
		`C:\Users\Alice\w*.sock`,
		`C:\Users\Alice\w?.sock`,
		`C:\Users\Alice\w.sock:ads`,
		`relative\path\w.sock`,
		"C:\\Users\\Alice\\w\x00.sock",
	} {
		if err := validateWorkerUnixSocketPath(invalid); err == nil {
			t.Errorf("invalid path %q unexpectedly accepted", invalid)
		}
	}
}

func TestNekoInstallManifest(t *testing.T) {
	makeTree := func(t *testing.T) (string, string) {
		t.Helper()
		root := t.TempDir()
		write := func(rel, content string) string {
			p := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(content))
			return hex.EncodeToString(sum[:]) + "  " + rel + "\n"
		}
		var manifest strings.Builder
		manifest.WriteString(write("niko.exe", "fake-window"))
		manifest.WriteString(write("flutter_windows.dll", "fake-flutter"))
		manifest.WriteString(write("data/app.so", "fake-app-so"))
		manifest.WriteString(write("resources/daemon/libcronet.dll", "fake-cronet"))
		// Daemon binary itself is verified by Authenticode, not listed in files.sha256.
		_ = write("resources/daemon/niko-daemon.exe", "fake-daemon")

		manifestBytes := []byte(manifest.String())
		if err := os.WriteFile(filepath.Join(root, "resources", "files.sha256"), manifestBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(manifestBytes)
		return root, hex.EncodeToString(sum[:])
	}

	root, hash := makeTree(t)
	if err := verifyInstallManifest(root, hash, "niko-daemon.exe"); err != nil {
		t.Fatalf("valid manifest failed: %v", err)
	}

	// Wrong manifest hash rejected.
	if err := verifyInstallManifest(root, strings.Repeat("00", 32), "niko-daemon.exe"); err == nil {
		t.Fatal("expected error for wrong manifest hash")
	}

	// Tampered file rejected.
	rootTamper, hashTamper := makeTree(t)
	if err := os.WriteFile(filepath.Join(rootTamper, "flutter_windows.dll"), []byte("evil-dll"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyInstallManifest(rootTamper, hashTamper, "niko-daemon.exe"); err == nil {
		t.Fatal("expected error for tampered DLL")
	}

	// Unexpected extra file rejected.
	rootExtra, hashExtra := makeTree(t)
	if err := os.WriteFile(filepath.Join(rootExtra, "extra.dll"), []byte("hijack"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyInstallManifest(rootExtra, hashExtra, "niko-daemon.exe"); err == nil {
		t.Fatal("expected error for extra file")
	}

	// Missing listed file rejected.
	rootMissing, hashMissing := makeTree(t)
	if err := os.Remove(filepath.Join(rootMissing, "data", "app.so")); err != nil {
		t.Fatal(err)
	}
	if err := verifyInstallManifest(rootMissing, hashMissing, "niko-daemon.exe"); err == nil {
		t.Fatal("expected error for missing file")
	}

	// Symlink inside staged tree rejected (Unix).
	if runtime.GOOS != "windows" {
		rootSym, hashSym := makeTree(t)
		if err := os.Symlink("/etc/hosts", filepath.Join(rootSym, "link")); err != nil {
			t.Fatal(err)
		}
		if err := verifyInstallManifest(rootSym, hashSym, "niko-daemon.exe"); err == nil {
			t.Fatal("expected error for symlink")
		}
	}

	// Malformed manifest lines rejected.
	for _, bad := range []string{
		"not-a-hash  niko.exe\n",
		strings.Repeat("a", 64) + "  ../evil.dll\n",
		strings.Repeat("a", 64) + "  /abs/path.dll\n",
		strings.Repeat("a", 64) + "  a.dll\n" + strings.Repeat("b", 64) + "  A.DLL\n",
	} {
		if _, err := parseInstallManifest([]byte(bad), "niko-daemon.exe"); err == nil {
			t.Errorf("parseInstallManifest unexpectedly accepted %q", bad)
		}
	}
}
