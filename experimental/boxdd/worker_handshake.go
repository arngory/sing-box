package boxdd

// niko: window <-> worker AF_UNIX mutual HMAC-SHA256 handshake and stdin key reader (slice 14).

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	workerKeySize              = 32
	workerHexKeyLineSize       = workerKeySize*2 + 1 // 64 hex chars + '\n'
	workerNonceSize            = 32
	workerMACSize              = 32
	workerHandshakeMagic       = "NIKOW\x00\x01\x00"
	workerDomainServer         = "niko-worker/1 server"
	workerDomainClient         = "niko-worker/1 client"
	workerHandshakeTimeout     = 5 * time.Second
	maxPendingWorkerHandshakes = 4
	maxUnixSocketPathBytes     = 107 // sockaddr_un.sun_path is 108 bytes including trailing NUL
)

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// readWorkerKey reads exactly 64 hex characters followed by '\n' from r within timeout.
// Leaving r open afterward allows the caller to continue reading r until EOF as a parent-exit sentinel.
func readWorkerKey(r io.Reader, timeout time.Duration) (*[workerKeySize]byte, error) {
	type readResult struct {
		buf [workerHexKeyLineSize]byte
		err error
	}
	ch := make(chan readResult, 1)
	go func() {
		var res readResult
		_, res.err = io.ReadFull(r, res.buf[:])
		ch <- res
	}()

	var res readResult
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case res = <-ch:
		case <-timer.C:
			return nil, E.New("timeout waiting for worker handshake key on stdin")
		}
	} else {
		res = <-ch
	}
	defer zeroBytes(res.buf[:])

	if res.err != nil {
		return nil, E.Cause(res.err, "read worker handshake key")
	}
	if res.buf[workerHexKeyLineSize-1] != '\n' {
		return nil, E.New("worker handshake key line must end with LF")
	}
	var key [workerKeySize]byte
	n, err := hex.Decode(key[:], res.buf[:workerKeySize*2])
	if err != nil || n != workerKeySize {
		zeroBytes(key[:])
		return nil, E.New("invalid hex worker handshake key")
	}
	return &key, nil
}

func computeWorkerMAC(key *[workerKeySize]byte, domain string, clientNonce, serverNonce []byte, windowPID, workerPID uint32) []byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(domain))
	mac.Write(clientNonce)
	mac.Write(serverNonce)
	var pids [8]byte
	binary.LittleEndian.PutUint32(pids[0:4], windowPID)
	binary.LittleEndian.PutUint32(pids[4:8], workerPID)
	mac.Write(pids[:])
	return mac.Sum(nil)
}

func workerServerHandshake(conn net.Conn, key *[workerKeySize]byte, windowPID, workerPID uint32) error {
	if err := conn.SetDeadline(time.Now().Add(workerHandshakeTimeout)); err != nil {
		return err
	}
	var hello [len(workerHandshakeMagic) + workerNonceSize]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil {
		return E.Cause(err, "read worker client hello")
	}
	if subtle.ConstantTimeCompare(hello[:len(workerHandshakeMagic)], []byte(workerHandshakeMagic)) != 1 {
		return E.New("invalid worker handshake magic")
	}
	clientNonce := hello[len(workerHandshakeMagic):]

	var serverNonce [workerNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, serverNonce[:]); err != nil {
		return E.Cause(err, "generate worker server nonce")
	}
	serverMAC := computeWorkerMAC(key, workerDomainServer, clientNonce, serverNonce[:], windowPID, workerPID)

	var reply [workerNonceSize + workerMACSize]byte
	copy(reply[:workerNonceSize], serverNonce[:])
	copy(reply[workerNonceSize:], serverMAC)
	if _, err := conn.Write(reply[:]); err != nil {
		return E.Cause(err, "write worker server handshake")
	}

	var clientMAC [workerMACSize]byte
	if _, err := io.ReadFull(conn, clientMAC[:]); err != nil {
		return E.Cause(err, "read worker client MAC")
	}
	expectedClientMAC := computeWorkerMAC(key, workerDomainClient, clientNonce, serverNonce[:], windowPID, workerPID)
	if !hmac.Equal(clientMAC[:], expectedClientMAC) {
		return E.New("worker client MAC mismatch")
	}
	return conn.SetDeadline(time.Time{})
}

func workerClientHandshake(conn net.Conn, key *[workerKeySize]byte, windowPID, workerPID uint32) error {
	if err := conn.SetDeadline(time.Now().Add(workerHandshakeTimeout)); err != nil {
		return err
	}
	var clientNonce [workerNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, clientNonce[:]); err != nil {
		return E.Cause(err, "generate worker client nonce")
	}
	var hello [len(workerHandshakeMagic) + workerNonceSize]byte
	copy(hello[:len(workerHandshakeMagic)], workerHandshakeMagic)
	copy(hello[len(workerHandshakeMagic):], clientNonce[:])
	if _, err := conn.Write(hello[:]); err != nil {
		return E.Cause(err, "write worker client hello")
	}

	var reply [workerNonceSize + workerMACSize]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return E.Cause(err, "read worker server handshake")
	}
	serverNonce := reply[:workerNonceSize]
	serverMAC := reply[workerNonceSize:]
	expectedServerMAC := computeWorkerMAC(key, workerDomainServer, clientNonce[:], serverNonce, windowPID, workerPID)
	if !hmac.Equal(serverMAC, expectedServerMAC) {
		return E.New("worker server MAC mismatch")
	}

	clientMAC := computeWorkerMAC(key, workerDomainClient, clientNonce[:], serverNonce, windowPID, workerPID)
	if _, err := conn.Write(clientMAC); err != nil {
		return E.Cause(err, "write worker client MAC")
	}
	return conn.SetDeadline(time.Time{})
}

// validateWorkerUnixSocketPath checks the syntax of a Windows AF_UNIX worker socket path
// without touching the filesystem (used by both the worker and the daemon's role validator).
func validateWorkerUnixSocketPath(path string) error {
	if path == "" || len(path) > 1024 || hasControlChar(path) {
		return E.New("invalid worker unix socket path")
	}
	if strings.HasPrefix(path, `\\`) || strings.Contains(path, "/") {
		return E.New("worker unix socket path must be a local drive path")
	}
	if len(path) < 10 { // e.g. C:\a\b.sock
		return E.New("worker unix socket path is too short")
	}
	drive := path[0]
	if !((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) || path[1] != ':' || path[2] != '\\' {
		return E.New("worker unix socket path must start with a Windows drive root")
	}
	rest := path[3:]
	// Reject wildcards (*, ?), alternate data stream colons (:), and other illegal NTFS characters
	// so FindFirstFile never expands wildcards and ADS paths are rejected.
	if strings.ContainsAny(rest, `:*?"<>|`) {
		return E.New("worker unix socket path contains illegal Windows characters")
	}
	parts := strings.Split(rest, `\`)
	if len(parts) < 2 {
		return E.New("worker unix socket path must reside in a directory")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return E.New("worker unix socket path has invalid component")
		}
	}
	base := parts[len(parts)-1]
	if len(base) <= len(".sock") || !strings.EqualFold(base[len(base)-len(".sock"):], ".sock") {
		return E.New("worker unix socket path must end with .sock")
	}
	return nil
}
