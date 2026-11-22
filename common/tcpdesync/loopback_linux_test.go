package tcpdesync_test

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tcpdesync"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func tcpInfo(t *testing.T, conn *net.TCPConn) *unix.TCPInfo {
	t.Helper()
	raw, err := conn.SyscallConn()
	require.NoError(t, err)
	var info *unix.TCPInfo
	var infoErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}))
	require.NoError(t, infoErr)
	return info
}

func socketTTL(t *testing.T, conn *net.TCPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	require.NoError(t, err)
	var ttl int
	var ttlErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		ttl, ttlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	}))
	require.NoError(t, ttlErr)
	return ttl
}

func socketOOBInline(t *testing.T, conn *net.TCPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	require.NoError(t, err)
	var value int
	require.NoError(t, raw.Control(func(fd uintptr) {
		value, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_OOBINLINE)
	}))
	return value
}

// recorder records the test hooks of one test; the tests using it do not run in parallel.
type recorder struct {
	access sync.Mutex
	ttls   []int
	plans  [][]tcpdesync.Piece
}

func record(t *testing.T) *recorder {
	r := &recorder{}
	t.Cleanup(tcpdesync.SetTestHooks(func(ttl int) {
		r.access.Lock()
		r.ttls = append(r.ttls, ttl)
		r.access.Unlock()
	}, func(pieces []tcpdesync.Piece) {
		r.access.Lock()
		r.plans = append(r.plans, pieces)
		r.access.Unlock()
	}))
	return r
}

// readAll reads what the server gets until the client closes.
func readAll(server *net.TCPConn) <-chan []byte {
	received := make(chan []byte, 1)
	go func() {
		_ = server.SetReadDeadline(time.Now().Add(10 * time.Second))
		content, _ := io.ReadAll(server)
		received <- content
	}()
	return received
}

// TestLoopbackModes: for every mode the server, without SO_OOBINLINE, reads exactly the bytes of the ClientHello;
// every piece leaves as a segment of its own; no mode sleeps when the ACK is fast.
func TestLoopbackModes(t *testing.T) {
	hello := chromeHello(t, "www.youtube.com")
	for _, mode := range []string{"split", "disorder", "oob", "disoob"} {
		t.Run(mode, func(t *testing.T) {
			r := record(t)
			strategy := mustStrategy(t, option.TCPDesyncOptions{Split: splits("1", "split", "sni+1", mode, "midsld", "split", "-3", "split")})
			client, server := loopbackPair(t)
			require.Zero(t, socketOOBInline(t, server))
			defaultTTL := socketTTL(t, client)
			received := readAll(server)
			segmentsBefore := tcpInfo(t, client).Segs_out
			conn := tcpdesync.NewConn(context.Background(), client, strategy, nil)
			start := time.Now()
			n, err := conn.Write(hello)
			elapsed := time.Since(start)
			require.NoError(t, err)
			require.Equal(t, len(hello), n)
			segments := tcpInfo(t, client).Segs_out - segmentsBefore
			require.True(t, conn.WriterReplaceable())
			require.NoError(t, client.CloseWrite())
			require.Equal(t, hello, <-received)
			require.Len(t, r.plans, 1)
			pieces := r.plans[0]
			require.Len(t, pieces, 5)
			require.GreaterOrEqual(t, int(segments), len(pieces), "segments sent")
			require.Less(t, elapsed, 150*time.Millisecond)
			t.Log(mode, ": ", len(pieces), " pieces, ", segments, " segments, ", elapsed)
			if mode == "disorder" || mode == "disoob" {
				require.Equal(t, []int{1, defaultTTL}, r.ttls)
			} else {
				require.Empty(t, r.ttls)
			}
			require.Equal(t, defaultTTL, socketTTL(t, client))
		})
	}
}

// TestLoopbackTwoWrites: a ClientHello written in two writes is held, then cut.
func TestLoopbackTwoWrites(t *testing.T) {
	r := record(t)
	hello := chromeHello(t, "www.youtube.com")
	strategy := mustStrategy(t, option.TCPDesyncOptions{Split: splits("1", "split", "sni+1", "oob"), TLSRec: []string{"sni+2"}})
	client, server := loopbackPair(t)
	received := readAll(server)
	conn := tcpdesync.NewConn(context.Background(), client, strategy, nil)
	n, err := conn.Write(hello[:100])
	require.NoError(t, err)
	require.Equal(t, 100, n)
	require.False(t, conn.WriterReplaceable())
	time.Sleep(20 * time.Millisecond)
	n, err = conn.Write(hello[100:])
	require.NoError(t, err)
	require.Equal(t, len(hello)-100, n)
	require.True(t, conn.WriterReplaceable())
	_, err = conn.Write([]byte("after"))
	require.NoError(t, err)
	require.NoError(t, client.CloseWrite())
	got := <-received
	require.Len(t, r.plans, 1)
	require.Len(t, r.plans[0], 3)
	_, payloads := records(t, got[:len(got)-len("after")])
	require.Len(t, payloads, 2)
	require.Equal(t, hello[5:], append(payloads[0], payloads[1]...))
	require.Equal(t, "after", string(got[len(got)-len("after"):]))
}

// TestLoopbackBufferTimeout: a ClientHello record that does not complete within 200 ms goes out as it is.
func TestLoopbackBufferTimeout(t *testing.T) {
	r := record(t)
	hello := chromeHello(t, "www.youtube.com")
	strategy := mustStrategy(t, option.TCPDesyncOptions{Split: splits("1", "split")})
	client, server := loopbackPair(t)
	conn := tcpdesync.NewConn(context.Background(), client, strategy, nil)
	start := time.Now()
	_, err := conn.Write(hello[:100])
	require.NoError(t, err)
	buffer := make([]byte, 100)
	require.NoError(t, server.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = io.ReadFull(server, buffer)
	require.NoError(t, err)
	waited := time.Since(start)
	require.Equal(t, hello[:100], buffer)
	require.GreaterOrEqual(t, waited, tcpdesync.BufferTimeout)
	require.Less(t, waited, tcpdesync.BufferTimeout+300*time.Millisecond)
	require.True(t, conn.WriterReplaceable())
	received := readAll(server)
	_, err = conn.Write(hello[100:])
	require.NoError(t, err)
	require.NoError(t, client.CloseWrite())
	require.Equal(t, hello[100:], <-received)
	require.Empty(t, r.plans)
}

// TestLoopbackOtherProtocols: what is neither TLS nor HTTP passes untouched, at once.
func TestLoopbackOtherProtocols(t *testing.T) {
	r := record(t)
	strategy := mustStrategy(t, option.TCPDesyncOptions{Split: splits("1", "oob")})
	client, server := loopbackPair(t)
	received := readAll(server)
	conn := tcpdesync.NewConn(context.Background(), client, strategy, nil)
	payload := []byte("SSH-2.0-OpenSSH_9.6\r\n")
	_, err := conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, client.CloseWrite())
	require.Equal(t, payload, <-received)
	require.Empty(t, r.plans)
}

func TestCapabilities(t *testing.T) {
	capabilities := tcpdesync.Capabilities()
	t.Log(capabilities)
	require.Empty(t, capabilities.Error)
	require.True(t, capabilities.TTL)
	require.True(t, capabilities.OOB)
	require.True(t, capabilities.NotSent)
}

const netnsChildEnv = "TCPDESYNC_TEST_NETNS_CHILD"

// TestDisorderDropped runs disorder on a loopback where a TTL=1 packet is dropped, as on a real first hop: the
// piece dies after the one behind it has been sent, the kernel sends it again with the restored TTL, and the server reads the stream whole. It
// needs root, unshare and iptables, and runs in a network namespace of its own.
func TestDisorderDropped(t *testing.T) {
	if os.Getenv(netnsChildEnv) == "1" {
		disorderDroppedChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, tool := range []string{"unshare", "iptables"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("needs ", tool)
		}
	}
	command := exec.Command("unshare", "-n", os.Args[0], "-test.run=^TestDisorderDropped$", "-test.v", "-test.count=1")
	command.Env = append(os.Environ(), netnsChildEnv+"=1")
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if strings.Contains(string(output), "--- SKIP") {
		t.Skip("skipped in the namespace")
	}
	require.NoError(t, err)
	require.Contains(t, string(output), "--- PASS: TestDisorderDropped")
}

func disorderDroppedChild(t *testing.T) {
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	ifreq, err := unix.NewIfreq("lo")
	require.NoError(t, err)
	require.NoError(t, unix.IoctlIfreq(socket, unix.SIOCGIFFLAGS, ifreq))
	ifreq.SetUint16(ifreq.Uint16() | unix.IFF_UP)
	require.NoError(t, unix.IoctlIfreq(socket, unix.SIOCSIFFLAGS, ifreq))
	unix.Close(socket)
	// dropped on input, after the packet has left the socket, as a first hop drops it; a drop on output fails the
	// send itself and the kernel keeps the data unsent
	rule := []string{"INPUT", "-i", "lo", "-p", "tcp", "-m", "ttl", "--ttl-eq", "1", "-j", "DROP"}
	if output, ruleErr := exec.Command("iptables", append([]string{"-A"}, rule...)...).CombinedOutput(); ruleErr != nil {
		t.Skip("iptables: ", strings.TrimSpace(string(output)))
	}

	r := record(t)
	hello := chromeHello(t, "www.youtube.com")
	strategy := mustStrategy(t, option.TCPDesyncOptions{Split: splits("1", "split", "sni+1", "disorder")})
	client, server := loopbackPair(t)
	received := readAll(server)
	conn := tcpdesync.NewConn(context.Background(), client, strategy, nil)
	start := time.Now()
	_, err = conn.Write(hello)
	elapsed := time.Since(start)
	require.NoError(t, err)
	info := tcpInfo(t, client)
	require.NoError(t, client.CloseWrite())
	require.Equal(t, hello, <-received)
	require.Len(t, r.plans, 1)
	require.Equal(t, []int{1, 64}, r.ttls)
	output, err := exec.Command("iptables", "-L", "INPUT", "-v", "-n", "-x").CombinedOutput()
	require.NoError(t, err)
	match := regexp.MustCompile(`(?m)^\s*(\d+)\s+\d+\s+DROP`).FindSubmatch(output)
	require.NotNil(t, match, string(output))
	dropped, _ := strconv.Atoi(string(match[1]))
	t.Log("dropped ", dropped, " low-TTL packets; write took ", elapsed, "; retransmits ", info.Total_retrans, "; unacked ", info.Unacked)
	require.GreaterOrEqual(t, dropped, 1)
	require.GreaterOrEqual(t, info.Total_retrans, uint32(1))
	// the write returned after the piece was sent again and acknowledged
	require.Zero(t, info.Unacked)
}
