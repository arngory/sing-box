//go:build with_quic

package hysteria2_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// neko: await_dial ("honest connect"). The client's TCP dial returns only after the server's answer: a destination
// the server cannot reach fails the dial itself (the SOCKS reply here, the app's SYN-ACK under a TUN), where without
// it the dial succeeded and the connection ended empty. Destinations that speak second and first both work: the
// request goes out at once, not with the client's first bytes.
func TestNekoHysteria2AwaitDial(t *testing.T) {
	// a destination that speaks second: it answers what it reads
	echo := nekoServe(t, func(conn net.Conn) {
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		conn.Write(append([]byte("echo "), buf[:n]...))
	})
	// one that speaks first
	banner := nekoServe(t, func(conn net.Conn) { conn.Write([]byte("hello")) })
	// a port nothing listens on
	closed := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: nekoFreePort(t, "tcp")}

	certificate, key := nekoSelfSigned(t)
	serverPort := nekoFreePort(t, "udp")
	nekoStartBox(t, fmt.Sprintf(`{"log":{"level":"error"},
		"inbounds":[{"type":"hysteria2","listen":"127.0.0.1","listen_port":%d,"users":[{"password":"neko"}],
			"tls":{"enabled":true,"certificate":%s,"key":%s}}],
		"outbounds":[{"type":"direct"}]}`, serverPort, nekoLines(certificate), nekoLines(key)))
	client := func(await bool) int {
		port := nekoFreePort(t, "tcp")
		nekoStartBox(t, fmt.Sprintf(`{"log":{"level":"error"},
			"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":%d}],
			"outbounds":[{"type":"hysteria2","server":"127.0.0.1","server_port":%d,"password":"neko","await_dial":%t,
				"tls":{"enabled":true,"server_name":"localhost","insecure":true}}]}`, port, serverPort, await))
		return port
	}
	awaiting, lazy := client(true), client(false)

	if reply, conn := nekoSocksReply(t, awaiting, closed); reply == 0 {
		conn.Close()
		t.Fatal("await_dial: a refused destination was reported as connected")
	}
	// without it the dial is the client's alone: connected, then nothing
	if reply, conn := nekoSocksReply(t, lazy, closed); reply != 0 {
		t.Fatalf("without await_dial the dial is not the server's: reply %d", reply)
	} else {
		conn.Close()
	}
	for _, port := range []int{awaiting, lazy} {
		reply, conn := nekoSocksReply(t, port, echo)
		if reply != 0 {
			t.Fatalf("a destination that speaks second: reply %d", reply)
		}
		conn.Write([]byte("ping"))
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		got := make([]byte, 64)
		n, err := io.ReadAtLeast(conn, got, len("echo ping"))
		conn.Close()
		if string(got[:n]) != "echo ping" {
			t.Fatalf("a destination that speaks second: %q %v", got[:n], err)
		}
		reply, conn = nekoSocksReply(t, port, banner)
		if reply != 0 {
			t.Fatalf("a destination that speaks first: reply %d", reply)
		}
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err = io.ReadAtLeast(conn, got, len("hello"))
		conn.Close()
		if string(got[:n]) != "hello" {
			t.Fatalf("a destination that speaks first: %q %v", got[:n], err)
		}
	}
}

func nekoServe(t *testing.T, handle func(net.Conn)) *net.TCPAddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr)
}

// nekoSocksReply is a SOCKS5 CONNECT to target through 127.0.0.1:port and its reply code (0: connected)
func nekoSocksReply(t *testing.T, port int, target *net.TCPAddr) (byte, net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	request := append([]byte{5, 1, 0, 5, 1, 0, 1}, target.IP.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(target.Port))
	if _, err = conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2+10)
	if _, err = io.ReadFull(conn, reply); err != nil {
		// a refused connection may close without a reply
		conn.Close()
		return 0xff, conn
	}
	conn.SetDeadline(time.Time{})
	return reply[3], conn
}
