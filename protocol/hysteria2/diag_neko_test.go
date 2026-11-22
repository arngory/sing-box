//go:build with_quic

package hysteria2_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// neko: each QUIC connection of a Hysteria2 client logs its opening and its end, and with log_connections its
// traffic and stalls: here a path that goes away under a connection in use, packets out and none in.
func TestNekoHysteria2ConnLog(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				question := make([]byte, 64)
				n, err := conn.Read(question)
				if err != nil {
					return
				}
				conn.Write(append([]byte("answer to "), question[:n]...))
			}()
		}
	}()
	certificate, key := nekoSelfSigned(t)
	serverPort, socksPort := nekoFreePort(t, "udp"), nekoFreePort(t, "tcp")
	nekoStartBox(t, fmt.Sprintf(`{"log":{"level":"error"},
		"inbounds":[{"type":"hysteria2","listen":"127.0.0.1","listen_port":%d,"users":[{"password":"neko"}],
			"tls":{"enabled":true,"certificate":%s,"key":%s}}],
		"outbounds":[{"type":"direct"}]}`, serverPort, nekoLines(certificate), nekoLines(key)))
	relay := newNekoRelay(t, serverPort)
	logPath := filepath.Join(t.TempDir(), "client.log")
	nekoStartBox(t, fmt.Sprintf(`{"log":{"level":"info","output":%q},
		"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":%d}],
		"outbounds":[{"type":"hysteria2","server":"127.0.0.1","server_port":%d,"password":"neko","up_mbps":10,
			"log_connections":true,"tls":{"enabled":true,"server_name":"localhost","insecure":true}}]}`,
		logPath, socksPort, relay.port))
	address := target.Addr().(*net.TCPAddr)
	ask := func(question string) error {
		conn := nekoSocksConnect(t, socksPort, address)
		defer conn.Close()
		if _, err := conn.Write([]byte(question)); err != nil {
			return err
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		answer := make([]byte, 64)
		n, err := io.ReadAtLeast(conn, answer, len("answer to ")+len(question))
		if err == nil && !bytes.Equal(answer[:n], []byte("answer to "+question)) {
			err = fmt.Errorf("answer %q", answer[:n])
		}
		return err
	}
	if err := ask("one"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(11 * time.Second) // a summary line
	relay.cut()
	start := time.Now()
	for ask("two") != nil {
		if time.Since(start) > 40*time.Second {
			t.Fatal("no answer 40 s after the path went")
		}
	}
	time.Sleep(time.Second)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	t.Log(log)
	for _, want := range []string{
		`hysteria2 conn #\d+ open to 127\.0\.0\.1:\d+: (brutal at \d+|bbr standard \(node rx auto true\)).*, packet \d+ B, parrot true`,
		`hysteria2 conn #\d+: 1\ds out \d+ (B|KiB)/\d+ pkts, in \d+ (B|KiB)/\d+ pkts, lost \d+, rtt`,
		`hysteria2 conn #\d+: stall, packets out and none in for [3-9]s`,
		`hysteria2 conn #\d+ ended after \d+s: .* pkts out, .* pkts in, \d+ lost, rtt .*, [1-9]\d* streams, last in \d+s before: hysteria2: no packet back while sending`,
	} {
		if !regexp.MustCompile(want).MatchString(log) {
			t.Errorf("no line like %q", want)
		}
	}
	if strings.Count(log, " open to ") < 2 {
		t.Errorf("want a second connection after the first ended")
	}
}
