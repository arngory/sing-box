//go:build with_quic

package hysteria2_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// neko: a Hysteria2 connection whose path is gone (the node's conntrack entry or the NAT's binding lost while the
// phone slept, the node restarted; salamander has no stateless reset) is closed by the client within seconds of
// sending into it, not at the idle timeout (60 s on a raycontrol row), and the next dial takes a new one. A live
// connection to a slow destination (12 s, past the 10 s the check waits at least) stays.
func TestNekoHysteria2DeadPath(t *testing.T) {
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
				if bytes.HasPrefix(question[:n], []byte("slow")) {
					time.Sleep(12 * time.Second)
				}
				conn.Write(append([]byte("answer to "), question[:n]...))
			}()
		}
	}()
	certificate, key := nekoSelfSigned(t)
	serverPort, socksPort := nekoFreePort(t, "udp"), nekoFreePort(t, "tcp")
	nekoStartBox(t, fmt.Sprintf(`{"log":{"level":"error"},
		"inbounds":[{"type":"hysteria2","listen":"127.0.0.1","listen_port":%d,"users":[{"password":"neko"}],
			"obfs":{"type":"salamander","password":"neko"},
			"tls":{"enabled":true,"certificate":%s,"key":%s}}],
		"outbounds":[{"type":"direct"}]}`, serverPort, nekoLines(certificate), nekoLines(key)))
	relay := newNekoRelay(t, serverPort)
	// as a raycontrol row with obfs: no Chrome parrot, the 60 s idle timeout and the 25 s keepalive hold
	nekoStartBox(t, fmt.Sprintf(`{"log":{"level":"error"},
		"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":%d}],
		"outbounds":[{"type":"hysteria2","server":"127.0.0.1","server_port":%d,"password":"neko",
			"obfs":{"type":"salamander","password":"neko"},
			"idle_timeout":"60s","keep_alive_period":"25s","disable_chrome_parrot":true,
			"tls":{"enabled":true,"server_name":"localhost","insecure":true}}]}`, socksPort, relay.port))
	address := target.Addr().(*net.TCPAddr)

	ask := func(question string, wait time.Duration) error {
		conn := nekoSocksConnect(t, socksPort, address)
		defer conn.Close()
		if _, err := conn.Write([]byte(question)); err != nil {
			return err
		}
		conn.SetReadDeadline(time.Now().Add(wait))
		answer := make([]byte, 64)
		n, err := io.ReadAtLeast(conn, answer, len("answer to ")+len(question))
		if err != nil {
			return err
		}
		if want := "answer to " + question; string(answer[:n]) != want {
			return fmt.Errorf("answer %q, want %q", answer[:n], want)
		}
		return nil
	}
	if err := ask("one", 10*time.Second); err != nil {
		t.Fatal("before the cut: ", err)
	}
	if err := ask("slow one", 20*time.Second); err != nil {
		t.Fatal("a live connection to a slow destination: ", err)
	}
	if relay.flows() != 1 {
		t.Fatalf("%d flows through the relay before the cut, want the one connection", relay.flows())
	}

	relay.cut()
	start := time.Now()
	for {
		err := ask("two", 3*time.Second)
		if err == nil {
			break
		}
		if time.Since(start) > 40*time.Second {
			t.Fatal("no answer 40 s after the path went: ", err)
		}
	}
	elapsed := time.Since(start)
	t.Logf("answered %v after the path went", elapsed.Round(100*time.Millisecond))
	if elapsed > 20*time.Second {
		t.Fatalf("answered %v after the path went: the dead connection was not closed before its idle timeout", elapsed)
	}
	if relay.flows() != 2 {
		t.Fatalf("%d flows through the relay, want a second connection", relay.flows())
	}
}

// nekoRelay forwards UDP to the server, a socket upstream for each client address, as a NAT does. After cut, the
// flows it had are dropped both ways and new ones pass: a binding or a conntrack entry gone.
type nekoRelay struct {
	port   int
	access sync.Mutex
	conns  map[string]*nekoRelayFlow
	count  int
}

type nekoRelayFlow struct {
	upstream *net.UDPConn
	dead     bool
}

func newNekoRelay(t *testing.T, serverPort int) *nekoRelay {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relay := &nekoRelay{port: listener.LocalAddr().(*net.UDPAddr).Port, conns: map[string]*nekoRelayFlow{}}
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort}
	t.Cleanup(func() {
		listener.Close()
		relay.access.Lock()
		for _, flow := range relay.conns {
			flow.upstream.Close()
		}
		relay.access.Unlock()
	})
	go func() {
		packet := make([]byte, 65535)
		for {
			n, client, err := listener.ReadFromUDP(packet)
			if err != nil {
				return
			}
			relay.access.Lock()
			flow := relay.conns[client.String()]
			if flow == nil {
				upstream, err := net.DialUDP("udp", nil, server)
				if err != nil {
					relay.access.Unlock()
					continue
				}
				flow = &nekoRelayFlow{upstream: upstream}
				relay.conns[client.String()] = flow
				relay.count++
				go func() {
					back := make([]byte, 65535)
					for {
						n, err := upstream.Read(back)
						if err != nil {
							return
						}
						relay.access.Lock()
						dead := flow.dead
						relay.access.Unlock()
						if !dead {
							listener.WriteToUDP(back[:n], client)
						}
					}
				}()
			}
			dead := flow.dead
			relay.access.Unlock()
			if !dead {
				flow.upstream.Write(packet[:n])
			}
		}
	}()
	return relay
}

func (r *nekoRelay) cut() {
	r.access.Lock()
	defer r.access.Unlock()
	for _, flow := range r.conns {
		flow.dead = true
	}
}

func (r *nekoRelay) flows() int {
	r.access.Lock()
	defer r.access.Unlock()
	return r.count
}
