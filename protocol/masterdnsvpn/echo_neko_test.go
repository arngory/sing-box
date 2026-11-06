//go:build with_masterdnsvpn

package masterdnsvpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"masterdnsvpn-go/embed"
)

// The client in process against the embedded server (niko-server's masterdns backend) on a local socket: MTU probes,
// the session and data both ways. Through a resolver the server's answers stay within its size; where the client's
// probes ask past it (a resolver of 700 for Niko's 500, or a client that asks 1200 of one of 1232) they go as TC, and
// the MTU the client settles on carries its data: no answer is cut once the session is up.
func TestNekoMasterDNSVPNEcho(t *testing.T) {
	for _, c := range []struct {
		name     string
		resolver uint16 // 0: directly
		extra    map[string]any
		cut      bool // the probes must meet the size
	}{
		{"direct", 0, nil, false},
		{"resolver of 1232", 1232, nil, false},
		{"resolver of 700", 700, nil, true},
		{"resolver of 1232, client of 1200", 1232, map[string]any{"max_download_mtu": 1200}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			nekoEcho(t, nekoEchoCase{resolver: c.resolver, extra: c.extra, mustCut: c.cut, session: true})
		})
	}
}

// mdseal-v1: sealed sessions through a resolver; a client that seals and a node that does not (or the other way round
// in required) get no session, the node answering bit 7 or its absence as an unknown mode.
func TestNekoMasterDNSVPNSealed(t *testing.T) {
	for _, c := range []struct {
		name, server, client string
		resolver             uint16
		session              bool
	}{
		{"optional", "optional", "optional", 0, true},
		{"required, resolver of 1232", "required", "required", 1232, true},
		{"required, resolver of 700", "required", "required", 700, true},
		{"optional node, open client", "optional", "", 1232, true},
		{"base64 sealed", "required", "required", 1232, true},
		{"node off, sealed client", "", "optional", 0, false},
		{"required node, open client", "required", "", 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			extra := map[string]any{}
			if c.client != "" {
				extra["niko_mdseal"] = c.client
			}
			if c.name == "base64 sealed" {
				extra["base_encode_data"] = true
			}
			nekoEcho(t, nekoEchoCase{resolver: c.resolver, extra: extra, seal: c.server, session: c.session})
		})
	}
}

type nekoEchoCase struct {
	resolver uint16 // 0: directly
	extra    map[string]any
	mustCut  bool   // the probes must meet the size
	seal     string // the node's mdseal mode
	session  bool   // a session must come up (else: must not, within a short wait)
}

func nekoEcho(t *testing.T, c nekoEchoCase) {
	resolverSize, extra, mustCut := c.resolver, c.extra, c.mustCut
	workDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(workDir)
	defer os.Chdir(oldDir)
	timeout := 60 * time.Second
	if !c.session {
		timeout = 12 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	key := strings.Repeat("k", 32)
	keyFile := filepath.Join(workDir, "key")
	if err = os.WriteFile(keyFile, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- embed.RunServer(ctx, embed.ServerOptions{
			Domains: []string{"v.example.com"},
			Method:  5,
			KeyFile: keyFile,
			Seal:    c.seal,
			Conn:    serverConn,
			Dial: func(timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("tcp", echo.Addr().String(), timeout)
			},
		})
	}()
	resolver := serverConn.LocalAddr().String()
	var through *nekoResolverStats
	if resolverSize != 0 {
		through = &nekoResolverStats{}
		resolver = nekoResolver(t, ctx, serverConn.LocalAddr().(*net.UDPAddr), resolverSize, through)
	}
	options := map[string]any{"mtu_test_timeout": 1.0}
	for key, value := range extra {
		options[key] = value
	}

	outbound, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "mdv", option.MasterDNSVPNOutboundOptions{
		Domains:          []string{"v.example.com"},
		Resolvers:        []string{resolver},
		Mode:             "tcp",
		EncryptionMethod: 5,
		EncryptionKey:    key,
		Extra:            options,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	if err = outbound.(*Outbound).Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	defer outbound.(*Outbound).Close()

	var conn net.Conn
	for conn == nil {
		dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err = outbound.(*Outbound).DialContext(dialCtx, "tcp", M.ParseSocksaddr("example.com:443"))
		dialCancel()
		if err != nil && ctx.Err() != nil {
			if !c.session {
				return
			}
			t.Fatal("no session: ", err)
		}
	}
	defer conn.Close()
	if !c.session {
		// a stream is set up lazily: what must not come is its data back
		conn.SetDeadline(time.Now().Add(8 * time.Second))
		conn.Write([]byte("ping"))
		if n, _ := conn.Read(make([]byte, 4)); n > 0 {
			t.Fatal("a session came up the seal modes do not allow")
		}
		return
	}
	if through != nil {
		through.sessionUp.Store(true)
	}
	data := make([]byte, 16<<10)
	rand.Read(data)
	go conn.Write(data)
	got := make([]byte, len(data))
	conn.SetReadDeadline(time.Now().Add(40 * time.Second))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("echo differs")
	}
	select {
	case err := <-serverDone:
		t.Fatal("server stopped: ", err)
	default:
	}
	if through != nil {
		if cut := through.cutInSession.Load(); cut != 0 {
			t.Fatalf("%d answers cut (TC) once the session was up: the probes found an MTU too large", cut)
		}
		if mustCut && through.cut.Load() == 0 {
			t.Fatal("no probe met the resolver's size: the test does not reach the cap")
		}
	}
}

type nekoResolverStats struct {
	sessionUp    atomic.Bool
	cut          atomic.Int32 // answers with TC
	cutInSession atomic.Int32 // of them, once the session was up
}

// nekoResolver passes queries on with its own size in their OPT, as a resolver asks, and the answers back as they are.
func nekoResolver(t *testing.T, ctx context.Context, server *net.UDPAddr, size uint16, stats *nekoResolverStats) string {
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		front.Close()
	}()
	go func() {
		// one socket to the server for each of the client's sockets, as a resolver's own ports
		backs := make(map[string]*net.UDPConn)
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			back := backs[from.String()]
			if back == nil {
				if back, err = net.DialUDP("udp", nil, server); err != nil {
					return
				}
				backs[from.String()] = back
				go func() {
					<-ctx.Done()
					back.Close()
				}()
				go func() {
					answer := make([]byte, 65535)
					for {
						n, err := back.Read(answer)
						if err != nil {
							return
						}
						if n > int(size) {
							t.Errorf("an answer of %d bytes to a requester of %d", n, size)
						}
						if n >= 4 && answer[2]&0x02 != 0 {
							stats.cut.Add(1)
							if stats.sessionUp.Load() {
								stats.cutInSession.Add(1)
							}
						}
						front.WriteToUDP(answer[:n], from)
					}
				}()
			}
			back.Write(nekoWithSize(buf[:n], size))
		}
	}()
	return front.LocalAddr().String()
}

// nekoWithSize is a query of one question and an OPT with size in the OPT.
func nekoWithSize(query []byte, size uint16) []byte {
	if len(query) < 12 || binary.BigEndian.Uint16(query[10:12]) != 1 {
		return query
	}
	end := 12
	for end < len(query) && query[end] != 0 {
		end += int(query[end]) + 1
	}
	// the question's root and type and class, then the OPT's root name and type: its class is the size
	end += 1 + 4 + 1 + 2
	if end+2 > len(query) {
		return query
	}
	out := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(out[end:end+2], size)
	return out
}

// A node that restarts mid-session knows the session no longer: its ERROR_DROP (raw, whatever the session's encoding)
// makes the client set up a new one, and the client reads the new SESSION_ACCEPT in its own encoding. Upstream's
// client reset its mode to raw there, so a base64 client never got a new session; its node alternated the
// ERROR_DROP's encoding.
func TestNekoMasterDNSVPNNodeRestart(t *testing.T) {
	for _, c := range []struct {
		name  string
		seal  string
		extra map[string]any
	}{
		{"raw", "", nil},
		{"base64", "", map[string]any{"base_encode_data": true}},
		{"base64 sealed", "required", map[string]any{"base_encode_data": true, "niko_mdseal": "required"}},
		{"sealed optional", "optional", map[string]any{"niko_mdseal": "optional"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			nekoNodeRestart(t, c.seal, c.extra)
		})
	}
}

func nekoNodeRestart(t *testing.T, seal string, extra map[string]any) {
	workDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(workDir)
	defer os.Chdir(oldDir)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	key := strings.Repeat("k", 32)
	keyFile := filepath.Join(workDir, "key")
	if err = os.WriteFile(keyFile, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := serverConn.LocalAddr().(*net.UDPAddr)
	run := func(ctx context.Context, conn *net.UDPConn) chan error {
		done := make(chan error, 1)
		go func() {
			done <- embed.RunServer(ctx, embed.ServerOptions{
				Domains: []string{"v.example.com"}, Method: 5, KeyFile: keyFile, Seal: seal, Conn: conn,
				Dial: func(timeout time.Duration) (net.Conn, error) {
					return net.DialTimeout("tcp", echo.Addr().String(), timeout)
				},
			})
		}()
		return done
	}
	firstCtx, stopFirst := context.WithCancel(ctx)
	firstDone := run(firstCtx, serverConn)

	options := map[string]any{"mtu_test_timeout": 1.0}
	for key, value := range extra {
		options[key] = value
	}
	outbound, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "mdv", option.MasterDNSVPNOutboundOptions{
		Domains: []string{"v.example.com"}, Resolvers: []string{address.String()}, Mode: "tcp",
		EncryptionMethod: 5, EncryptionKey: key, Extra: options,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	if err = outbound.(*Outbound).Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	defer outbound.(*Outbound).Close()

	roundTrip := func(stage string) {
		deadline := time.Now().Add(40 * time.Second)
		for {
			dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
			conn, err := outbound.(*Outbound).DialContext(dialCtx, "tcp", M.ParseSocksaddr("example.com:443"))
			dialCancel()
			if err == nil {
				data := make([]byte, 4<<10)
				rand.Read(data)
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				go conn.Write(data)
				got := make([]byte, len(data))
				_, err = io.ReadFull(conn, got)
				conn.Close()
				if err == nil && bytes.Equal(got, data) {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: no echo: %v", stage, err)
			}
		}
	}
	roundTrip("first node")

	// the node restarts on the same address: its sessions are gone
	stopFirst()
	<-firstDone
	serverConn.Close()
	var secondConn *net.UDPConn
	for i := 0; i < 50 && secondConn == nil; i++ {
		secondConn, err = net.ListenUDP("udp", address)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if secondConn == nil {
		t.Fatal(err)
	}
	run(ctx, secondConn)
	roundTrip("after the node's restart")
}
