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
			nekoEcho(t, c.resolver, c.extra, c.cut)
		})
	}
}

func nekoEcho(t *testing.T, resolverSize uint16, extra map[string]any, mustCut bool) {
	workDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(workDir)
	defer os.Chdir(oldDir)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
			t.Fatal("no session: ", err)
		}
	}
	defer conn.Close()
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
