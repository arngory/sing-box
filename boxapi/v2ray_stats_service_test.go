package boxapi

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func TestOutgoingConnectionStats(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = io.ReadFull(conn, make([]byte, 5))
		if err == nil {
			_, err = conn.Write([]byte("ack"))
		}
		serverDone <- err
	}()
	instance, err := box.New(box.Options{
		Context: include.Context(context.Background()),
		Options: option.Options{Outbounds: []option.Outbound{{Type: "direct", Tag: "proxy"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	stats := NewSbStatsService(option.V2RayStatsServiceOptions{Enabled: true, Outbounds: []string{"proxy"}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, instance, stats, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(conn, make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
	for direction, expected := range map[string]int64{"uplink": 5, "downlink": 3} {
		name := "outbound>>>proxy>>>traffic>>>" + direction
		value, err := stats.GetStats(ctx, name, true)
		if err != nil || value != expected {
			t.Fatalf("%s: got %d, %v; want %d", direction, value, err, expected)
		}
		value, err = stats.GetStats(ctx, name, false)
		if err != nil || value != 0 {
			t.Fatalf("%s after reset: got %d, %v", direction, value, err)
		}
	}
}

func TestDisabledStats(t *testing.T) {
	if NewSbStatsService(option.V2RayStatsServiceOptions{}) != nil {
		t.Fatal("disabled stats must be nil")
	}
}
