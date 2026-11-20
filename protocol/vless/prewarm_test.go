package vless

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

type fakeConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *fakeConn) Close() error {
	c.closed.Store(true)
	return nil
}

type fakeDialer struct {
	access sync.Mutex
	conns  []*fakeConn
	fail   bool
	gate   chan struct{}
}

func (d *fakeDialer) dial(ctx context.Context) (net.Conn, error) {
	if d.gate != nil {
		<-d.gate
	}
	d.access.Lock()
	defer d.access.Unlock()
	if d.fail {
		return nil, errors.New("refused")
	}
	conn := &fakeConn{}
	d.conns = append(d.conns, conn)
	return conn, nil
}

func (d *fakeDialer) count() int {
	d.access.Lock()
	defer d.access.Unlock()
	return len(d.conns)
}

func newTestPrewarm(d *fakeDialer, idle time.Duration) *prewarm {
	return newPrewarm(context.Background(), log.NewNOPFactory().Logger(), idle, d.dial)
}

// waitSpare waits for warm's goroutine to settle: a spare, or no dial in flight
func waitSettled(t *testing.T, p *prewarm) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.access.Lock()
		warming := p.warming
		p.access.Unlock()
		if !warming {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the spare's dial did not settle")
}

// One spare after a request, handed to the next; one dial however often warm is called
func TestPrewarmOneSpare(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, time.Minute)
	defer p.Close()
	if p.take() != nil {
		t.Fatal("a spare before any warm")
	}
	for i := 0; i < 5; i++ {
		p.warm()
	}
	waitSettled(t, p)
	p.warm()
	waitSettled(t, p)
	if d.count() != 1 {
		t.Fatal("dials: ", d.count())
	}
	conn := p.take()
	if conn == nil || conn != d.conns[0] {
		t.Fatal("the spare was not handed out")
	}
	if p.take() != nil {
		t.Fatal("the spare handed out twice")
	}
	if d.conns[0].closed.Load() {
		t.Fatal("the spare handed out was closed")
	}
}

// Unused, the spare is closed after idle and not opened again until the next request
func TestPrewarmIdle(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, 50*time.Millisecond)
	defer p.Close()
	p.warm()
	waitSettled(t, p)
	time.Sleep(200 * time.Millisecond)
	if !d.conns[0].closed.Load() {
		t.Fatal("the idle spare was kept")
	}
	if p.take() != nil || d.count() != 1 {
		t.Fatal("a spare after idle: dials ", d.count())
	}
}

// A spare taken just before its expiry is not closed under the request that took it
func TestPrewarmTakenBeforeExpiry(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, 30*time.Millisecond)
	defer p.Close()
	p.warm()
	waitSettled(t, p)
	conn := p.take().(*fakeConn)
	time.Sleep(100 * time.Millisecond)
	if conn.closed.Load() {
		t.Fatal("the expiry closed a spare in use")
	}
}

// A network change drops the spare and the one being dialled on the old network
func TestPrewarmReset(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, time.Minute)
	defer p.Close()
	p.warm()
	waitSettled(t, p)
	p.reset()
	if !d.conns[0].closed.Load() || p.take() != nil {
		t.Fatal("the spare outlived the reset")
	}
	d.gate = make(chan struct{})
	p.warm()
	p.reset()
	close(d.gate)
	waitSettled(t, p)
	if p.take() != nil || !d.conns[1].closed.Load() {
		t.Fatal("a spare of the old network was kept")
	}
}

// Off while the outbound is not in use; closed for good with the outbound; a failed dial leaves nothing
func TestPrewarmOffClosedFailed(t *testing.T) {
	d := &fakeDialer{}
	p := newTestPrewarm(d, time.Minute)
	p.warm()
	waitSettled(t, p)
	p.setOn(false)
	if !d.conns[0].closed.Load() {
		t.Fatal("the spare outlived setOn(false)")
	}
	p.warm()
	waitSettled(t, p)
	if d.count() != 1 {
		t.Fatal("warmed while off")
	}
	p.setOn(true)
	d.fail = true
	p.warm()
	waitSettled(t, p)
	if p.take() != nil {
		t.Fatal("a spare from a failed dial")
	}
	d.fail = false
	p.warm()
	waitSettled(t, p)
	if d.count() != 2 {
		t.Fatal("no warm after a failed one: dials ", d.count())
	}
	p.Close()
	if !d.conns[1].closed.Load() {
		t.Fatal("the spare outlived Close")
	}
	p.warm()
	waitSettled(t, p)
	if d.count() != 2 {
		t.Fatal("warmed after Close")
	}
}
