package hysteria2

import (
	"testing"
	"time"
)

// A keepalive or a request after an idle spell is no stall: its answer has diagStall to come back, however long the
// connection was idle before. Packets out with none in for diagStall are one; so is quiet both ways with streams open.
func TestStallWatch(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	type sample struct {
		in, out, open bool
		want          stallEvent
		gap           time.Duration
	}
	run := func(name string, samples []sample) {
		t.Helper()
		var w stallWatch
		for i, s := range samples {
			event, gap := w.tick(at(i+1), s.in, s.out, s.open)
			if event != s.want || (s.want != stallNone && gap != s.gap) {
				t.Errorf("%s, tick %d: %v after %v, want %v after %v", name, i+1, event, gap, s.want, s.gap)
			}
		}
	}
	idle := func(n int) (samples []sample) {
		for range n {
			samples = append(samples, sample{})
		}
		return
	}
	// 10 s idle, a keepalive, its ACK a tick later: nothing
	run("keepalive after idle", append(idle(10), sample{out: true}, sample{in: true}))
	// a request after idle, its answer two ticks later (under diagStall): nothing
	run("slow answer", append(idle(5), sample{out: true, open: true}, sample{open: true}, sample{in: true, open: true}))
	// packets out, none in: a stall diagStall after the first unanswered tick, once, then over when packets come
	run("one way", append(idle(5),
		sample{out: true, open: true},
		sample{out: true, open: true},
		sample{open: true}, // a PTO backing off: still waiting for an answer, no quiet
		sample{out: true, open: true, want: stallOneWay, gap: 3 * time.Second},
		sample{out: true, open: true},
		sample{in: true, open: true, want: stallOverOneWay, gap: 5 * time.Second},
	))
	// quiet both ways with a stream open, from the first quiet tick
	run("quiet", []sample{
		{in: true, out: true, open: true},
		{open: true},
		{open: true},
		{open: true},
		{open: true, want: stallQuiet, gap: 3 * time.Second},
		{open: true},
		{in: true, open: true, want: stallOverQuiet, gap: 5 * time.Second},
	})
	// a quiet spell logged, then a request answered within diagStall: the spell's end is logged, from its start
	run("quiet then a request", []sample{
		{in: true, open: true},
		{open: true},
		{open: true},
		{open: true},
		{open: true, want: stallQuiet, gap: 3 * time.Second},
		{out: true, open: true},
		{in: true, open: true, want: stallOverQuiet, gap: 5 * time.Second},
	})
	// a request in a quiet spell not yet logged: no quiet, the request's answer due as any
	run("short quiet then a request", []sample{
		{in: true, open: true},
		{open: true},
		{open: true},
		{out: true, open: true},
		{open: true},
		{in: true, open: true},
	})
	// idle with nothing open is not quiet
	run("idle closed", idle(10))
}
