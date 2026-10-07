package reconnect

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// onlineDetector is a NetworkChangeDetector that also reports Online.
type onlineDetector struct {
	online atomic.Bool
	ch     chan struct{}
}

func newOnlineDetector(online bool) *onlineDetector {
	d := &onlineDetector{ch: make(chan struct{}, 1)}
	d.online.Store(online)
	return d
}

func (d *onlineDetector) Start()                      {}
func (d *onlineDetector) Stop()                       {}
func (d *onlineDetector) ChangeChan() <-chan struct{} { return d.ch }
func (d *onlineDetector) Online() bool                { return d.online.Load() }

// plainDetector has no Online method.
type plainDetector struct{}

func (plainDetector) Start()                      {}
func (plainDetector) Stop()                       {}
func (plainDetector) ChangeChan() <-chan struct{} { return nil }

type triggerRecorder struct {
	mu    sync.Mutex
	calls []string
	kinds []Trigger
}

func (r *triggerRecorder) fn(ctx context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, name)
	r.kinds = append(r.kinds, TriggerFromContext(ctx))
	return nil
}

func (r *triggerRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *triggerRecorder) lastKind() Trigger {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.kinds) == 0 {
		return ""
	}
	return r.kinds[len(r.kinds)-1]
}

// healthMonitor builds a running-flagged monitor with a fake clock and a
// connected tunnel "t1" whose handshake time is hs.
func healthMonitor(t *testing.T, rec *triggerRecorder, now *time.Time, hs time.Time, nd NetworkChangeDetector) (*Monitor, *mockManager) {
	t.Helper()
	mon, mgr, _ := newTestMonitor(testConfig(), rec.fn)
	mon.networkDetector = nd
	mon.now = func() time.Time { return *now }
	mon.SetHealthCheck(true)
	mgr.setConnected(true, "t1")
	mgr.setStatus(&tunnel.ConnectionStatus{
		TunnelName:        "t1",
		State:             domain.StateConnected,
		LastHandshakeTime: hs,
	})
	mon.mu.Lock()
	mon.running = true
	mon.stopCh = make(chan struct{})
	mon.mu.Unlock()
	t.Cleanup(func() {
		mon.mu.Lock()
		mon.running = false
		close(mon.stopCh)
		mon.mu.Unlock()
		mon.CancelRetry()
	})
	return mon, mgr
}

func TestHealthCheck_StaleTriggersWithKind(t *testing.T) {
	rec := &triggerRecorder{}
	now := time.Unix(1_000_000, 0)
	mon, _ := healthMonitor(t, rec, &now, now.Add(-4*time.Minute), newOnlineDetector(true))
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "stale handshake reconnect", func() bool { return rec.count() > 0 })
	if k := rec.lastKind(); k != TriggerHealthCheck {
		t.Fatalf("trigger kind = %q, want %q", k, TriggerHealthCheck)
	}
}

func TestHealthCheck_WakeGraceSkipsThenDeadTunnelTriggers(t *testing.T) {
	rec := &triggerRecorder{}
	wake := time.Unix(2_000_000, 0)
	now := wake
	// Handshake from long before sleep.
	mon, _ := healthMonitor(t, rec, &now, wake.Add(-2*time.Hour), newOnlineDetector(true))
	mon.noteWake()

	// Inside the grace window: skipped.
	now = wake.Add(60 * time.Second)
	mon.checkHandshakes(now)
	// Just after grace, but less than the threshold since the wake: age is
	// measured from the wake, so still not stale.
	now = wake.Add(120 * time.Second)
	mon.checkHandshakes(now)
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatalf("health check fired within wake grace / threshold-since-wake: %d calls", rec.count())
	}

	// A genuinely dead tunnel (no handshake since wake) triggers once the
	// threshold has elapsed since the wake, i.e. within threshold + grace.
	now = wake.Add(handshakeStaleThreshold + time.Second)
	if now.Sub(wake) > handshakeStaleThreshold+wakeGrace {
		t.Fatal("test setup: beyond threshold + grace")
	}
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "dead tunnel reconnect after grace", func() bool { return rec.count() > 0 })
}

func TestHealthCheck_RecentHandshakeAfterWakeNotStale(t *testing.T) {
	rec := &triggerRecorder{}
	wake := time.Unix(3_000_000, 0)
	now := wake
	mon, mgr := healthMonitor(t, rec, &now, wake.Add(-2*time.Hour), newOnlineDetector(true))
	mon.noteWake()
	// Tunnel handshook after the wake.
	mgr.setStatus(&tunnel.ConnectionStatus{TunnelName: "t1", State: domain.StateConnected, LastHandshakeTime: wake.Add(100 * time.Second)})
	now = wake.Add(200 * time.Second)
	mon.checkHandshakes(now)
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatal("fresh post-wake handshake treated as stale")
	}
}

func TestHealthCheck_OfflineSuppressed(t *testing.T) {
	rec := &triggerRecorder{}
	now := time.Unix(4_000_000, 0)
	nd := newOnlineDetector(false)
	mon, _ := healthMonitor(t, rec, &now, now.Add(-10*time.Minute), nd)
	mon.checkHandshakes(now)
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatal("health check ran while offline")
	}
	nd.online.Store(true)
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "reconnect once back online", func() bool { return rec.count() > 0 })
}

func TestHealthCheck_DetectorWithoutOnlineCountsAsOnline(t *testing.T) {
	rec := &triggerRecorder{}
	now := time.Unix(5_000_000, 0)
	mon, _ := healthMonitor(t, rec, &now, now.Add(-10*time.Minute), plainDetector{})
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "reconnect without online reporter", func() bool { return rec.count() > 0 })
}

func TestHealthCheck_PerTunnelOverride(t *testing.T) {
	cases := []struct {
		name     string
		global   bool
		override string // "on" | "off" | "inherit"
		want     bool
	}{
		{"inherit-global-on", true, "inherit", true},
		{"inherit-global-off", false, "inherit", false},
		{"on-beats-global-off", false, "on", true},
		{"off-beats-global-on", true, "off", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &triggerRecorder{}
			now := time.Unix(6_000_000, 0)
			mon, _ := healthMonitor(t, rec, &now, now.Add(-10*time.Minute), newOnlineDetector(true))
			mon.SetHealthCheck(tc.global)
			mon.SetHealthCheckFilter(func(name string, global bool) bool {
				switch tc.override {
				case "on":
					return true
				case "off":
					return false
				}
				return global
			})
			mon.checkHandshakes(now)
			if tc.want {
				waitFor(t, 2*time.Second, "override reconnect", func() bool { return rec.count() > 0 })
				return
			}
			time.Sleep(50 * time.Millisecond)
			if rec.count() != 0 {
				t.Fatal("health check ran for a disabled tunnel")
			}
		})
	}
}

func TestTriggerKinds_WakeAndNetworkChange(t *testing.T) {
	rec := &triggerRecorder{}
	mon, mgr, sd := newTestMonitor(testConfig(), rec.fn)
	nd := newOnlineDetector(true)
	mon.networkDetector = nd
	mgr.setConnected(true, "t1")
	mon.Start()
	defer mon.Stop()

	sd.sendWake()
	waitFor(t, 2*time.Second, "wake reconnect", func() bool { return rec.count() >= 1 })
	if k := rec.lastKind(); k != TriggerWake {
		t.Fatalf("wake trigger kind = %q", k)
	}
	mon.mu.Lock()
	woke := !mon.lastWake.IsZero()
	mon.mu.Unlock()
	if !woke {
		t.Fatal("wake not recorded for the health-check grace")
	}

	nd.ch <- struct{}{}
	waitFor(t, 2*time.Second, "network change reconnect", func() bool { return rec.count() >= 2 })
	if k := rec.lastKind(); k != TriggerNetworkChange {
		t.Fatalf("network trigger kind = %q", k)
	}
}

func TestReconnectTunnelIfIdle_HealthCheckKind(t *testing.T) {
	rec := &triggerRecorder{}
	mon, mgr, _ := newTestMonitor(testConfig(), rec.fn)
	mon.networkDetector = plainDetector{}
	mgr.setConnected(true, "t1")
	mon.Start()
	defer mon.Stop()
	mon.ReconnectTunnelIfIdle("t1", nil)
	waitFor(t, 2*time.Second, "ping reconnect", func() bool { return rec.count() >= 1 })
	if k := rec.lastKind(); k != TriggerHealthCheck {
		t.Fatalf("ping trigger kind = %q", k)
	}
}

// A tunnel rebuilt on wake against an unreachable peer never handshakes:
// LastHandshakeTime stays zero. It must still trigger within threshold +
// grace of the wake, measured from max(ConnectedAt, lastWake).
func TestHealthCheck_ZeroHandshakeAfterWakeTriggers(t *testing.T) {
	rec := &triggerRecorder{}
	wake := time.Unix(6_000_000, 0)
	now := wake
	mon, mgr := healthMonitor(t, rec, &now, time.Time{}, newOnlineDetector(true))
	mgr.setStatus(&tunnel.ConnectionStatus{
		TunnelName:  "t1",
		State:       domain.StateConnected,
		ConnectedAt: wake.Add(-8 * time.Hour),
	})
	mon.noteWake()

	for _, d := range []time.Duration{60 * time.Second, 120 * time.Second, handshakeStaleThreshold - time.Second} {
		now = wake.Add(d)
		mon.checkHandshakes(now)
	}
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatalf("zero-handshake tunnel flagged before threshold since wake: %d calls", rec.count())
	}

	now = wake.Add(handshakeStaleThreshold + time.Second)
	if now.Sub(wake) > handshakeStaleThreshold+wakeGrace {
		t.Fatal("test setup: beyond threshold + grace")
	}
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "zero-handshake reconnect after wake", func() bool { return rec.count() > 0 })
}

// A brand-new connect that has not handshaken yet gets the full threshold
// from ConnectedAt, then is reconnected if it still never handshakes.
func TestHealthCheck_ZeroHandshakeFreshConnectFlooredAtConnectedAt(t *testing.T) {
	rec := &triggerRecorder{}
	connected := time.Unix(7_000_000, 0)
	now := connected
	mon, mgr := healthMonitor(t, rec, &now, time.Time{}, newOnlineDetector(true))
	mgr.setStatus(&tunnel.ConnectionStatus{
		TunnelName:  "t1",
		State:       domain.StateConnected,
		ConnectedAt: connected,
	})
	now = connected.Add(handshakeStaleThreshold - time.Second)
	mon.checkHandshakes(now)
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatal("fresh connect flagged before it had threshold to handshake")
	}
	now = connected.Add(handshakeStaleThreshold + time.Second)
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "fresh never-handshaking connect reconnect", func() bool { return rec.count() > 0 })
}

func TestHealthCheck_NeverHandshakingPeerBacksOff(t *testing.T) {
	rec := &triggerRecorder{}
	connected := time.Unix(8_000_000, 0)
	now := connected
	mon, mgr := healthMonitor(t, rec, &now, time.Time{}, newOnlineDetector(true))
	mgr.setStatus(&tunnel.ConnectionStatus{
		TunnelName:  "t1",
		State:       domain.StateConnected,
		ConnectedAt: connected,
	})
	now = connected.Add(handshakeStaleThreshold + time.Second)
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "first no-handshake reconnect", func() bool { return rec.count() == 1 })

	// The reconnect "succeeded" (new ConnectedAt) but the peer still never
	// answers: the next attempt waits twice as long, not one more threshold.
	reconnected := now
	mgr.setStatus(&tunnel.ConnectionStatus{
		TunnelName:  "t1",
		State:       domain.StateConnected,
		ConnectedAt: reconnected,
	})
	now = reconnected.Add(handshakeStaleThreshold + time.Second)
	mon.checkHandshakes(now)
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 1 {
		t.Fatalf("retried after one threshold despite backoff: %d triggers", rec.count())
	}
	now = reconnected.Add(2*handshakeStaleThreshold + time.Second)
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "second no-handshake reconnect after backoff", func() bool { return rec.count() == 2 })
}

func TestHealthCheck_NoHandshakeBackoffCapsAndResets(t *testing.T) {
	m := &Monitor{}
	for i := 0; i < 10; i++ {
		m.noteNoHandshakeReconnect("t1")
	}
	if got, want := m.staleThresholdFor("t1", true), handshakeStaleThreshold<<maxNoHandshakeBackoff; got != want {
		t.Fatalf("capped threshold = %v, want %v", got, want)
	}
	// A completed handshake ends the streak.
	if got := m.staleThresholdFor("t1", false); got != handshakeStaleThreshold {
		t.Fatalf("threshold after handshake = %v", got)
	}
	if got := m.staleThresholdFor("t1", true); got != handshakeStaleThreshold {
		t.Fatalf("streak not reset by handshake: %v", got)
	}
	// An explicit cancel (user disconnect) ends it too.
	m.noteNoHandshakeReconnect("t2")
	m.retries = map[string]*retryState{}
	m.CancelRetryFor("t2")
	if got := m.staleThresholdFor("t2", true); got != handshakeStaleThreshold {
		t.Fatalf("streak not reset by cancel: %v", got)
	}
}
