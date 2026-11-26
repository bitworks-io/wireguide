package reconnect

import (
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// neverHandshakedMonitor returns a monitor with tunnel "t1" connected at
// connectedAt that has sent txBytes and never completed a handshake.
func neverHandshakedMonitor(t *testing.T, rec *reconnectRecorder, clk *fakeClock, connectedAt time.Time, txBytes int64) (*Monitor, *mockManager) {
	t.Helper()
	mon, mgr := healthMonitor(t, rec, clk, time.Time{}, newOnlineDetector(true))
	mgr.setStatus(&tunnel.ConnectionStatus{
		TunnelName:  "t1",
		State:       domain.StateConnected,
		ConnectedAt: connectedAt,
		TxBytes:     txBytes,
	})
	return mon, mgr
}

// waitIdle waits until the monitor has no retry slot, so the next
// checkHandshakes is not suppressed by onlyIfIdle.
func waitIdle(t *testing.T, mon *Monitor) {
	t.Helper()
	waitFor(t, 2*time.Second, "retry slot cleared", func() bool {
		mon.mu.Lock()
		defer mon.mu.Unlock()
		return len(mon.retries) == 0
	})
}

func streak(mon *Monitor, name string) int {
	mon.mu.Lock()
	defer mon.mu.Unlock()
	return mon.noHandshakeStreak[name]
}

func TestNoHandshake_IdleTunnelNeverRetried(t *testing.T) {
	rec := &reconnectRecorder{}
	t0 := time.Unix(10_000_000, 0)
	clk := &fakeClock{t: t0}
	mon, _ := neverHandshakedMonitor(t, rec, clk, t0, 0)
	mon.checkHandshakes(t0.Add(24 * time.Hour))
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatalf("idle tunnel (TxBytes 0) was retried %d times", rec.count())
	}
}

func TestNoHandshake_ZeroConnectedAtSkipped(t *testing.T) {
	rec := &reconnectRecorder{}
	t0 := time.Unix(10_000_000, 0)
	mon, _ := neverHandshakedMonitor(t, rec, &fakeClock{t: t0}, time.Time{}, 148)
	mon.checkHandshakes(t0.Add(24 * time.Hour))
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatalf("tunnel without ConnectedAt was retried %d times", rec.count())
	}
}

func TestNoHandshake_RetriedAfterThresholdThenBacksOff(t *testing.T) {
	rec := &reconnectRecorder{}
	t0 := time.Unix(10_000_000, 0)
	clk := &fakeClock{t: t0}
	mon, mgr := neverHandshakedMonitor(t, rec, clk, t0, 148)

	mon.checkHandshakes(t0.Add(handshakeStaleThreshold - time.Second))
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatal("retried before the threshold")
	}

	now := t0.Add(handshakeStaleThreshold + time.Second)
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "first retry", func() bool { return rec.count() == 1 })
	waitIdle(t, mon)
	if streak(mon, "t1") != 1 {
		t.Fatalf("streak = %d, want 1", streak(mon, "t1"))
	}

	// The reconnect resets ConnectedAt; the next threshold is doubled.
	mgr.setStatus(&tunnel.ConnectionStatus{TunnelName: "t1", State: domain.StateConnected, ConnectedAt: now, TxBytes: 148})
	mon.checkHandshakes(now.Add(handshakeStaleThreshold + time.Second))
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 1 {
		t.Fatal("retried again at 180 s; backoff should require 360 s")
	}
	mon.checkHandshakes(now.Add(2*handshakeStaleThreshold + time.Second))
	waitFor(t, 2*time.Second, "second retry", func() bool { return rec.count() == 2 })
	waitIdle(t, mon)
	if streak(mon, "t1") != 2 {
		t.Fatalf("streak = %d, want 2", streak(mon, "t1"))
	}
}

func TestNoHandshake_BackoffCapped(t *testing.T) {
	mon, _, _ := newTestMonitor(testConfig(), nil)
	for i := 0; i < 10; i++ {
		mon.noteNoHandshakeReconnect("t1")
	}
	want := handshakeStaleThreshold << maxNoHandshakeBackoff
	if got := mon.staleThresholdFor("t1", true); got != want {
		t.Fatalf("threshold = %v, want cap %v", got, want)
	}
	if want != 48*time.Minute {
		t.Fatalf("cap = %v, want 48m", want)
	}
}

func TestNoHandshake_ResetOnHandshake(t *testing.T) {
	mon, _, _ := newTestMonitor(testConfig(), nil)
	mon.noteNoHandshakeReconnect("t1")
	mon.noteNoHandshakeReconnect("t1")
	if got := mon.staleThresholdFor("t1", false); got != handshakeStaleThreshold {
		t.Fatalf("threshold with handshake = %v", got)
	}
	if streak(mon, "t1") != 0 {
		t.Fatal("streak not reset by a completed handshake")
	}
}

func TestNoHandshake_ResetOnCancel(t *testing.T) {
	mon, _, _ := newTestMonitor(testConfig(), nil)
	mon.noteNoHandshakeReconnect("t1")
	mon.noteNoHandshakeReconnect("t2")
	mon.CancelRetryFor("t1")
	if streak(mon, "t1") != 0 || streak(mon, "t2") != 1 {
		t.Fatalf("CancelRetryFor: t1=%d t2=%d, want 0 and 1", streak(mon, "t1"), streak(mon, "t2"))
	}
	mon.CancelRetry()
	if streak(mon, "t2") != 0 {
		t.Fatal("CancelRetry did not reset the streak")
	}
}

func TestNoHandshake_WakeGraceStillApplies(t *testing.T) {
	rec := &reconnectRecorder{}
	t0 := time.Unix(10_000_000, 0)
	clk := &fakeClock{t: t0}
	mon, _ := neverHandshakedMonitor(t, rec, clk, t0.Add(-time.Hour), 148)
	clk.Set(t0)
	mon.noteWake()

	mon.checkHandshakes(t0.Add(60 * time.Second)) // inside grace
	// Past grace but less than the threshold since the wake: the hour-old
	// ConnectedAt must not count.
	mon.checkHandshakes(t0.Add(wakeGrace + time.Second))
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatalf("never-handshaked tunnel retried within grace/threshold-since-wake: %d", rec.count())
	}
	mon.checkHandshakes(t0.Add(handshakeStaleThreshold + time.Second))
	waitFor(t, 2*time.Second, "retry after wake threshold", func() bool { return rec.count() == 1 })
}
