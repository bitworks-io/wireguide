package reconnect

import (
	"context"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// chanNetworkDetector delivers primary-interface changes on demand.
type chanNetworkDetector struct{ ch chan struct{} }

func (d *chanNetworkDetector) Start()                      {}
func (d *chanNetworkDetector) Stop()                       {}
func (d *chanNetworkDetector) ChangeChan() <-chan struct{} { return d.ch }

// triggerRecorder is a ReconnectFunc that reports the trigger kind its ctx
// carries, then succeeds.
func triggerRecorder() (ReconnectFunc, chan Trigger) {
	got := make(chan Trigger, 4)
	return func(ctx context.Context, _ string) error {
		got <- TriggerFromContext(ctx)
		return nil
	}, got
}

func expectTrigger(t *testing.T, got chan Trigger, want Trigger) {
	t.Helper()
	select {
	case tr := <-got:
		if tr != want {
			t.Fatalf("reconnect trigger = %q, want %q", tr, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("reconnectFn not called (want trigger %q)", want)
	}
}

func TestTriggerContextRoundTrip(t *testing.T) {
	if got := TriggerFromContext(context.Background()); got != "" {
		t.Fatalf("empty ctx trigger = %q", got)
	}
	//nolint:staticcheck // nil ctx must be tolerated
	if got := TriggerFromContext(nil); got != "" {
		t.Fatalf("nil ctx trigger = %q", got)
	}
	ctx := WithTrigger(context.Background(), TriggerWake)
	if got := TriggerFromContext(ctx); got != TriggerWake {
		t.Fatalf("trigger = %q", got)
	}
	if WithTrigger(ctx, "") != ctx {
		t.Fatal("empty trigger should leave ctx unchanged")
	}
}

func TestWakeReconnectCarriesWakeTrigger(t *testing.T) {
	fn, got := triggerRecorder()
	mon, mgr, sd := newTestMonitor(testConfig(), fn)
	mon.networkDetector = nil
	mgr.setConnected(true, "alpha")
	mon.Start()
	defer mon.Stop()
	sd.sendWake()
	expectTrigger(t, got, TriggerWake)
}

func TestNetworkChangeReconnectCarriesNetworkTrigger(t *testing.T) {
	fn, got := triggerRecorder()
	mon, mgr, _ := newTestMonitor(testConfig(), fn)
	nd := &chanNetworkDetector{ch: make(chan struct{}, 1)}
	mon.networkDetector = nd
	mgr.setConnected(true, "alpha")
	mon.Start()
	defer mon.Stop()
	nd.ch <- struct{}{}
	expectTrigger(t, got, TriggerNetworkChange)
}

func TestStaleHandshakeReconnectCarriesHealthTrigger(t *testing.T) {
	fn, got := triggerRecorder()
	mon, mgr, _ := newTestMonitor(testConfig(), fn)
	mon.networkDetector = nil
	mgr.mu.Lock()
	mgr.connected = true
	mgr.allStatuses = []*tunnel.ConnectionStatus{{
		State:             domain.StateConnected,
		TunnelName:        "alpha",
		LastHandshakeTime: time.Now().Add(-10 * time.Minute),
	}}
	mgr.mu.Unlock()
	mon.Start()
	defer mon.Stop()
	mon.checkStaleHandshakes(3 * time.Minute)
	expectTrigger(t, got, TriggerHealthCheck)
}

func TestPingHealthReconnectCarriesHealthTrigger(t *testing.T) {
	fn, got := triggerRecorder()
	mon, mgr, _ := newTestMonitor(testConfig(), fn)
	mon.networkDetector = nil
	mgr.setConnected(true, "alpha")
	mon.Start()
	defer mon.Stop()
	mon.ReconnectTunnelIfIdle("alpha", nil)
	expectTrigger(t, got, TriggerHealthCheck)
}
