package helper

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// connectReasonOf is what statusDTO would report as name's
// last_change_reason while it is listed.
func connectReasonOf(h *Helper, name string) string {
	c, _ := h.changeSnapshot(map[string]bool{name: true})
	return c[name].Reason
}

// endReasonOf is name's recent_disconnects reason while it is not listed.
func endReasonOf(h *Helper, name string) string {
	_, e := h.changeSnapshot(nil)
	return e[name].Reason
}

// failingDisableFirewall fails the kill-switch suspend every connect does
// under an enabled kill switch, so a connect fails before touching the
// network. onDisable observes the helper at that moment (mid-connect).
type failingDisableFirewall struct {
	*pendingTestFirewall
	onDisable func()
}

func (f *failingDisableFirewall) DisableKillSwitch() error {
	if f.onDisable != nil {
		f.onDisable()
	}
	return errors.New("blocked")
}

func newFailingConnectHelper(t *testing.T, names ...string) (*Helper, *failingDisableFirewall) {
	t.Helper()
	h := newPendingTestHelper(t, names...)
	fw := &failingDisableFirewall{pendingTestFirewall: &pendingTestFirewall{killSwitch: true}}
	h.firewall = fw
	return h, fw
}

func stubReconnectConnect(t *testing.T, fn func(h *Helper, ctx context.Context, cfg *domain.WireGuardConfig) error) {
	t.Helper()
	prev := reconnectConnect
	reconnectConnect = fn
	t.Cleanup(func() { reconnectConnect = prev })
}

func TestBeginConnectReason_UndoRestoresPrevious(t *testing.T) {
	h := &Helper{}
	h.beginConnectReason("alpha", domain.ChangeReasonUser)
	undo := h.beginConnectReason("alpha", domain.ChangeReasonWake)
	if got := connectReasonOf(h, "alpha"); got != domain.ChangeReasonWake {
		t.Fatalf("reason = %q", got)
	}
	undo()
	if got := connectReasonOf(h, "alpha"); got != domain.ChangeReasonUser {
		t.Fatalf("undo left %q, want the earlier user reason", got)
	}
	undo = h.beginConnectReason("bravo", domain.ChangeReasonAutomation)
	undo()
	if got := connectReasonOf(h, "bravo"); got != "" {
		t.Fatalf("undo of a first record left %q", got)
	}
}

// A connect attempt drops the previous session's end reason, so a session
// the GUI opens on the Connecting tick is not closed with it.
func TestBeginConnectReason_ClearsEndReason(t *testing.T) {
	h := &Helper{}
	h.beginDisconnectReason("alpha", domain.ChangeReasonAutomation)
	undo := h.beginConnectReason("alpha", domain.ChangeReasonUser)
	undo()
	if got := endReasonOf(h, "alpha"); got != "" {
		t.Fatalf("end reason %q survived a new connect attempt", got)
	}
}

func TestRecentDisconnects_Expire(t *testing.T) {
	now := time.Unix(50_000, 0)
	prev := changeNow
	changeNow = func() time.Time { return now }
	t.Cleanup(func() { changeNow = prev })

	h := &Helper{}
	h.beginDisconnectReason("alpha", domain.ChangeReasonAutomation)
	now = now.Add(recentDisconnectTTL - time.Second)
	if got := endReasonOf(h, "alpha"); got != domain.ChangeReasonAutomation {
		t.Fatalf("end reason gone before the TTL: %q", got)
	}
	// Listed again (reconnected out of band): hidden but not pruned.
	if _, e := h.changeSnapshot(map[string]bool{"alpha": true}); e["alpha"].Reason != "" {
		t.Fatal("an active tunnel must not appear in recent_disconnects")
	}
	now = now.Add(2 * time.Second)
	if got := endReasonOf(h, "alpha"); got != "" {
		t.Fatalf("end reason %q outlived the TTL", got)
	}
	h.changeMu.Lock()
	n := len(h.endReasons)
	h.changeMu.Unlock()
	if n != 0 {
		t.Fatal("expired end reason was not pruned")
	}
}

// handleConnect records "user" before the connect and restores the
// previous reason when the connect fails.
func TestHandleConnect_ReasonRecordedFirstAndRestoredOnFailure(t *testing.T) {
	h, fw := newFailingConnectHelper(t, "alpha")
	h.beginConnectReason("alpha", domain.ChangeReasonAutomation)
	var during string
	fw.onDisable = func() { during = connectReasonOf(h, "alpha") }
	cfg, err := h.userTunnelStore.Load("alpha")
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(ipc.ConnectRequest{Config: cfg})
	if _, err := h.handleConnect(params); err == nil {
		t.Fatal("connect should fail")
	}
	if during != domain.ChangeReasonUser {
		t.Fatalf("reason during connect = %q, want user", during)
	}
	if got := connectReasonOf(h, "alpha"); got != domain.ChangeReasonAutomation {
		t.Fatalf("failed connect left %q, want the earlier automation reason", got)
	}
}

func TestAutomationConnect_ReasonRecordedFirstAndRestoredOnFailure(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, fw := newFailingConnectHelper(t, "alpha")
	h.emitAutomationFn = func(ipc.AutomationEventPayload) {}
	var during string
	fw.onDisable = func() { during = connectReasonOf(h, "alpha") }
	h.automationConnect("alpha", "test", automation.NetworkContext{SSID: "HomeWiFi"}, nil, -1)
	if during != domain.ChangeReasonAutomation {
		t.Fatalf("reason during connect = %q, want automation", during)
	}
	if got := connectReasonOf(h, "alpha"); got != "" {
		t.Fatalf("failed automation connect left %q", got)
	}
}

func TestReconnectFn_SingleTunnelRecordsTriggerReason(t *testing.T) {
	cases := []struct {
		trigger reconnect.Trigger
		want    string
	}{
		{reconnect.TriggerWake, domain.ChangeReasonWake},
		{reconnect.TriggerNetworkChange, domain.ChangeReasonNetworkChange},
		{reconnect.TriggerHealthCheck, domain.ChangeReasonHealthCheck},
		{"", domain.ChangeReasonReconnect},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			h := newPendingTestHelper(t)
			h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
			var during string
			stubReconnectConnect(t, func(h *Helper, _ context.Context, cfg *domain.WireGuardConfig) error {
				during = connectReasonOf(h, cfg.Name)
				return nil
			})
			ctx := reconnect.WithTrigger(context.Background(), tc.trigger)
			if err := h.reconnectFn(ctx, "alpha"); err != nil {
				t.Fatal(err)
			}
			if during != tc.want || connectReasonOf(h, "alpha") != tc.want {
				t.Fatalf("reason during=%q after=%q, want %q", during, connectReasonOf(h, "alpha"), tc.want)
			}
		})
	}
}

// A failed retry, and one that found the tunnel already up (a GUI connect
// raced it), keep the reason that was there.
func TestReconnectFn_FailureAndAlreadyConnectedRestoreReason(t *testing.T) {
	for name, connErr := range map[string]error{
		"failure":           errors.New("no route"),
		"already_connected": &domain.TunnelError{Kind: domain.ErrAlreadyConnected, Message: "up"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newPendingTestHelper(t)
			h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
			h.beginConnectReason("alpha", domain.ChangeReasonUser)
			stubReconnectConnect(t, func(*Helper, context.Context, *domain.WireGuardConfig) error { return connErr })
			ctx := reconnect.WithTrigger(context.Background(), reconnect.TriggerWake)
			err := h.reconnectFn(ctx, "alpha")
			if name == "already_connected" && err != nil {
				t.Fatalf("already connected should be success: %v", err)
			}
			if got := connectReasonOf(h, "alpha"); got != domain.ChangeReasonUser {
				t.Fatalf("reason = %q, want the earlier user reason", got)
			}
		})
	}
}

func TestReconnectFn_AllTunnelsRecordTriggerReason(t *testing.T) {
	h := newPendingTestHelper(t)
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	h.activeCfgs["bravo"] = &domain.WireGuardConfig{Name: "bravo"}
	h.beginConnectReason("bravo", domain.ChangeReasonUser)
	stubReconnectConnect(t, func(_ *Helper, _ context.Context, cfg *domain.WireGuardConfig) error {
		if cfg.Name == "bravo" {
			return errors.New("no route")
		}
		return nil
	})
	ctx := reconnect.WithTrigger(context.Background(), reconnect.TriggerNetworkChange)
	_ = h.reconnectFn(ctx, "")
	if got := connectReasonOf(h, "alpha"); got != domain.ChangeReasonNetworkChange {
		t.Fatalf("alpha reason = %q", got)
	}
	if got := connectReasonOf(h, "bravo"); got != domain.ChangeReasonUser {
		t.Fatalf("failed bravo reason = %q, want the earlier user reason", got)
	}
}

// Pending desired tunnels brought up by a reconnect trigger get that
// trigger's reason; a failed one gets none.
func TestReconnectFn_PendingDesiredRecordsTriggerReason(t *testing.T) {
	h := newPendingTestHelper(t, "alpha", "bravo")
	h.pendingDesired["alpha"] = struct{}{}
	h.pendingDesired["bravo"] = struct{}{}
	stubRestoreConnect(t, "bravo")
	ctx := reconnect.WithTrigger(context.Background(), reconnect.TriggerWake)
	_ = h.reconnectFn(ctx, "")
	if got := connectReasonOf(h, "alpha"); got != domain.ChangeReasonWake {
		t.Fatalf("alpha reason = %q, want wake", got)
	}
	if got := connectReasonOf(h, "bravo"); got != "" {
		t.Fatalf("failed bravo reason = %q", got)
	}
}

func TestRestoreDesiredTunnels_RecordsRecovery(t *testing.T) {
	h := newPendingTestHelper(t, "alpha", "bravo")
	if err := saveDesiredState(h.dataDir, []string{"alpha", "bravo"}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	stubRestoreConnect(t, "bravo")
	h.restoreDesiredTunnels()
	if got := connectReasonOf(h, "alpha"); got != domain.ChangeReasonRecovery {
		t.Fatalf("alpha reason = %q, want recovery", got)
	}
	if got := connectReasonOf(h, "bravo"); got != "" {
		t.Fatalf("failed bravo reason = %q", got)
	}
}

func TestHandleDisconnect_RecordsUserEndReason(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	params, _ := json.Marshal(ipc.DisconnectRequest{TunnelName: "alpha"})
	if _, err := h.handleDisconnect(params); err != nil {
		t.Fatal(err)
	}
	if got := endReasonOf(h, "alpha"); got != domain.ChangeReasonUser {
		t.Fatalf("end reason = %q, want user", got)
	}
	// A failed teardown withdraws the reason it recorded.
	h.beginDisconnectReason("ghost", domain.ChangeReasonAutomation)
	params, _ = json.Marshal(ipc.DisconnectRequest{TunnelName: "ghost"})
	if _, err := h.handleDisconnect(params); err == nil {
		t.Fatal("disconnect of an unknown tunnel should fail")
	}
	if got := endReasonOf(h, "ghost"); got != domain.ChangeReasonAutomation {
		t.Fatalf("failed disconnect left %q, want the earlier reason", got)
	}
}

func TestDeleteConnectedProfile_RecordsUserEndReason(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h := newPendingTestHelper(t, "alpha")
	cfg, err := h.userTunnelStore.Load("alpha")
	if err != nil {
		t.Fatal(err)
	}
	h.activeCfgs["alpha"] = cfg
	params, _ := json.Marshal(ipc.DeleteRequest{TunnelName: "alpha", Disconnect: true})
	if _, err := h.handleDelete(params); err != nil {
		t.Fatal(err)
	}
	if got := endReasonOf(h, "alpha"); got != domain.ChangeReasonUser {
		t.Fatalf("end reason = %q, want user", got)
	}
}

func TestRuleDisconnect_RecordsAutomationEndReason(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	if latched, _ := h.disconnectAutoManaged("alpha"); latched {
		t.Fatal("unexpected latch")
	}
	if got := endReasonOf(h, "alpha"); got != domain.ChangeReasonAutomation {
		t.Fatalf("end reason = %q, want automation", got)
	}
}

func TestForcedDisconnect_RecordsWatchdogEndReason(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	h.handleForcedDisconnect(tunnel.NewForcedDisconnect("alpha", "utun9", "routing loop detected", nil))
	if got := endReasonOf(h, "alpha"); got != domain.ChangeReasonWatchdog {
		t.Fatalf("end reason = %q, want watchdog", got)
	}
}

func TestHandleRename_MovesChangeReasons(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.beginDisconnectReason("alpha", domain.ChangeReasonUser)
	params, _ := json.Marshal(ipc.RenameRequest{OldName: "alpha", NewName: "delta"})
	if _, err := h.handleRename(params); err != nil {
		t.Fatal(err)
	}
	if endReasonOf(h, "alpha") != "" || endReasonOf(h, "delta") != domain.ChangeReasonUser {
		t.Fatal("end reason did not follow the rename")
	}
}

// stubAllStatuses presents sts as the manager's tunnels; the ones that are
// connected, connecting or disconnecting are also its ActiveTunnels, as in
// the real manager.
func stubAllStatuses(t *testing.T, sts ...*tunnel.ConnectionStatus) {
	t.Helper()
	prevAll, prevActive := managerAllStatuses, managerActiveTunnels
	var active []string
	for _, st := range sts {
		if st.State == domain.StateConnected || st.State == domain.StateConnecting || st.State == domain.StateDisconnecting {
			active = append(active, st.TunnelName)
		}
	}
	managerAllStatuses = func(*Helper) []*tunnel.ConnectionStatus { return sts }
	managerActiveTunnels = func(*Helper) []string { return active }
	t.Cleanup(func() { managerAllStatuses, managerActiveTunnels = prevAll, prevActive })
}

// A torn-down tunnel whose manager entry lingers (Disconnected/Error) is
// already gone from ActiveTunnels — the GUI closes its session on this
// tick — so its end reason must be reported, not hidden as "active".
func TestStatusDTO_LingeringEntryStillReportsEndReason(t *testing.T) {
	h := newPendingTestHelper(t)
	h.beginConnectReason("alpha", domain.ChangeReasonUser)
	h.beginDisconnectReason("bravo", domain.ChangeReasonAutomation)
	stubAllStatuses(t,
		&tunnel.ConnectionStatus{TunnelName: "alpha", State: domain.StateConnected},
		&tunnel.ConnectionStatus{TunnelName: "bravo", State: domain.StateError})
	st := h.statusDTO()
	if st.RecentDisconnects["bravo"].Reason != domain.ChangeReasonAutomation {
		t.Fatalf("recent_disconnects = %v", st.RecentDisconnects)
	}
}

// With one tunnel up the status has no Tunnels list, so the primary itself
// must carry the reason; a tunnel that just went down travels top-level.
func TestStatusDTO_SingleTunnelCarriesReasons(t *testing.T) {
	h := newPendingTestHelper(t)
	h.beginConnectReason("alpha", domain.ChangeReasonAutomation)
	h.beginDisconnectReason("bravo", domain.ChangeReasonUser)
	stubAllStatuses(t, &tunnel.ConnectionStatus{TunnelName: "alpha", State: domain.StateConnected})
	st := h.statusDTO()
	if len(st.Tunnels) != 0 {
		t.Fatalf("single tunnel status grew a Tunnels list: %v", st.Tunnels)
	}
	if st.LastChangeReason != domain.ChangeReasonAutomation || st.LastChangeAt == "" {
		t.Fatalf("primary reason = %q at %q", st.LastChangeReason, st.LastChangeAt)
	}
	if st.RecentDisconnects["bravo"].Reason != domain.ChangeReasonUser {
		t.Fatalf("recent_disconnects = %v", st.RecentDisconnects)
	}
}

func TestStatusDTO_MultiTunnelAndIdleCarryReasons(t *testing.T) {
	h := newPendingTestHelper(t)
	h.beginConnectReason("alpha", domain.ChangeReasonUser)
	h.beginConnectReason("bravo", domain.ChangeReasonWake)
	stubAllStatuses(t,
		&tunnel.ConnectionStatus{TunnelName: "alpha", State: domain.StateConnected},
		&tunnel.ConnectionStatus{TunnelName: "bravo", State: domain.StateConnecting})
	st := h.statusDTO()
	got := map[string]string{}
	for _, ts := range st.Tunnels {
		got[ts.TunnelName] = ts.LastChangeReason
		if ts.RecentDisconnects != nil {
			t.Fatal("per-tunnel entries must not repeat recent_disconnects")
		}
	}
	if got["alpha"] != domain.ChangeReasonUser || got["bravo"] != domain.ChangeReasonWake {
		t.Fatalf("per-tunnel reasons = %v", got)
	}

	// Everything down: the idle status still says why the last one went.
	h.beginDisconnectReason("alpha", domain.ChangeReasonAutomation)
	stubAllStatuses(t)
	st = h.statusDTO()
	if st.State != domain.StateDisconnected || st.RecentDisconnects["alpha"].Reason != domain.ChangeReasonAutomation {
		t.Fatalf("idle status = %+v", st)
	}
}

// statusDTO (change snapshot) runs concurrently with connect/disconnect
// paths recording reasons under connectMu; changeMu is a leaf lock, so this
// must neither race nor deadlock.
func TestChangeReasons_ConcurrentWithStatus(t *testing.T) {
	h := newPendingTestHelper(t)
	stubAllStatuses(t, &tunnel.ConnectionStatus{TunnelName: "alpha", State: domain.StateConnected})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = h.statusDTO()
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer close(stop)
		for i := 0; i < 500; i++ {
			h.connectMu.Lock()
			undo := h.beginConnectReason("alpha", domain.ChangeReasonUser)
			undoEnd := h.beginDisconnectReason("bravo", domain.ChangeReasonAutomation)
			if i%2 == 0 {
				undo()
				undoEnd()
			}
			h.renameChangeReasons("bravo", "charlie")
			h.renameChangeReasons("charlie", "bravo")
			h.connectMu.Unlock()
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock between status and reason recording")
	}
}
