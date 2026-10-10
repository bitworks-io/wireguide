package helper

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// eventSink records emitted automation events and fails the test if one is
// emitted while connectMu is held.
type eventSink struct {
	mu     sync.Mutex
	events []ipc.AutomationEventPayload
}

func (s *eventSink) install(t *testing.T, h *Helper) {
	h.emitAutomationFn = func(ev ipc.AutomationEventPayload) {
		if !h.connectMu.TryLock() {
			t.Errorf("automation event %+v emitted while connectMu is held", ev)
		} else {
			h.connectMu.Unlock()
		}
		s.mu.Lock()
		s.events = append(s.events, ev)
		s.mu.Unlock()
	}
}

func (s *eventSink) take() []ipc.AutomationEventPayload {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.events
	s.events = nil
	return out
}

func actions(evs []ipc.AutomationEventPayload) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Action)
	}
	return out
}

func settledHelper(t *testing.T, ssid string) (*Helper, *fakeClock, *eventSink) {
	t.Helper()
	stubNetwork(t, wifiProbe())
	h, clk := newAutomationHelper(t, ssid)
	h.done = make(chan struct{})
	t.Cleanup(h.stopSettleTimer)
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow)
	sink := &eventSink{}
	sink.install(t, h)
	return h, clk, sink
}

func TestAutomationEvent_ExecutedConnectAlwaysEmitted(t *testing.T) {
	h, _, sink := settledHelper(t, "Cafe")
	writeAutomation(t, h, map[string][]wifi.Rule{
		"Site": {{When: wifi.Condition{Type: wifi.CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: wifi.ActionConnect}},
	})
	// No tunnel store: every evaluation executes a (failing) connect.
	for i := 0; i < 3; i++ {
		h.reevaluateAutomation("test")
	}
	evs := sink.take()
	if len(evs) != 3 {
		t.Fatalf("want 3 executed connect events, got %d: %+v", len(evs), evs)
	}
	ev := evs[0]
	if ev.Tunnel != "Site" || ev.Action != ipc.AutomationActionConnect || ev.RuleIndex != 0 ||
		ev.RuleText != "SSID is not HomeWiFi" || ev.SSID != "Cafe" || !ev.Settled || ev.Error == "" || ev.At == "" {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if _, err := time.Parse(time.RFC3339, ev.At); err != nil {
		t.Fatalf("at not RFC3339: %v", err)
	}
}

func TestAutomationEvent_HeldEmittedOnlyOnChange(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, clk := newAutomationHelper(t, "Cafe")
	h.done = make(chan struct{})
	t.Cleanup(h.stopSettleTimer)
	sink := &eventSink{}
	sink.install(t, h)
	writeAutomation(t, h, map[string][]wifi.Rule{
		"Site": {{When: wifi.Condition{Type: wifi.CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: wifi.ActionConnect}},
	})
	logs := captureLogs(t)
	// Unsettled: held, three times -> one event, one Info line.
	for i := 0; i < 3; i++ {
		h.reevaluateAutomation("test")
	}
	if got := actions(sink.take()); len(got) != 1 || got[0] != ipc.AutomationActionHeld {
		t.Fatalf("held must be emitted once, got %v", got)
	}
	if n := strings.Count(logs.String(), "level=INFO msg=\"automation: negated rule undecidable, holding\""); n != 1 {
		t.Fatalf("held log at Info %d times, want 1:\n%s", n, logs)
	}
	// Settled: executed connect, then unsettled again -> held re-emitted
	// because the executed connect replaced the last decision.
	clk.Advance(wifi.NegationSettleWindow)
	h.reevaluateAutomation("test")
	if got := actions(sink.take()); len(got) != 1 || got[0] != ipc.AutomationActionConnect {
		t.Fatalf("want executed connect, got %v", got)
	}
	h.wifiMon.ReportExternalSSID("Cafe2") // new network, not settled
	h.reevaluateAutomation("test")
	if got := actions(sink.take()); len(got) != 1 || got[0] != ipc.AutomationActionHeld {
		t.Fatalf("held after connect must re-emit, got %v", got)
	}
}

// Repeated roam blips with the tunnel already in its desired state: each
// blip's hold is reported (event + Info line) once per episode, because the
// satisfied decision in between resets the change-only dedupe.
func TestAutomationEvent_HeldReportedEachBlipEpisode(t *testing.T) {
	h, clk, sink := settledHelper(t, "HomeWiFi")
	writeAutomation(t, h, map[string][]wifi.Rule{
		"Site": {
			{When: wifi.Condition{Type: wifi.CondSSID, SSID: "HomeWiFi"}, Do: wifi.ActionDisconnect},
			{When: wifi.Condition{Type: wifi.CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: wifi.ActionConnect},
		},
	})
	logs := captureLogs(t)
	// At home, tunnel down: disconnect already satisfied, nothing emitted.
	h.reevaluateAutomation("test")
	if evs := sink.take(); len(evs) != 0 {
		t.Fatalf("satisfied decision must not emit: %+v", evs)
	}
	for i := 0; i < 3; i++ {
		h.wifiMon.ReportExternalSSID("") // roam blip, unsettled
		h.reevaluateAutomation("test")
		h.reevaluateAutomation("test")
		evs := sink.take()
		if got := actions(evs); len(got) != 1 || got[0] != ipc.AutomationActionHeld || evs[0].RuleIndex != 1 {
			t.Fatalf("episode %d: want one held(1), got %+v", i, evs)
		}
		h.wifiMon.ReportExternalSSID("HomeWiFi")
		clk.Advance(wifi.NegationSettleWindow)
		h.reevaluateAutomation("test")
		if evs := sink.take(); len(evs) != 0 {
			t.Fatalf("episode %d: settle back home must not emit: %+v", i, evs)
		}
	}
	if n := strings.Count(logs.String(), "level=INFO msg=\"automation: negated rule undecidable, holding\""); n != 3 {
		t.Fatalf("hold logged at Info %d times, want 3 (once per episode):\n%s", n, logs)
	}
}

func TestAutomationEvent_LatchedOnChangeAndNoDecisionClears(t *testing.T) {
	h, _, sink := settledHelper(t, "Home")
	writeAutomation(t, h, map[string][]wifi.Rule{
		"vpn": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Office"}, Do: wifi.ActionConnect}},
	})
	h.manualOverride["vpn"] = manualLatch{identity: "ssid:Home", disconnected: true}
	h.reevaluateAutomation("test")
	h.reevaluateAutomation("test")
	evs := sink.take()
	if got := actions(evs); len(got) != 1 || got[0] != ipc.AutomationActionLatched || evs[0].RuleIndex != -1 {
		t.Fatalf("latched must be emitted once with rule_index -1, got %+v", evs)
	}
	// Latch gone, rule doesn't match -> no decision: entry cleared.
	delete(h.manualOverride, "vpn")
	h.reevaluateAutomation("test")
	if evs := sink.take(); len(evs) != 0 {
		t.Fatalf("no decision must not emit: %+v", evs)
	}
	h.autoEvMu.Lock()
	_, has := h.lastAutoEvent["vpn"]
	h.autoEvMu.Unlock()
	if has {
		t.Fatal("no decision must clear the last-emitted entry")
	}
	// Latched again -> reported again.
	h.manualOverride["vpn"] = manualLatch{identity: "ssid:Home", disconnected: true}
	h.reevaluateAutomation("test")
	if got := actions(sink.take()); len(got) != 1 || got[0] != ipc.AutomationActionLatched {
		t.Fatalf("latched after clear must re-emit, got %v", got)
	}
}

func TestAutomationEvent_DisconnectNotUnderConnectMuAndReason(t *testing.T) {
	h, _, sink := settledHelper(t, "Home")
	writeAutomation(t, h, map[string][]wifi.Rule{
		"vpn": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Home"}, Do: wifi.ActionDisconnect}},
	})
	// Automation believes vpn is up; the real manager has nothing, so the
	// teardown reports not-connected and the tunnel counts as gone.
	h.automationActiveFn = func() []string { return []string{"vpn"} }
	h.healthOverride = map[string]string{"vpn": "on"}
	ln, err := net.Listen("unix", shortSock(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h.server = ipc.NewServer(ln)
	t.Cleanup(h.cancelShutdownTimer)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.reevaluateAutomation("race") }()
	}
	wg.Wait()
	evs := sink.take()
	if len(evs) != 4 {
		t.Fatalf("want 4 executed disconnect events, got %+v", evs)
	}
	for _, ev := range evs {
		if ev.Action != ipc.AutomationActionDisconnect || ev.RuleText != "SSID is Home" {
			t.Fatalf("unexpected event %+v", ev)
		}
	}
	_, ended := h.changeSnapshot(nil)
	if ended["vpn"].Reason != domain.ChangeReasonAutomation {
		t.Fatalf("end reason = %+v, want automation", ended["vpn"])
	}
	h.mu.Lock()
	_, kept := h.healthOverride["vpn"]
	h.mu.Unlock()
	if kept {
		t.Fatal("health override must be dropped with the tunnel")
	}
}

func TestAutomationState_RenameAndDeleteHygiene(t *testing.T) {
	h, _ := newAutomationHelper(t, "x")
	dir := t.TempDir()
	h.userTunnelStore = storage.NewTunnelStore(dir)
	conf := "[Interface]\nPrivateKey = 4Lc3MwNRFEH1dkqmwLfXPJ1j0RVPtv5dQ3TlkBe1CVI=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bRgKrDAsB1OBFKLrCiB0bIvGKsPMGDqGBUl2bG0AEgY=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 10.0.0.0/24\n"
	if err := os.WriteFile(filepath.Join(dir, "old.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	h.lastAutoEvent = map[string]autoDecision{"old": {action: "held", ruleIndex: 1}, "gone": {action: "latched", ruleIndex: -1}}
	h.rulesHash = map[string]string{"old": "abc", "gone": "def"}
	h.healthOverride = map[string]string{"old": "off"}
	h.recordConnectReason("old", domain.ChangeReasonUser)
	params, _ := json.Marshal(ipc.RenameRequest{OldName: "old", NewName: "new"})
	if _, err := h.handleRename(params); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.lastAutoEvent["old"]; ok {
		t.Error("old decision must move")
	}
	if d := h.lastAutoEvent["new"]; d.action != "held" || d.ruleIndex != 1 {
		t.Errorf("decision not moved: %+v", d)
	}
	if h.rulesHash["new"] != "abc" || h.rulesHash["old"] != "" {
		t.Errorf("rules hash not moved: %v", h.rulesHash)
	}
	if h.healthOverride["new"] != "off" || h.healthOverride["old"] != "" {
		t.Errorf("health override not moved: %v", h.healthOverride)
	}
	if conn, _ := h.changeSnapshot(map[string]bool{"new": true}); conn["new"].Reason != domain.ChangeReasonUser {
		t.Errorf("change reason not moved: %v", conn)
	}

	// "gone" lost its rules (deleted): pruned.
	h.pruneAutomationDecisions(map[string][]wifi.Rule{"new": {{Do: wifi.ActionConnect}}})
	if _, ok := h.lastAutoEvent["gone"]; ok {
		t.Error("decision for tunnel without rules must be pruned")
	}
	if _, ok := h.rulesHash["gone"]; ok {
		t.Error("rules hash for tunnel without rules must be pruned")
	}
	if _, ok := h.lastAutoEvent["new"]; !ok {
		t.Error("tunnel with rules must keep its decision")
	}
	h.pruneAutomationDecisions(nil)
	if len(h.lastAutoEvent) != 0 || len(h.rulesHash) != 0 {
		t.Error("no rules at all must clear everything")
	}
}

func TestRulesLoadedLoggedOnChangeOnly(t *testing.T) {
	h, _, _ := settledHelper(t, "Home")
	rules := map[string][]wifi.Rule{
		"vpn": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Office"}, Do: wifi.ActionConnect}},
	}
	writeAutomation(t, h, rules)
	logs := captureLogs(t)
	h.reevaluateAutomation("test")
	h.reevaluateAutomation("test")
	if n := strings.Count(logs.String(), "automation: rules loaded"); n != 1 {
		t.Fatalf("rules loaded logged %d times for unchanged rules:\n%s", n, logs)
	}
	if !strings.Contains(logs.String(), "tunnel=vpn count=1") {
		t.Fatalf("missing tunnel/count:\n%s", logs)
	}
	rules["vpn"] = append(rules["vpn"], wifi.Rule{When: wifi.Condition{Type: wifi.CondNoneMatch}, Do: wifi.ActionDisconnect})
	writeAutomation(t, h, rules)
	h.reevaluateAutomation("test")
	if n := strings.Count(logs.String(), "automation: rules loaded"); n != 2 {
		t.Fatalf("changed rules must log again (got %d):\n%s", n, logs)
	}
}

func TestChangeReasons_UserDisconnectAndUndo(t *testing.T) {
	h := newWiringHelper(t, &fakeFW{})
	// Disconnecting a tunnel the manager doesn't have fails, but the tunnel
	// is gone, so the user end reason stands.
	params, _ := json.Marshal(ipc.DisconnectRequest{TunnelName: "t"})
	if _, err := h.handleDisconnect(params); err == nil {
		t.Fatal("expected not-connected error")
	}
	_, ended := h.changeSnapshot(nil)
	if ended["t"].Reason != domain.ChangeReasonUser {
		t.Fatalf("end reason %+v, want user", ended["t"])
	}
	// The status of an idle helper carries it.
	st := h.statusDTO()
	if st.RecentDisconnects["t"].Reason != domain.ChangeReasonUser {
		t.Fatalf("status recent_disconnects = %+v", st.RecentDisconnects)
	}
	// A reconnect clears the end reason and reports the connect reason.
	h.recordConnectReason("t", domain.ChangeReasonWake)
	conn, ended := h.changeSnapshot(map[string]bool{"t": true})
	if conn["t"].Reason != domain.ChangeReasonWake || len(ended) != 0 {
		t.Fatalf("after reconnect: conn=%v ended=%v", conn, ended)
	}
	// Undo restores the previous state.
	undo := h.beginDisconnectReason("t", domain.ChangeReasonAutomation)
	undo()
	if _, ended := h.changeSnapshot(nil); len(ended) != 0 {
		t.Fatalf("undo must drop the end reason: %v", ended)
	}
}

func TestChangeReasons_ExpireAndRecovery(t *testing.T) {
	h := newWiringHelper(t, &fakeFW{})
	now := time.Unix(50_000, 0)
	orig := changeNow
	changeNow = func() time.Time { return now }
	t.Cleanup(func() { changeNow = orig })
	h.beginDisconnectReason("a", domain.ChangeReasonRecovery)
	if _, ended := h.changeSnapshot(nil); ended["a"].Reason != domain.ChangeReasonRecovery {
		t.Fatalf("ended = %v", ended)
	}
	now = now.Add(recentDisconnectTTL + time.Second)
	if _, ended := h.changeSnapshot(nil); len(ended) != 0 {
		t.Fatalf("expired end reason must be pruned: %v", ended)
	}
}

func TestReconnectReasonFromTrigger(t *testing.T) {
	cases := map[reconnect.Trigger]string{
		reconnect.TriggerWake:          domain.ChangeReasonWake,
		reconnect.TriggerNetworkChange: domain.ChangeReasonNetworkChange,
		reconnect.TriggerHealthCheck:   domain.ChangeReasonHealthCheck,
		"":                             domain.ChangeReasonReconnect,
	}
	for trig, want := range cases {
		ctx := reconnect.WithTrigger(context.Background(), trig)
		if got := reconnectReason(ctx); got != want {
			t.Errorf("trigger %q -> %q, want %q", trig, got, want)
		}
	}
}

func TestHealthCheckOverridePrecedence(t *testing.T) {
	h := newWiringHelper(t, &fakeFW{})
	// No store: the value from the connect request decides.
	h.setHealthOverride("a", storage.HealthCheckOn)
	h.setHealthOverride("b", storage.HealthCheckOff)
	h.setHealthOverride("c", "bogus")
	for _, tc := range []struct {
		name   string
		global bool
		want   bool
	}{
		{"a", false, true}, {"b", true, false}, {"c", true, true}, {"c", false, false}, {"d", true, true},
	} {
		if got := h.healthCheckEnabledFor(tc.name, tc.global); got != tc.want {
			t.Errorf("%s global=%v: got %v want %v", tc.name, tc.global, got, tc.want)
		}
	}
	// With a store the sidecar is the live source and wins.
	h.userTunnelStore = storage.NewTunnelStore(t.TempDir())
	if err := h.userTunnelStore.SaveMeta("a", &storage.TunnelMeta{HealthCheck: storage.HealthCheckOff}); err != nil {
		t.Fatal(err)
	}
	if h.healthCheckEnabledFor("a", true) {
		t.Error("sidecar off must win over the connect-time on")
	}
	if err := h.userTunnelStore.SaveMeta("a", &storage.TunnelMeta{}); err != nil {
		t.Fatal(err)
	}
	if !h.healthCheckEnabledFor("a", true) || h.healthCheckEnabledFor("a", false) {
		t.Error("empty sidecar value must inherit the global setting")
	}
}

// The connect reason is visible while the connect is in flight (the GUI
// opens the history session on the Connecting tick); a failed connect
// restores the previous connect reason, and the earlier disconnect's end
// reason is dropped as the attempt starts so it cannot close the new
// (failed) session.
func TestBeginConnectReasonVisibleDuringConnectAndUndo(t *testing.T) {
	h := newWiringHelper(t, &fakeFW{})
	h.recordConnectReason("a", domain.ChangeReasonUser)
	h.beginDisconnectReason("a", domain.ChangeReasonUser)

	commit, undo := h.beginConnectReason("a", domain.ChangeReasonAutomation)
	conn, _ := h.changeSnapshot(map[string]bool{"a": true})
	if conn["a"].Reason != domain.ChangeReasonAutomation {
		t.Fatalf("in-flight connect reason = %+v", conn["a"])
	}
	undo()
	conn, ended := h.changeSnapshot(map[string]bool{"a": true})
	if conn["a"].Reason != domain.ChangeReasonUser {
		t.Fatalf("undo must restore the previous reason, got %+v", conn["a"])
	}
	if _, ended := h.changeSnapshot(nil); len(ended) != 0 {
		t.Fatalf("failed connect must not resurrect the earlier disconnect's end reason: %v", ended)
	}
	_ = ended

	commit, _ = h.beginConnectReason("a", domain.ChangeReasonHealthCheck)
	commit()
	conn, _ = h.changeSnapshot(map[string]bool{"a": true})
	if conn["a"].Reason != domain.ChangeReasonHealthCheck {
		t.Fatalf("committed reason = %+v", conn["a"])
	}
	if _, ended := h.changeSnapshot(nil); len(ended) != 0 {
		t.Fatalf("successful connect must drop the end reason: %v", ended)
	}

	// A first-ever connect that fails leaves no reason behind.
	_, undo = h.beginConnectReason("b", domain.ChangeReasonUser)
	undo()
	if conn, _ := h.changeSnapshot(map[string]bool{"b": true}); len(conn) != 0 {
		t.Fatalf("undo of first connect must leave nothing: %v", conn)
	}
}
