package helper

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
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

func eventActions(evs []ipc.AutomationEventPayload) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Action)
	}
	return out
}

func settledEventHelper(t *testing.T, ssid string) (*Helper, *fakeClock, *eventSink) {
	t.Helper()
	stubNetwork(t, wifiProbe())
	h, clk := newAutomationHelper(t, ssid)
	h.done = make(chan struct{})
	h.currentNetworkState()
	clk.Advance(automation.NegationSettleWindow)
	sink := &eventSink{}
	sink.install(t, h)
	return h, clk, sink
}

const testTunnelConf = "[Interface]\nPrivateKey = 4Lc3MwNRFEH1dkqmwLfXPJ1j0RVPtv5dQ3TlkBe1CVI=\nAddress = 10.66.66.2/32\n\n[Peer]\nPublicKey = bRgKrDAsB1OBFKLrCiB0bIvGKsPMGDqGBUl2bG0AEgY=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = %s\n"

func writeTestTunnel(t *testing.T, h *Helper, name, allowed string) {
	t.Helper()
	dir := t.TempDir()
	h.userTunnelStore = storage.NewTunnelStore(dir)
	conf := strings.Replace(testTunnelConf, "%s", allowed, 1)
	if err := os.WriteFile(filepath.Join(dir, name+".conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAutomationEvent_ExecutedConnectAlwaysEmitted(t *testing.T) {
	h, _, sink := settledEventHelper(t, "CafeWiFi")
	writeAutomation(t, h, map[string][]automation.Rule{
		"office-vpn": {{When: automation.Condition{Type: automation.CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: automation.ActionConnect}},
	})
	// No tunnel store: every evaluation executes a (failing) connect, and
	// every executed connect is reported.
	for i := 0; i < 3; i++ {
		h.reevaluateAutomation("test")
	}
	evs := sink.take()
	if len(evs) != 3 {
		t.Fatalf("want 3 executed connect events, got %d: %+v", len(evs), evs)
	}
	ev := evs[0]
	if ev.Tunnel != "office-vpn" || ev.Action != ipc.AutomationActionConnect || ev.RuleIndex != 0 ||
		ev.RuleText != "SSID is not HomeWiFi" || ev.SSID != "CafeWiFi" || !ev.Settled || ev.Error == "" {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if _, err := time.Parse(time.RFC3339, ev.At); err != nil {
		t.Fatalf("at %q not RFC3339: %v", ev.At, err)
	}
	// Wire shape: rule_index present even when 0, error only when set.
	b, _ := json.Marshal(ipc.AutomationEventPayload{Tunnel: "t", Action: "held", RuleIndex: -1})
	if s := string(b); !strings.Contains(s, `"rule_index":-1`) || strings.Contains(s, `"error"`) {
		t.Fatalf("payload JSON = %s", s)
	}
}

func TestAutomationEvent_HeldEmittedOnlyOnChange(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, clk := newAutomationHelper(t, "CafeWiFi")
	h.done = make(chan struct{})
	sink := &eventSink{}
	sink.install(t, h)
	writeAutomation(t, h, map[string][]automation.Rule{
		"office-vpn": {{When: automation.Condition{Type: automation.CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: automation.ActionConnect}},
	})
	logs := captureLogs(t)
	// Unsettled: held three times -> one event, one Info line.
	for i := 0; i < 3; i++ {
		h.reevaluateAutomation("test")
	}
	if got := eventActions(sink.take()); len(got) != 1 || got[0] != ipc.AutomationActionHeld {
		t.Fatalf("held must be emitted once, got %v", got)
	}
	if n := strings.Count(logs.String(), `level=INFO msg="automation: negated rule undecidable, holding"`); n != 1 {
		t.Fatalf("held log at Info %d times, want 1:\n%s", n, logs)
	}
	// Settled: executed connect; then unsettled again -> held re-emitted
	// because the executed connect replaced the last decision.
	clk.Advance(automation.NegationSettleWindow)
	h.reevaluateAutomation("test")
	if got := eventActions(sink.take()); len(got) != 1 || got[0] != ipc.AutomationActionConnect {
		t.Fatalf("want executed connect, got %v", got)
	}
	h.wifiMon.ReportExternalSSID("CafeWiFi2") // new network, not settled
	h.reevaluateAutomation("test")
	if got := eventActions(sink.take()); len(got) != 1 || got[0] != ipc.AutomationActionHeld {
		t.Fatalf("held after connect must re-emit, got %v", got)
	}
}

// Repeated roam blips with the tunnel already in its desired state: each
// blip's hold is reported once per episode, because the satisfied decision
// in between resets the change-only dedupe.
func TestAutomationEvent_HeldReportedEachBlipEpisode(t *testing.T) {
	h, clk, sink := settledEventHelper(t, "HomeWiFi")
	writeAutomation(t, h, map[string][]automation.Rule{
		"office-vpn": {
			{When: automation.Condition{Type: automation.CondSSID, SSID: "HomeWiFi"}, Do: automation.ActionDisconnect},
			{When: automation.Condition{Type: automation.CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: automation.ActionConnect},
		},
	})
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
		if got := eventActions(evs); len(got) != 1 || got[0] != ipc.AutomationActionHeld || evs[0].RuleIndex != 1 {
			t.Fatalf("episode %d: want one held(1), got %+v", i, evs)
		}
		h.wifiMon.ReportExternalSSID("HomeWiFi")
		h.reevaluateAutomation("test") // unsettled again: still held, no event
		clk.Advance(automation.NegationSettleWindow)
		h.reevaluateAutomation("test")
		if evs := sink.take(); len(evs) != 0 {
			t.Fatalf("episode %d: settling back home must not emit: %+v", i, evs)
		}
	}
}

func TestAutomationEvent_LatchedOnChangeAndNoDecisionClears(t *testing.T) {
	h, _, sink := settledEventHelper(t, "HomeWiFi")
	writeAutomation(t, h, map[string][]automation.Rule{
		"office-vpn": {{When: automation.Condition{Type: automation.CondSSID, SSID: "CafeWiFi"}, Do: automation.ActionConnect}},
	})
	h.recordManualOverride("office-vpn", true)
	h.reevaluateAutomation("test")
	h.reevaluateAutomation("test")
	evs := sink.take()
	if got := eventActions(evs); len(got) != 1 || got[0] != ipc.AutomationActionLatched || evs[0].RuleIndex != -1 || evs[0].RuleText != "" {
		t.Fatalf("latched must be emitted once with rule_index -1, got %+v", evs)
	}
	// Latch gone, rule doesn't match -> no decision: entry cleared.
	delete(h.manualOverride, "office-vpn")
	h.reevaluateAutomation("test")
	if evs := sink.take(); len(evs) != 0 {
		t.Fatalf("no decision must not emit: %+v", evs)
	}
	h.autoEvMu.Lock()
	_, has := h.lastAutoEvent["office-vpn"]
	h.autoEvMu.Unlock()
	if has {
		t.Fatal("no decision must clear the last-recorded entry")
	}
	// Latched again -> reported again.
	h.recordManualOverride("office-vpn", true)
	h.reevaluateAutomation("test")
	if got := eventActions(sink.take()); len(got) != 1 || got[0] != ipc.AutomationActionLatched {
		t.Fatalf("latched after clear must re-emit, got %v", got)
	}
}

// Every executed rule disconnect is reported, after connectMu is released
// (the sink fails the test otherwise), even with evaluations racing.
func TestAutomationEvent_DisconnectEmittedOutsideConnectMu(t *testing.T) {
	h, _, sink := settledEventHelper(t, "HomeWiFi")
	writeAutomation(t, h, map[string][]automation.Rule{
		"home-vpn": {{When: automation.Condition{Type: automation.CondSSID, SSID: "HomeWiFi"}, Do: automation.ActionDisconnect}},
	})
	// Automation believes home-vpn is up; the real manager has nothing, so
	// the teardown reports not-connected, carried as the event's error.
	h.automationActiveFn = func() []string { return []string{"home-vpn"} }

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
		if ev.Action != ipc.AutomationActionDisconnect || ev.RuleIndex != 0 || ev.RuleText != "SSID is HomeWiFi" || ev.Error == "" {
			t.Fatalf("unexpected event %+v", ev)
		}
	}
}

// Spam guard: a disconnect rule that keeps matching a tunnel that is not up
// reports nothing, but its teardown still runs (it withdraws a pending
// restore so the tunnel isn't brought back later).
func TestAutomationEvent_DisconnectOfInactiveTunnelNotReported(t *testing.T) {
	h, _, sink := settledEventHelper(t, "HomeWiFi")
	writeAutomation(t, h, map[string][]automation.Rule{
		"home-vpn": {{When: automation.Condition{Type: automation.CondSSID, SSID: "HomeWiFi"}, Do: automation.ActionDisconnect}},
	})
	h.automationActiveFn = func() []string { return nil }
	h.mu.Lock()
	h.pendingDesired["home-vpn"] = struct{}{}
	h.mu.Unlock()
	for i := 0; i < 5; i++ {
		h.reevaluateAutomation("test")
	}
	if evs := sink.take(); len(evs) != 0 {
		t.Fatalf("disconnect of a tunnel that is not up must not be reported: %+v", evs)
	}
	h.mu.Lock()
	_, pending := h.pendingDesired["home-vpn"]
	h.mu.Unlock()
	if pending {
		t.Fatal("the teardown must still withdraw the pending restore")
	}
}

// skipped_overlap shares the legacy automation_skipped dedupe: one event
// per overlap episode; leaving the rule's network ends the episode.
func TestAutomationEvent_SkippedOverlapDedupedPerEpisode(t *testing.T) {
	h, _, sink := settledEventHelper(t, "CafeWiFi")
	localOverlapProbe = func([]string) (string, net.IP, bool) {
		return "192.168.50.0/24", net.ParseIP("192.168.50.65"), true
	}
	writeTestTunnel(t, h, "lan-vpn", "192.168.50.0/24")
	writeAutomation(t, h, map[string][]automation.Rule{
		"lan-vpn": {{When: automation.Condition{Type: automation.CondSSID, SSID: "CafeWiFi"}, Do: automation.ActionConnect}},
	})
	for i := 0; i < 3; i++ {
		h.reevaluateAutomation("test")
	}
	evs := sink.take()
	if got := eventActions(evs); len(got) != 1 || got[0] != ipc.AutomationActionSkippedOverlap ||
		evs[0].RuleIndex != 0 || evs[0].RuleText != "SSID is CafeWiFi" {
		t.Fatalf("want one skipped_overlap, got %+v", evs)
	}
	h.wifiMon.ReportExternalSSID("HomeWiFi") // rule no longer decides
	h.reevaluateAutomation("test")
	h.wifiMon.ReportExternalSSID("CafeWiFi")
	h.reevaluateAutomation("test")
	if got := eventActions(sink.take()); len(got) != 1 || got[0] != ipc.AutomationActionSkippedOverlap {
		t.Fatalf("a new overlap episode must be reported again, got %v", got)
	}
}

// skipped -> held -> skipped on the same LAN: the overlap signature
// repeats, but the decision changed, so the return to skipped is reported.
func TestAutomationEvent_SkippedOverlapAfterHoldReported(t *testing.T) {
	h, clk, sink := settledEventHelper(t, "CafeWiFi")
	localOverlapProbe = func([]string) (string, net.IP, bool) {
		return "192.168.50.0/24", net.ParseIP("192.168.50.65"), true
	}
	writeTestTunnel(t, h, "lan-vpn", "192.168.50.0/24")
	writeAutomation(t, h, map[string][]automation.Rule{
		"lan-vpn": {{When: automation.Condition{Type: automation.CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: automation.ActionConnect}},
	})
	h.reevaluateAutomation("test")
	h.wifiMon.ReportExternalSSID("") // roam blip: held
	h.reevaluateAutomation("test")
	h.wifiMon.ReportExternalSSID("CafeWiFi")
	h.reevaluateAutomation("test") // back, not settled yet: still held
	clk.Advance(automation.NegationSettleWindow)
	h.reevaluateAutomation("test")
	h.reevaluateAutomation("test")
	want := []string{ipc.AutomationActionSkippedOverlap, ipc.AutomationActionHeld, ipc.AutomationActionSkippedOverlap}
	if got := eventActions(sink.take()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// The reconnect/restore overlap guard runs under connectMu, so it sends
// only the legacy event, never event.automation.
func TestAutomationEvent_LANConflictGuardDoesNotEmitUnderConnectMu(t *testing.T) {
	h, _, sink := settledEventHelper(t, "CafeWiFi")
	localOverlapProbe = func([]string) (string, net.IP, bool) {
		return "192.168.50.0/24", net.ParseIP("192.168.50.65"), true
	}
	writeTestTunnel(t, h, "lan-vpn", "192.168.50.0/24")
	cfg, err := h.userTunnelStore.Load("lan-vpn")
	if err != nil {
		t.Fatal(err)
	}
	h.autoConnectedBy["lan-vpn"] = "CafeWiFi"
	h.connectMu.Lock()
	conflict := h.automaticLANConflict(cfg)
	h.connectMu.Unlock()
	if !conflict {
		t.Fatal("expected a LAN conflict")
	}
	if evs := sink.take(); len(evs) != 0 {
		t.Fatalf("guard must not emit event.automation: %+v", evs)
	}
}

func TestAutomationState_RenameDeleteAndPrune(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "HomeWiFi")
	writeTestTunnel(t, h, "old", "10.66.66.0/24")
	h.lastAutoEvent = map[string]autoDecision{"old": {action: "held", ruleIndex: 1}, "gone": {action: "latched", ruleIndex: -1}}
	h.rulesHash = map[string]string{"old": "abc", "gone": "def"}
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

	// Delete drops both entries.
	params, _ = json.Marshal(ipc.DeleteRequest{TunnelName: "new"})
	if _, err := h.handleDelete(params); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.lastAutoEvent["new"]; ok {
		t.Error("deleted tunnel's decision must be dropped")
	}
	if _, ok := h.rulesHash["new"]; ok {
		t.Error("deleted tunnel's rules hash must be dropped")
	}

	// "gone" lost its rules: pruned; a tunnel with rules keeps its entry.
	h.lastAutoEvent["kept"] = autoDecision{action: "held", ruleIndex: 0}
	h.pruneAutomationDecisions(map[string][]automation.Rule{"kept": {{Do: automation.ActionConnect}}})
	if _, ok := h.lastAutoEvent["gone"]; ok {
		t.Error("decision for tunnel without rules must be pruned")
	}
	if _, ok := h.rulesHash["gone"]; ok {
		t.Error("rules hash for tunnel without rules must be pruned")
	}
	if _, ok := h.lastAutoEvent["kept"]; !ok {
		t.Error("tunnel with rules must keep its decision")
	}
	h.pruneAutomationDecisions(nil)
	if len(h.lastAutoEvent) != 0 || len(h.rulesHash) != 0 {
		t.Error("no rules at all must clear everything")
	}
}

func TestRulesLoadedLoggedPerTunnelOnChangeOnly(t *testing.T) {
	h, _, _ := settledEventHelper(t, "HomeWiFi")
	rules := map[string][]automation.Rule{
		"home-vpn":   {{When: automation.Condition{Type: automation.CondSSID, SSID: "CafeWiFi"}, Do: automation.ActionConnect}},
		"office-vpn": {{When: automation.Condition{Type: automation.CondSSID, SSID: "CafeWiFi"}, Do: automation.ActionConnect}},
	}
	writeAutomation(t, h, rules)
	logs := captureLogs(t)
	h.reevaluateAutomation("test")
	h.reevaluateAutomation("test")
	if n := strings.Count(logs.String(), "automation: rules loaded"); n != 2 {
		t.Fatalf("rules loaded logged %d times, want once per tunnel:\n%s", n, logs)
	}
	if !strings.Contains(logs.String(), "tunnel=home-vpn count=1") || !strings.Contains(logs.String(), "tunnel=office-vpn count=1") {
		t.Fatalf("missing tunnel/count:\n%s", logs)
	}
	logs.Reset()
	rules["office-vpn"] = append(rules["office-vpn"], automation.Rule{When: automation.Condition{Type: automation.CondNoneMatch}, Do: automation.ActionDisconnect})
	writeAutomation(t, h, rules)
	h.reevaluateAutomation("test")
	if n := strings.Count(logs.String(), "automation: rules loaded"); n != 1 || !strings.Contains(logs.String(), "tunnel=office-vpn count=2") {
		t.Fatalf("only the changed tunnel must log again:\n%s", logs)
	}
}
