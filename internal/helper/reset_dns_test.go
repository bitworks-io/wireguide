package helper

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
)

// resetFirewall records Cleanup in the shared call order.
type resetFirewall struct {
	pendingTestFirewall
	order      *[]string
	cleanupErr error
}

func (f *resetFirewall) Cleanup() error {
	*f.order = append(*f.order, "firewall")
	if f.cleanupErr != nil {
		return f.cleanupErr
	}
	f.mu.Lock()
	f.killSwitch, f.dns = false, false
	f.mu.Unlock()
	return nil
}

func (f *resetFirewall) DisableKillSwitch() error {
	*f.order = append(*f.order, "kill_switch")
	return f.pendingTestFirewall.DisableKillSwitch()
}

type resetStubs struct {
	order    []string
	live     []string
	pending  []string
	splitErr error
}

// newResetHelper stubs every OS-touching reset step; the disconnect stays the
// real disconnectHeld unless a test replaces it.
func newResetHelper(t *testing.T, names ...string) (*Helper, *resetFirewall, *resetStubs) {
	t.Helper()
	h := newPendingTestHelper(t, names...)
	st := &resetStubs{}
	fw := &resetFirewall{order: &st.order}
	h.firewall = fw
	prevLive, prevDisc, prevSplit, prevRetry, prevFlush := resetLiveTunnels, resetDisconnectAll, resetSweepSplitDNS, resetRetryPendingCleanup, resetFlushDNSCache
	t.Cleanup(func() {
		resetLiveTunnels, resetDisconnectAll, resetSweepSplitDNS, resetRetryPendingCleanup, resetFlushDNSCache = prevLive, prevDisc, prevSplit, prevRetry, prevFlush
	})
	resetLiveTunnels = func(*Helper) []string { return slices.Clone(st.live) }
	resetDisconnectAll = func(h *Helper) error {
		st.order = append(st.order, "disconnect")
		st.live = nil
		_, err := h.disconnectHeld("")
		return err
	}
	resetSweepSplitDNS = func() error { st.order = append(st.order, "split_dns"); return st.splitErr }
	resetRetryPendingCleanup = func(*Helper) (int, []string) {
		st.order = append(st.order, "dns_recovery")
		return len(st.pending), slices.Clone(st.pending)
	}
	resetFlushDNSCache = func() { st.order = append(st.order, "dns_cache") }
	return h, fw, st
}

func runReset(t *testing.T, h *Helper, req ipc.ResetDNSRequest) ipc.ResetDNSResponse {
	t.Helper()
	raw, _ := json.Marshal(req)
	out, err := h.handleResetDNS(raw)
	if err != nil {
		t.Fatalf("handleResetDNS: %v", err)
	}
	return out.(ipc.ResetDNSResponse)
}

func stepNames(resp ipc.ResetDNSResponse) []string {
	var names []string
	for _, s := range resp.Steps {
		names = append(names, s.Name)
	}
	return names
}

func assertRefused(t *testing.T, resp ipc.ResetDNSResponse, st *resetStubs, reason string) {
	t.Helper()
	if !resp.Refused || resp.Reason != reason {
		t.Fatalf("refused=%v reason=%q, want refused %q", resp.Refused, resp.Reason, reason)
	}
	if len(st.order) != 0 || len(resp.Steps) != 0 {
		t.Fatalf("a refused reset changed something: calls=%v steps=%v", st.order, resp.Steps)
	}
}

func TestResetDNSRefusesWhileTunnelConnected(t *testing.T) {
	h, _, st := newResetHelper(t)
	st.live = []string{"home-vpn"}
	resp := runReset(t, h, ipc.ResetDNSRequest{})
	assertRefused(t, resp, st, ipc.ResetRefusedTunnels)
	if !slices.Equal(resp.ConnectedTunnels, []string{"home-vpn"}) {
		t.Fatalf("connected_tunnels = %v", resp.ConnectedTunnels)
	}
}

func TestResetDNSRefusesWhileTunnelWanted(t *testing.T) {
	h, _, st := newResetHelper(t, "office-vpn")
	h.activeCfgs["office-vpn"] = &domain.WireGuardConfig{Name: "office-vpn"} // reconnect pending
	resp := runReset(t, h, ipc.ResetDNSRequest{})
	assertRefused(t, resp, st, ipc.ResetRefusedTunnels)
	if !slices.Equal(resp.ConnectedTunnels, []string{"office-vpn"}) {
		t.Fatalf("connected_tunnels = %v", resp.ConnectedTunnels)
	}
	if _, ok := h.activeCfgs["office-vpn"]; !ok {
		t.Fatal("a refused reset dropped the wanted tunnel")
	}
}

func TestResetDNSRefusesWhilePendingRestore(t *testing.T) {
	h, _, st := newResetHelper(t, "home-vpn")
	h.pendingDesired["home-vpn"] = struct{}{}
	resp := runReset(t, h, ipc.ResetDNSRequest{})
	assertRefused(t, resp, st, ipc.ResetRefusedTunnels)
	if _, ok := h.pendingDesired["home-vpn"]; !ok {
		t.Fatal("a refused reset withdrew the pending restore")
	}
}

// A kill switch the backend reports on, with no recorded intent, still counts
// as wanted: reconcileKillSwitch would import it and re-apply the blockade.
func TestResetDNSRefusesWhileKillSwitchWanted(t *testing.T) {
	for _, imported := range []bool{false, true} {
		h, fw, st := newResetHelper(t)
		if imported {
			fw.killSwitch = true
		} else {
			h.killSwitchWanted, h.ksIntentKnown = true, true
		}
		resp := runReset(t, h, ipc.ResetDNSRequest{Force: true})
		assertRefused(t, resp, st, ipc.ResetRefusedKillSwitch)
		if !h.killSwitchWanted {
			t.Fatal("a refused reset changed the kill switch setting")
		}
	}
}

func TestResetDNSForceRunsStepsInOrder(t *testing.T) {
	h, fw, st := newResetHelper(t, "home-vpn", "office-vpn")
	st.live = []string{"home-vpn"}
	h.activeCfgs["home-vpn"] = &domain.WireGuardConfig{Name: "home-vpn"}
	h.pendingDesired["office-vpn"] = struct{}{}
	h.killSwitchWanted, h.ksIntentKnown = true, true
	fw.killSwitch = true
	if err := saveDesiredState(h.dataDir, []string{"home-vpn", "office-vpn"}); err != nil {
		t.Fatal(err)
	}

	resp := runReset(t, h, ipc.ResetDNSRequest{Force: true, KillSwitchOff: true})
	if resp.Refused {
		t.Fatalf("forced reset refused: %+v", resp)
	}
	want := []string{"disconnect", "kill_switch", "firewall", "split_dns", "dns_recovery", "dns_cache"}
	if !slices.Equal(st.order, want) {
		t.Fatalf("call order = %v, want %v", st.order, want)
	}
	if !slices.Equal(stepNames(resp), want) {
		t.Fatalf("steps = %v, want %v", stepNames(resp), want)
	}
	for _, s := range resp.Steps {
		if !s.OK || s.DetailKey == "" || s.Detail == "" {
			t.Fatalf("step %+v", s)
		}
	}
	if resp.Steps[0].DetailParams["tunnels"] != "home-vpn, office-vpn" {
		t.Fatalf("disconnect params = %v", resp.Steps[0].DetailParams)
	}
	// Explicit Off: nothing wanted any more, pending restore withdrawn and
	// persisted, automation latched off.
	if len(h.wantedTunnelNames()) != 0 {
		t.Fatalf("still wanted: %v", h.wantedTunnelNames())
	}
	assertDesiredState(t, h)
	for _, name := range []string{"home-vpn", "office-vpn"} {
		if latch, ok := h.manualOverride[name]; !ok || !latch.disconnected {
			t.Fatalf("%s: no manual-off latch", name)
		}
	}
	if h.killSwitchWanted || loadDesiredIntent(h.dataDir).KillSwitch {
		t.Fatal("kill switch setting not turned off and persisted")
	}
}

// A retained journal whose cleanup still fails is reported and kept; the step
// fails but the cache is still flushed.
func TestResetDNSReportsRetainedJournals(t *testing.T) {
	h, _, st := newResetHelper(t)
	st.pending = []string{"office-vpn"}
	resp := runReset(t, h, ipc.ResetDNSRequest{})
	var rec ipc.ResetDNSStep
	for _, s := range resp.Steps {
		if s.Name == "dns_recovery" {
			rec = s
		}
	}
	if rec.OK || rec.DetailKey != "reset_dns.detail.dns_recovery_pending" || rec.DetailParams["tunnels"] != "office-vpn" {
		t.Fatalf("dns_recovery step = %+v", rec)
	}
	if st.order[len(st.order)-1] != "dns_cache" {
		t.Fatalf("cache not flushed after pending recovery: %v", st.order)
	}
}

func TestResetDNSStepFailureIsReportedAndOthersRun(t *testing.T) {
	h, fw, st := newResetHelper(t)
	fw.cleanupErr = errors.New("pfctl: busy")
	st.splitErr = errors.New("scutil: denied")
	resp := runReset(t, h, ipc.ResetDNSRequest{})
	if !slices.Equal(stepNames(resp), []string{"firewall", "split_dns", "dns_recovery", "dns_cache"}) {
		t.Fatalf("steps = %v", stepNames(resp))
	}
	if resp.Steps[0].OK || resp.Steps[0].DetailKey != "reset_dns.detail.firewall_failed" || resp.Steps[0].DetailParams["error"] != "pfctl: busy" {
		t.Fatalf("firewall step = %+v", resp.Steps[0])
	}
	if resp.Steps[1].OK || resp.Steps[1].Detail != "scutil: denied" {
		t.Fatalf("split step = %+v", resp.Steps[1])
	}
}

// Nothing connected, nothing pending: the reset succeeds and repeating it is
// harmless.
func TestResetDNSIdempotent(t *testing.T) {
	h, _, st := newResetHelper(t)
	for i := 0; i < 2; i++ {
		st.order = nil
		resp := runReset(t, h, ipc.ResetDNSRequest{})
		if resp.Refused || !slices.Equal(st.order, []string{"firewall", "split_dns", "dns_recovery", "dns_cache"}) {
			t.Fatalf("run %d: refused=%v order=%v", i, resp.Refused, st.order)
		}
		for _, s := range resp.Steps {
			if !s.OK {
				t.Fatalf("run %d: step %+v", i, s)
			}
		}
		if resp.Steps[2].DetailKey != "reset_dns.detail.dns_recovery_none" {
			t.Fatalf("dns_recovery = %+v", resp.Steps[2])
		}
	}
}

// After a forced disconnect that leaves a tunnel up, nothing else runs: the
// split-DNS sweep would remove a live tunnel's resolver.
func TestResetDNSStopsWhenTunnelSurvivesDisconnect(t *testing.T) {
	h, _, st := newResetHelper(t)
	st.live = []string{"home-vpn"}
	resetDisconnectAll = func(*Helper) error {
		st.order = append(st.order, "disconnect")
		return errors.New("teardown failed")
	}
	resp := runReset(t, h, ipc.ResetDNSRequest{Force: true})
	if !slices.Equal(st.order, []string{"disconnect"}) {
		t.Fatalf("ran past a surviving tunnel: %v", st.order)
	}
	last := resp.Steps[len(resp.Steps)-1]
	if !slices.Equal(resp.ConnectedTunnels, []string{"home-vpn"}) || last.OK ||
		last.DetailKey != "reset_dns.detail.remaining_failed" || last.DetailParams["tunnels"] != "home-vpn" {
		t.Fatalf("resp = %+v", resp)
	}
}
