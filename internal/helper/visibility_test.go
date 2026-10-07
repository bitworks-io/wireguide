package helper

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// stateReaderFW is fakeFW plus a pf-style read-back.
type stateReaderFW struct {
	*fakeFW
	rb  firewall.Readback
	err error
}

func (s *stateReaderFW) ReadBack() (firewall.Readback, error) { return s.rb, s.err }

// shortSock returns a unix socket path short enough for sun_path (t.TempDir
// embeds the test name and can overflow it).
func shortSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wgh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func connectedStatus(name string) *domain.ConnectionStatus {
	return &domain.ConnectionStatus{State: domain.StateConnected, TunnelName: name}
}

func TestDecorateStatusPopulatesDNSFields(t *testing.T) {
	h := newWiringHelper(t, &fakeFW{})
	cfgs := map[string]*domain.WireGuardConfig{
		"global": testCfg("global", []string{"1.1.1.1"}, "0.0.0.0/0"),
		"split":  testCfg("split", []string{"192.168.1.1", "~corp.lan"}, "192.168.1.0/24"),
		"none":   testCfg("none", nil, "10.0.0.0/8"),
		"search": testCfg("search", []string{"corp.lan"}, "10.0.0.0/8"),
	}
	view := fwView{dnsApplied: true, permits: []firewall.DNSPermit{{Interface: "utun4", Server: "1.1.1.1"}}}
	for name, want := range map[string]struct {
		mode      string
		servers   []string
		protected bool
	}{
		"global": {"global", []string{"1.1.1.1"}, true},
		"split":  {"split", []string{"192.168.1.1"}, false},
		"none":   {"none", nil, false},
		"search": {"search", nil, false},
	} {
		st := connectedStatus(name)
		h.decorateStatus(st, cfgs, view, true)
		if st.DNSMode != want.mode || !reflect.DeepEqual(st.DNSServers, want.servers) || st.DNSProtected != want.protected {
			t.Errorf("%s: got mode=%q servers=%v protected=%v, want %+v", name, st.DNSMode, st.DNSServers, st.DNSProtected, want)
		}
	}
	// Protection not wanted: global DNS is intended-only, never "protected".
	st := connectedStatus("global")
	h.decorateStatus(st, cfgs, view, false)
	if st.DNSProtected {
		t.Error("protected reported while protection is not wanted")
	}
	// Disconnected tunnels get nothing.
	st = &domain.ConnectionStatus{State: domain.StateDisconnected, TunnelName: "global"}
	h.decorateStatus(st, cfgs, view, true)
	if st.DNSMode != "" {
		t.Error("disconnected tunnel decorated")
	}
}

// tunnelWantsDNSProtection must agree with desiredDNSPermits' own notion of
// a protected tunnel, so the status can never claim coverage the reconcile
// would not install.
func TestTunnelWantsDNSProtectionAgreesWithDesiredPermits(t *testing.T) {
	cfgs := []*domain.WireGuardConfig{
		testCfg("a", []string{"1.1.1.1"}, "0.0.0.0/0"),
		testCfg("a", []string{"1.1.1.1"}, "192.168.1.0/24"),
		testCfg("a", []string{"192.168.1.1", "~corp.lan"}, "192.168.1.0/24"),
		testCfg("a", nil, "0.0.0.0/0"),
		testCfg("a", []string{"corp.lan"}, "0.0.0.0/0"),
	}
	for _, goos := range []string{"darwin", "windows", "linux"} {
		for _, wanted := range []bool{true, false} {
			for i, cfg := range cfgs {
				permits := desiredDNSPermits([]reconcileTunnel{rt("a", "utun4", cfg)}, goos, wanted, nil)
				if got := tunnelWantsDNSProtection(cfg, goos, wanted); got != (len(permits) > 0) {
					t.Errorf("cfg#%d goos=%s wanted=%v: wants=%v but desired permits=%v", i, goos, wanted, got, permits)
				}
			}
		}
	}
}

func TestShouldAlertReconcile(t *testing.T) {
	if shouldAlertReconcile(reconcileAlertAfter-1, true, true, false, true) {
		t.Error("alerted before the retry window elapsed")
	}
	if !shouldAlertReconcile(reconcileAlertAfter, true, true, false, true) {
		t.Error("no alert after repeated failures")
	}
	if shouldAlertReconcile(reconcileAlertAfter, false, true, false, true) {
		t.Error("alerted although DNS protection is not wanted")
	}
	if shouldAlertReconcile(reconcileAlertAfter, true, true, true, true) {
		t.Error("alert repeated within one failure streak")
	}
	if shouldAlertReconcile(reconcileAlertAfter, true, true, false, false) {
		t.Error("alert latched with nobody subscribed to see it")
	}
}

func TestFirewallStatusCached(t *testing.T) {
	fw := &fakeFW{}
	h := newWiringHelper(t, fw)
	h.dnsWanted = true
	h.ksWanted = true
	h.connectMu.Lock()
	h.dnsApplied = true
	h.lastPermits = []firewall.DNSPermit{{Interface: "", Server: "1.1.1.1"}, {Interface: "utun4", Server: "10.0.0.1"}}
	h.mirrorDNSView()
	h.mirrorReconcileView(nil, errors.New("kill switch boom"))
	h.connectMu.Unlock()

	out, err := h.handleFirewallStatus(nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := out.(ipc.FirewallStatusResponse)
	if !resp.DNSProtectionWanted || !resp.KillSwitchWanted || !resp.DNSProtectionActive {
		t.Fatalf("wanted/active wrong: %+v", resp)
	}
	if resp.Source != "cached" || resp.LastReconcileError != "kill switch boom" || resp.LastReconcileAt == "" {
		t.Fatalf("source/error/time wrong: %+v", resp)
	}
	if len(resp.Permits) != 2 {
		t.Fatalf("permits = %+v", resp.Permits)
	}

	// With the kill switch really active, the unpinned permit was never
	// loaded by pf, so it must not be reported.
	fw.ks = true
	h.connectMu.Lock()
	h.mirrorReconcileView(nil, nil)
	h.connectMu.Unlock()
	out, _ = h.handleFirewallStatus(nil)
	resp = out.(ipc.FirewallStatusResponse)
	if !resp.KillSwitchActive || len(resp.Permits) != 1 || resp.Permits[0].Server != "10.0.0.1" {
		t.Fatalf("kill-switch mode permits = %+v", resp.Permits)
	}
}

func TestFirewallStatusReadBack(t *testing.T) {
	fw := &stateReaderFW{fakeFW: &fakeFW{}, rb: firewall.Readback{
		DNSProtectionActive: true,
		Permits:             []firewall.DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}},
	}}
	h := newWiringHelper(t, fw)
	h.dnsWanted = true
	out, _ := h.handleFirewallStatus(nil)
	resp := out.(ipc.FirewallStatusResponse)
	if resp.Source != "pf" || !resp.DNSProtectionActive || len(resp.Permits) != 1 || resp.Permits[0].Interface != "utun4" {
		t.Fatalf("read-back not used: %+v", resp)
	}

	// A failed read-back falls back to the cached view and says why.
	fw.err = errors.New("pfctl: permission denied")
	out, _ = h.handleFirewallStatus(nil)
	resp = out.(ipc.FirewallStatusResponse)
	if resp.Source != "cached" || resp.ReadBackError == "" || resp.DNSProtectionActive {
		t.Fatalf("failed read-back handling: %+v", resp)
	}
}

func TestFirewallStatusPermitTunnelNames(t *testing.T) {
	cfg := testCfg("wg-office", []string{"10.9.0.1"}, "10.9.0.0/24")
	snap := connSnapshot{
		ifaces: map[string]string{"wg-office": "utun4"},
		cfgs:   map[string]*domain.WireGuardConfig{"wg-office": cfg},
	}
	got := permitTunnels([]firewall.DNSPermit{{Interface: "utun4", Server: "10.9.0.1"}, {Server: "10.9.0.1"}, {Server: "8.8.8.8"}}, snap)
	if got[0].Tunnel != "wg-office" || got[1].Tunnel != "wg-office" || got[2].Tunnel != "" {
		t.Fatalf("tunnel labels = %+v", got)
	}
}

func TestHelperInfo(t *testing.T) {
	h := newWiringHelper(t, &fakeFW{})
	ln, err := net.Listen("unix", shortSock(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h.server = ipc.NewServer(ln)
	h.startedAt = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	h.startMode, h.activationReason = describeStart(true)
	h.socketPath = "/var/run/com.wireguide.helper.sock"
	h.recovery = ipc.HelperRecovery{DNSRestored: true, TunnelsRecovered: []string{"a"}}

	out, err := h.handleHelperInfo(nil)
	if err != nil {
		t.Fatal(err)
	}
	info := out.(ipc.HelperInfoResponse)
	if info.StartMode != "launchd-socket" || info.SocketPath != h.socketPath || info.PID == 0 ||
		info.StartedAt != "2026-10-07T12:00:00Z" || info.ProtocolVersion != ipc.ProtocolVersion {
		t.Fatalf("info = %+v", info)
	}
	if info.Recovery == nil || !info.Recovery.DNSRestored {
		t.Fatalf("recovery missing: %+v", info)
	}
	raw, _ := json.Marshal(info)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"app_version", "start_mode", "socket_path", "pid", "started_at"} {
		if _, ok := m[k]; !ok {
			t.Errorf("wire field %q missing", k)
		}
	}

	h.recovery = ipc.HelperRecovery{}
	out, _ = h.handleHelperInfo(nil)
	if out.(ipc.HelperInfoResponse).Recovery != nil {
		t.Fatal("empty recovery must be omitted")
	}
	if mode, _ := describeStart(false); mode == "launchd-socket" {
		t.Fatal("a non-activated helper must not claim launchd-socket")
	}
}

// --- Network.ResetDNS ---

type resetFakes struct {
	recoverCalls int
	flushCalls   int
	report       tunnel.RecoveryReport
	flushErr     error
}

func installResetFakes(t *testing.T) *resetFakes {
	t.Helper()
	f := &resetFakes{}
	oldR, oldF := resetRecoverJournals, resetFlushDNSCache
	resetRecoverJournals = func(dir string, fw tunnel.FirewallCleaner) tunnel.RecoveryReport {
		f.recoverCalls++
		if fw != nil {
			t.Error("journal recovery must not receive the firewall (it is cleaned separately)")
		}
		return f.report
	}
	resetFlushDNSCache = func() error { f.flushCalls++; return f.flushErr }
	t.Cleanup(func() { resetRecoverJournals, resetFlushDNSCache = oldR, oldF })
	return f
}

func newResetHelper(t *testing.T, fw firewall.FirewallManager) *Helper {
	t.Helper()
	h := newWiringHelper(t, fw)
	ln, err := net.Listen("unix", shortSock(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h.server = ipc.NewServer(ln)
	return h
}

func stepByName(resp ipc.ResetDNSResponse, name string) (ipc.ResetStep, bool) {
	for _, s := range resp.Steps {
		if s.Name == name {
			return s, true
		}
	}
	return ipc.ResetStep{}, false
}

func TestResetDNSRefusesWhileConnected(t *testing.T) {
	f := installResetFakes(t)
	fw := &fakeFW{ks: true}
	h := newResetHelper(t, fw)
	h.connectedFn = func() []string { return []string{"home-vpn"} }

	out, err := h.handleResetDNS(nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := out.(ipc.ResetDNSResponse)
	if !resp.Refused || !reflect.DeepEqual(resp.ConnectedTunnels, []string{"home-vpn"}) || len(resp.Steps) != 0 {
		t.Fatalf("expected a refusal that changed nothing: %+v", resp)
	}
	if f.recoverCalls != 0 || f.flushCalls != 0 || !fw.ks {
		t.Fatalf("refused reset touched state: recover=%d flush=%d ks=%v", f.recoverCalls, f.flushCalls, fw.ks)
	}
}

func TestResetDNSRunsEveryStep(t *testing.T) {
	f := installResetFakes(t)
	f.report = tunnel.RecoveryReport{Tunnels: []string{"old"}, DNSRestored: []string{"old"}}
	h := newResetHelper(t, &fakeFW{})
	h.ksWanted = true
	h.connectMu.Lock()
	h.dnsApplied = true
	h.lastPermits = []firewall.DNSPermit{{Server: "1.1.1.1"}}
	h.mirrorDNSView()
	h.connectMu.Unlock()

	out, err := h.handleResetDNS(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := out.(ipc.ResetDNSResponse)
	if resp.Refused {
		t.Fatal("idle helper must not refuse")
	}
	for _, name := range []string{"firewall", "kill_switch", "split_dns", "dns_restore", "dns_cache"} {
		s, ok := stepByName(resp, name)
		if !ok || !s.OK {
			t.Errorf("step %q missing or failed: %+v", name, resp.Steps)
		}
	}
	if s, _ := stepByName(resp, "dns_restore"); s.Detail == "" || s.Detail[:8] != "restored" {
		t.Errorf("dns_restore detail = %q", s.Detail)
	}
	if f.recoverCalls != 1 || f.flushCalls != 1 {
		t.Fatalf("recover=%d flush=%d", f.recoverCalls, f.flushCalls)
	}
	v := h.viewSnapshot()
	if v.dnsApplied || len(v.permits) != 0 || v.ksActive {
		t.Fatalf("bookkeeping not reset: %+v", v)
	}
	if !h.ksWanted {
		t.Fatal("reset must not rewrite the user's kill switch setting")
	}
}

func TestResetDNSForceDisconnectsFirst(t *testing.T) {
	f := installResetFakes(t)
	h := newResetHelper(t, &fakeFW{})
	h.connectedFn = func() []string { return []string{"a"} }

	out, _ := h.handleResetDNS(json.RawMessage(`{"force":true}`))
	resp := out.(ipc.ResetDNSResponse)
	if resp.Refused {
		t.Fatal("force must not refuse")
	}
	first := resp.Steps[0]
	if first.Name != "tunnels" {
		t.Fatalf("force must disconnect tunnels first, steps = %+v", resp.Steps)
	}
	if _, ok := stepByName(resp, "dns_cache"); !ok || f.flushCalls != 1 {
		t.Fatalf("remaining steps did not run: %+v", resp.Steps)
	}
}

func TestResetDNSReportsFailuresAndContinues(t *testing.T) {
	f := installResetFakes(t)
	f.flushErr = errors.New("flush failed")
	f.report = tunnel.RecoveryReport{SplitDNSSweepErr: errors.New("scutil failed")}
	h := newResetHelper(t, &fakeFW{})
	out, _ := h.handleResetDNS(nil)
	resp := out.(ipc.ResetDNSResponse)
	if s, _ := stepByName(resp, "split_dns"); s.OK || s.Detail != "scutil failed" {
		t.Errorf("split_dns = %+v", s)
	}
	if s, _ := stepByName(resp, "dns_cache"); s.OK {
		t.Errorf("dns_cache = %+v", s)
	}
	if s, _ := stepByName(resp, "dns_restore"); !s.OK {
		t.Errorf("dns_restore must still run after a sweep failure: %+v", s)
	}
}

// After a reset the safety net must not re-install a wanted kill switch on its
// own (a failing reconcile is the usual reason people reset), or the reset
// would re-trap the user it exists to free.
func TestResetDNSDoesNotLetSafetyNetReinstallKillSwitch(t *testing.T) {
	installResetFakes(t)
	fw := &fakeFW{}
	h := newResetHelper(t, fw)
	h.ksWanted = true
	h.reconciledKey = reconcileDirtyKey
	h.reconcileFails = 5
	h.reconcileRetryAt = time.Now().Add(-time.Second)

	h.handleResetDNS(nil)

	h.reconcileRetryAt = time.Now().Add(-time.Second)
	h.maybeReconcileOnTunnelChange()
	for _, c := range fw.ksCalls {
		if len(c) >= 6 && c[:6] == "enable" {
			t.Fatalf("safety net re-installed the kill switch right after reset: %v", fw.ksCalls)
		}
	}
	if h.reconcileFails != 0 || h.reconciledKey == reconcileDirtyKey {
		t.Fatalf("reset must clear the failure streak: fails=%d key=%q", h.reconcileFails, h.reconciledKey)
	}
	if !h.ksWanted {
		t.Fatal("the user's kill switch setting must stay wanted")
	}
}

func TestEffectivePermitsDropsUnpinnedInKillSwitchMode(t *testing.T) {
	v := fwView{permits: []firewall.DNSPermit{{Server: "1.1.1.1"}, {Interface: "utun4", Server: "10.0.0.1"}}}
	if got := effectivePermits(v); len(got) != 2 {
		t.Fatalf("without a kill switch both permits are loaded: %v", got)
	}
	v.ksActive = true
	if got := effectivePermits(v); len(got) != 1 || got[0].Server != "10.0.0.1" {
		t.Fatalf("kill-switch mode keeps only pinned permits: %v", got)
	}
	// And so a tunnel whose only resolver was unpinned is not "protected".
	cfg := testCfg("a", []string{"1.1.1.1"}, "192.168.1.0/24")
	h := newWiringHelper(t, &fakeFW{})
	v.dnsApplied = true
	st := connectedStatus("a")
	h.decorateStatus(st, map[string]*domain.WireGuardConfig{"a": cfg}, v, true)
	if st.DNSProtected {
		t.Fatal("unpinned resolver reported as protected while the kill switch drops it")
	}
}
