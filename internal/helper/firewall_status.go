package helper

import (
	"encoding/json"
	"log/slog"
	"net"
	"runtime"
	"slices"
	"time"

	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
)

// This file reports DNS protection truth: Firewall.Status, the per-tunnel
// dns_mode / dns_servers / dns_protected status fields and the "DNS
// protection keeps failing" banner. It only reads; nothing here changes the
// firewall. Readers take h.mu alone, never dnsMu or connectMu, and never ask
// the backend's Is* methods (a backend may hold its own lock across a reload).

// dnsAlertAfter is how many consecutive failed DNS protection applies (each
// already retried with the reconcile backoff) raise the GUI banner.
const dnsAlertAfter = 3

// fwStatusView is the reconcile outcome mirrored under h.mu.
type fwStatusView struct {
	// dnsNeeded is dnsProtectionNeeded at the last DNS apply attempt.
	dnsNeeded bool
	// dnsAllow is the permit set of the last DNS apply that left the backend
	// active (nil once the rules were removed or an apply failed).
	dnsAllow  []firewall.DNSAllow
	dnsActive bool
	dnsErr    string
	dnsFails  int
	ksActive  bool
	ksErr     string
	ksFails   int
	lastAt    time.Time
	// suspended mirrors fwSuspendDepth > 0 / dnsSuspended.
	suspended bool
	// dnsAlerted latches the banner for one failure streak.
	dnsAlerted bool
}

// recordDNSReconcile mirrors one DNS apply attempt. Caller holds dnsMu
// (dnsMu -> mu is the existing order via dnsProtectionNeeded).
func (h *Helper) recordDNSReconcile(needed bool, allow []firewall.DNSAllow, active bool, err error, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := &h.fwView
	v.dnsNeeded = needed
	v.lastAt = now
	if err != nil {
		v.dnsActive = false
		v.dnsAllow = nil
		v.dnsErr = err.Error()
		v.dnsFails++
		return
	}
	v.dnsActive = active && needed && len(allow) > 0
	v.dnsAllow = nil
	if v.dnsActive {
		v.dnsAllow = cloneDNSAllow(allow)
	}
	v.dnsErr = ""
	v.dnsFails = 0
	v.dnsAlerted = false
}

// recordKillSwitchReconcile mirrors one kill-switch apply attempt. Caller
// holds connectMu.
func (h *Helper) recordKillSwitchReconcile(active bool, err error, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := &h.fwView
	v.ksActive = active
	v.lastAt = now
	if err != nil {
		v.ksErr = err.Error()
		v.ksFails++
		return
	}
	v.ksErr = ""
	v.ksFails = 0
}

// setFirewallSuspendedView mirrors the reconnect suspension. Caller holds
// connectMu.
func (h *Helper) setFirewallSuspendedView(suspended bool) {
	h.mu.Lock()
	h.fwView.suspended = suspended
	h.mu.Unlock()
}

func cloneDNSAllow(allow []firewall.DNSAllow) []firewall.DNSAllow {
	out := make([]firewall.DNSAllow, len(allow))
	for i, a := range allow {
		out[i] = firewall.DNSAllow{Interface: a.Interface, Servers: slices.Clone(a.Servers)}
	}
	return out
}

// dnsStatusSnapshot is everything the status paths need, taken under one
// h.mu acquisition.
type dnsStatusSnapshot struct {
	view      fwStatusView
	wanted    bool
	autoOff   bool
	ksWanted  bool
	cfgs      map[string]*domain.WireGuardConfig
	permitted map[string]bool // canonical servers in the effective permit set
}

func (h *Helper) dnsStatusSnapshot() dnsStatusSnapshot {
	h.mu.Lock()
	s := dnsStatusSnapshot{
		view:     h.fwView,
		wanted:   h.dnsProtectionWanted,
		autoOff:  h.dnsAutoOff,
		ksWanted: h.killSwitchWanted,
		cfgs:     h.copyActiveCfgs(),
	}
	h.mu.Unlock()
	s.permitted = make(map[string]bool)
	for _, a := range s.cachedPermits() {
		for _, srv := range a.Servers {
			s.permitted[srv] = true
		}
	}
	return s
}

// cachedPermits is the permit set the backend installed at the last
// successful apply. With the kill switch on, the macOS and Windows backends
// drop unpinned permits (an off-tunnel resolver would bypass it); the Linux
// nft table keeps every permit.
func (s dnsStatusSnapshot) cachedPermits() []firewall.DNSAllow {
	if !s.view.dnsActive || s.view.suspended {
		return nil
	}
	return firewall.EffectiveDNSAllow(s.view.dnsAllow, s.view.ksActive && runtime.GOOS != "linux")
}

// decorate fills the additive DNS fields of one tunnel's status.
func (s dnsStatusSnapshot) decorate(st *domain.ConnectionStatus) {
	if st == nil {
		return
	}
	cfg := s.cfgs[st.TunnelName]
	if cfg == nil {
		return
	}
	mode := diag.DNSModeOf(cfg.Interface.DNS)
	st.DNSMode = mode.Mode
	st.DNSServers = mode.Servers
	st.DNSProtected = st.State == domain.StateConnected && s.covers(cfg)
}

// covers reports whether the applied rules pin this tunnel's resolvers: the
// tunnel asks for protection (the same predicate reconcile uses) and at
// least one of its servers is in the effective permit set.
func (s dnsStatusSnapshot) covers(cfg *domain.WireGuardConfig) bool {
	if !tunnelWantsDNSProtection(cfg, s.wanted, s.autoOff) {
		return false
	}
	for _, raw := range cfg.Interface.ParseDNS().Servers {
		if ip := net.ParseIP(raw); ip != nil && s.permitted[ip.String()] {
			return true
		}
	}
	return false
}

// decorateDNSStatus fills the per-tunnel DNS fields of a status DTO: the
// primary entry and every Tunnels entry (the list is only built with more
// than one tunnel, and the GUI falls back to the primary otherwise).
func (h *Helper) decorateDNSStatus(st *domain.ConnectionStatus) {
	s := h.dnsStatusSnapshot()
	s.decorate(st)
	for i := range st.Tunnels {
		s.decorate(&st.Tunnels[i])
	}
}

// handleFirewallStatus reports wanted vs actual firewall state. It never
// takes dnsMu or connectMu. On macOS the actual state is read back from pf;
// elsewhere, or when that read fails, the helper's cached view of its last
// successful apply is reported and Source says so.
func (h *Helper) handleFirewallStatus(json.RawMessage) (interface{}, error) {
	s := h.dnsStatusSnapshot()
	v := s.view
	resp := ipc.FirewallStatusResponse{
		DNSProtectionWanted: s.wanted,
		DNSProtectionActive: v.dnsActive && !v.suspended,
		Source:              "cached",
		KillSwitchWanted:    s.ksWanted,
		KillSwitchActive:    v.ksActive && !v.suspended,
		Suspended:           v.suspended,
		DNSReconcileError:   v.dnsErr,
		ReconcileFailures:   max(v.dnsFails, v.ksFails),
	}
	resp.LastReconcileError = v.dnsErr
	if resp.LastReconcileError == "" {
		resp.LastReconcileError = v.ksErr
	}
	if !v.lastAt.IsZero() {
		resp.LastReconcileAt = v.lastAt.UTC().Format(time.RFC3339)
	}
	var permits []firewall.DNSPermit
	for _, a := range s.cachedPermits() {
		for _, srv := range a.Servers {
			permits = append(permits, firewall.DNSPermit{Interface: a.Interface, Server: srv})
		}
	}
	if r, ok := h.firewall.(firewall.StateReader); ok {
		if rb, err := r.ReadBack(); err != nil {
			resp.ReadBackError = err.Error()
		} else {
			resp.Source = "pf"
			resp.DNSProtectionActive = rb.DNSProtectionActive
			resp.KillSwitchActive = rb.KillSwitchActive
			permits = rb.Permits
		}
	}
	resp.Permits = labelPermits(permits, s.cfgs, tunnelStatuses(h))
	return resp, nil
}

// labelPermits names the tunnel each permit belongs to: by interface for a
// pinned permit, otherwise by the connected tunnel listing that server.
func labelPermits(permits []firewall.DNSPermit, cfgs map[string]*domain.WireGuardConfig, statuses []*domain.ConnectionStatus) []ipc.FirewallPermit {
	out := make([]ipc.FirewallPermit, 0, len(permits))
	for _, p := range permits {
		fp := ipc.FirewallPermit{Interface: p.Interface, Server: p.Server}
		for _, st := range statuses {
			if st != nil && p.Interface != "" && st.InterfaceName == p.Interface {
				fp.Tunnel = st.TunnelName
				break
			}
		}
		for _, st := range statuses {
			if fp.Tunnel != "" || st == nil || cfgs[st.TunnelName] == nil {
				continue
			}
			for _, raw := range cfgs[st.TunnelName].Interface.ParseDNS().Servers {
				if ip := net.ParseIP(raw); ip != nil && ip.String() == p.Server {
					fp.Tunnel = st.TunnelName
					break
				}
			}
		}
		out = append(out, fp)
	}
	return out
}

// shouldAlertDNSFailing is the banner decision: protection is needed, its
// apply has failed dnsAlertAfter times in a row (each after the reconcile
// backoff), the rules are not lifted on purpose by a reconnect, and this
// streak has not been reported yet.
func shouldAlertDNSFailing(v fwStatusView) bool {
	return v.dnsFails >= dnsAlertAfter && v.dnsNeeded && !v.suspended && !v.dnsAlerted
}

// maybeAlertDNSProtectionFailing raises the critical_error banner once per
// failure streak. Called from the reconcile loop after connectMu is
// released. The latch only arms when a GUI is subscribed to see it, so one
// that attaches mid-streak still gets the banner on the next tick.
func (h *Helper) maybeAlertDNSProtectionFailing() {
	if h.server == nil {
		return
	}
	// Ask the server before taking h.mu: its lock is never taken under mu.
	if !h.server.HasSubscribers() {
		return
	}
	h.mu.Lock()
	fire := shouldAlertDNSFailing(h.fwView)
	detail := h.fwView.dnsErr
	if fire {
		h.fwView.dnsAlerted = true
	}
	h.mu.Unlock()
	if !fire {
		return
	}
	slog.Error("DNS protection is wanted but cannot be applied", "error", detail)
	h.server.Broadcast(ipc.EventCriticalError, ipc.CriticalErrorPayload{
		Where:  "DNS protection",
		Detail: "DNS protection is turned on but could not be applied (" + detail + "). DNS may not be locked to your tunnel.",
		Code:   ipc.CriticalCodeDNSProtectionFailing,
	})
}
