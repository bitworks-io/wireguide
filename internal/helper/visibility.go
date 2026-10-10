package helper

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/update"
)

// This file is the read-only visibility layer: status decoration, the
// Firewall.Status and Helper.Info RPCs and the once-per-start notices. Nothing
// here changes what the firewall, DNS or routes are set to.

// reconcileAlertAfter is how many consecutive failed reconciles (each retried
// with reconcileBackoff) turn "DNS protection is failing" into a GUI banner.
const reconcileAlertAfter = 3

// fwView is the reconcile outcome mirrored under h.mu so readers never take
// connectMu (a connect can hold it for seconds, and the 1 Hz status loop must
// not stall behind it).
type fwView struct {
	permits    []firewall.DNSPermit // last permit set the helper applied
	dnsApplied bool                 // that apply succeeded
	ksActive   bool
	lastErr    string
	dnsFailing bool // the last reconcile failed in the DNS step
	lastAt     time.Time
}

// mirrorDNSView copies the connectMu-guarded DNS bookkeeping into the view.
// Caller holds h.connectMu.
func (h *Helper) mirrorDNSView() {
	permits := append([]firewall.DNSPermit(nil), h.lastPermits...)
	applied := h.dnsApplied
	h.mu.Lock()
	h.fwv.permits = permits
	h.fwv.dnsApplied = applied
	h.mu.Unlock()
}

// mirrorReconcileView records the outcome of a full reconcile. Caller holds
// h.connectMu.
func (h *Helper) mirrorReconcileView(dnsErr, ksErr error) {
	ks := h.firewall.IsKillSwitchEnabled()
	h.mu.Lock()
	h.fwv.ksActive = ks
	h.fwv.lastAt = time.Now()
	h.fwv.lastErr = ""
	h.fwv.dnsFailing = dnsErr != nil
	switch {
	case dnsErr != nil:
		h.fwv.lastErr = dnsErr.Error()
	case ksErr != nil:
		h.fwv.lastErr = ksErr.Error()
	}
	h.mu.Unlock()
}

func (h *Helper) viewSnapshot() fwView {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := h.fwv
	v.permits = append([]firewall.DNSPermit(nil), v.permits...)
	return v
}

// describeStart names how this helper was started.
func describeStart(activated bool) (mode, reason string) {
	switch {
	case activated:
		return "launchd-socket", "started by launchd as a socket-activated job (launchd handed over the listening socket)"
	case runtime.GOOS == "darwin":
		return "legacy", "launchd did not hand over a socket; the helper listens on its own socket"
	}
	return "direct", "started directly (no launchd socket activation on this platform)"
}

// tunnelWantsDNSProtection mirrors the `protected` expression of
// desiredDNSPermits for one tunnel. desiredDNSPermits stays the single place
// rules are decided; this only lets status report whether a tunnel is covered.
func tunnelWantsDNSProtection(cfg *domain.WireGuardConfig, goos string, dnsWanted bool) bool {
	if cfg == nil {
		return false
	}
	dns := cfg.Interface.ParseDNS()
	split := len(dns.Match) > 0
	hasServers := len(dns.Servers) > 0
	return (dnsWanted && !split && hasServers) ||
		(goos == "windows" && cfg.IsFullTunnel() && hasServers && !split)
}

// tunnelDNSProtected reports whether the tunnel's resolvers are covered by a
// successfully applied DNS permit set.
func tunnelDNSProtected(cfg *domain.WireGuardConfig, goos string, dnsWanted bool, v fwView) bool {
	if !v.dnsApplied || len(v.permits) == 0 || !tunnelWantsDNSProtection(cfg, goos, dnsWanted) {
		return false
	}
	for _, s := range cfg.Interface.ParseDNS().Servers {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		for _, p := range v.permits {
			if p.Server == ip.String() {
				return true
			}
		}
	}
	return false
}

// decorateStatus fills the additive per-tunnel DNS and route fields of one
// connected tunnel's status.
func (h *Helper) decorateStatus(st *domain.ConnectionStatus, cfgs map[string]*domain.WireGuardConfig, v fwView, dnsWanted bool) {
	v.permits = effectivePermits(v)
	if st == nil || st.State != domain.StateConnected || st.TunnelName == "" {
		return
	}
	cfg := cfgs[st.TunnelName]
	if cfg == nil {
		return
	}
	info := h.manager.NetInfo(st.TunnelName)
	mode := diag.DNSModeOf(cfg.Interface.DNS)
	if info.DNSUnsupported {
		// The platform could not apply the DNS= handling: nothing happened.
		mode = diag.DNSMode{Mode: diag.DNSModeNone}
	}
	st.DNSMode = mode.Mode
	st.DNSServers = mode.Servers
	st.DNSProtected = !info.DNSUnsupported && tunnelDNSProtected(cfg, runtime.GOOS, dnsWanted, v)
	st.RoutesSkipped = info.SkippedRoutes
}

// effectivePermits is the permit set pf actually loads: in kill-switch mode
// unpinned permits are dropped (see renderDNSAnchor), so they are neither
// "allowed" nor protecting anything.
func effectivePermits(v fwView) []firewall.DNSPermit {
	if !v.ksActive {
		return v.permits
	}
	pinned := make([]firewall.DNSPermit, 0, len(v.permits))
	for _, p := range v.permits {
		if p.Interface != "" {
			pinned = append(pinned, p)
		}
	}
	return pinned
}

// permitTunnels labels permits with the tunnel each belongs to.
func permitTunnels(permits []firewall.DNSPermit, snap connSnapshot) []ipc.FirewallPermit {
	byIface := snap.ifaceSet()
	out := make([]ipc.FirewallPermit, 0, len(permits))
	for _, p := range permits {
		fp := ipc.FirewallPermit{Interface: p.Interface, Server: p.Server}
		if p.Interface != "" {
			fp.Tunnel = byIface[p.Interface]
		}
		if fp.Tunnel == "" {
			for _, t := range snap.tunnels() {
				for _, s := range t.Cfg.Interface.ParseDNS().Servers {
					if ip := net.ParseIP(s); ip != nil && ip.String() == p.Server {
						fp.Tunnel = t.Name
						break
					}
				}
				if fp.Tunnel != "" {
					break
				}
			}
		}
		out = append(out, fp)
	}
	return out
}

// handleFirewallStatus reports the wanted vs actual firewall state. It is
// read-only and never takes connectMu. On macOS the actual state is read back
// from pf; elsewhere (or when the read-back fails) the helper's cached view is
// reported and Source says so.
func (h *Helper) handleFirewallStatus(params json.RawMessage) (interface{}, error) {
	dnsWanted, ksWanted := h.wantedState()
	v := h.viewSnapshot()
	resp := ipc.FirewallStatusResponse{
		DNSProtectionWanted: dnsWanted,
		KillSwitchWanted:    ksWanted,
		DNSProtectionActive: v.dnsApplied && len(v.permits) > 0,
		KillSwitchActive:    v.ksActive,
		LastReconcileError:  v.lastErr,
		Source:              "cached",
	}
	h.mu.Lock()
	resp.ReconcileFailures = h.reconcileFails
	h.mu.Unlock()
	if !v.lastAt.IsZero() {
		resp.LastReconcileAt = v.lastAt.UTC().Format(time.RFC3339)
	}

	permits := effectivePermits(v)
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
	if v.dnsFailing {
		resp.DNSReconcileError = v.lastErr
	}
	resp.Permits = permitTunnels(permits, h.snapshotConnected())
	return resp, nil
}

func (h *Helper) handleHelperInfo(params json.RawMessage) (interface{}, error) {
	resp := ipc.HelperInfoResponse{
		AppVersion:       update.CurrentVersion(),
		ProtocolVersion:  ipc.ProtocolVersion,
		PID:              os.Getpid(),
		StartedAt:        h.startedAt.UTC().Format(time.RFC3339),
		StartMode:        h.startMode,
		SocketPath:       h.socketPath,
		ActivationReason: h.activationReason,
		GUIAttached:      h.server.HasControlConn(),
	}
	if h.recovery.Any() {
		r := h.recovery
		resp.Recovery = &r
	}
	return resp, nil
}

// onSubscribe delivers the startup recovery notice to the first subscriber.
// Recovery runs before Serve, so no GUI can have been listening when it
// happened; Helper.Info keeps the same data for a GUI whose frontend was not
// ready for the event yet.
func (h *Helper) onSubscribe() {
	if !h.recovery.Any() || !h.recoveryEmitted.CompareAndSwap(false, true) {
		return
	}
	h.server.Broadcast(ipc.EventRecovery, h.recovery)
}

// shouldAlertReconcile is the banner decision: DNS protection wanted, the DNS
// step failing for reconcileAlertAfter consecutive reconciles, not yet
// alerted this streak, and someone subscribed to see it.
func shouldAlertReconcile(fails int, dnsWanted, dnsFailing, alerted, subscribers bool) bool {
	return fails >= reconcileAlertAfter && dnsWanted && dnsFailing && !alerted && subscribers
}

// maybeAlertReconcileFailure raises the critical_error banner once per
// failure streak when DNS protection is wanted but the reconcile keeps
// failing past its retry backoff. Called from the event loop, never under
// connectMu. The latch only arms when a subscriber could actually see it.
func (h *Helper) maybeAlertReconcileFailure() {
	if h.server == nil {
		return
	}
	// Ask the server BEFORE taking h.mu: the server's own lock must never be
	// taken while h.mu is held (its disconnect callback takes h.mu).
	subscribers := h.server.HasSubscribers()
	h.mu.Lock()
	if h.reconcileFails == 0 {
		h.reconcileAlerted = false
	}
	fire := shouldAlertReconcile(h.reconcileFails, h.dnsWanted, h.fwv.dnsFailing, h.reconcileAlerted, subscribers)
	detail := h.fwv.lastErr
	if fire {
		h.reconcileAlerted = true
	}
	h.mu.Unlock()
	if !fire {
		return
	}
	slog.Error("DNS protection is wanted but cannot be applied", "error", detail)
	h.server.Broadcast(ipc.EventCriticalError, ipc.CriticalErrorPayload{
		Where:  "DNS protection",
		Detail: "DNS protection is turned on but could not be applied (" + detail + "). DNS may not be locked to your tunnel.",
		Code:   "dns_protection_failing",
	})
}
