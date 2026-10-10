package helper

import (
	"log/slog"
	"runtime"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// fullTunnelForcesDNSProtection is the Windows-only auto-enable below; a
// package var so tests on other platforms can exercise it.
var fullTunnelForcesDNSProtection = runtime.GOOS == "windows"

// tunnelStatuses is the per-tunnel status source for DNS protection. A
// package var so tests can present connected tunnels without real ones.
var tunnelStatuses = func(h *Helper) []*tunnel.ConnectionStatus {
	return h.manager.AllStatuses()
}

// DNS protection follows the tunnel set (issue #48). The system resolver is
// given the union of every connected tunnel's DNS servers, so the rules must
// let each tunnel's servers through that tunnel's interface — not one
// tunnel's servers on one interface, which dropped every query to the other
// tunnels' servers and kept pointing at a dead interface after disconnect.
// Every transition that changes the connected set calls
// reapplyDNSProtection, which renders the rules from scratch.

// dnsAllowList pairs each connected tunnel's interface with its configured
// DNS entries. The firewall drops non-IP entries (search domains).
func (h *Helper) dnsAllowList() []firewall.DNSAllow {
	h.mu.Lock()
	cfgs := h.copyActiveCfgs()
	h.mu.Unlock()
	var allow []firewall.DNSAllow
	for _, st := range tunnelStatuses(h) {
		if st == nil || st.State != domain.StateConnected || st.InterfaceName == "" {
			continue
		}
		cfg := cfgs[st.TunnelName]
		if cfg == nil || len(cfg.Interface.DNS) == 0 {
			continue
		}
		allow = append(allow, firewall.DNSAllow{
			Interface: st.InterfaceName,
			Servers:   append([]string(nil), cfg.Interface.DNS...),
		})
	}
	return allow
}

// dnsProtectionNeeded reports whether DNS rules should be installed: the
// user turned DNS protection on, or (Windows only) a connected full tunnel
// has DNS servers. That Windows rule predates issue #48 and keeps its old
// behaviour: Windows' "smart multi-homed name resolution" queries every
// interface's DNS in parallel (wireguard-windows netquirk.md), so a full
// tunnel connect turns DNS protection on regardless of the setting, and an
// explicit "off" from the user holds until the next full-tunnel connect.
func (h *Helper) dnsProtectionNeeded() bool {
	h.mu.Lock()
	wanted := h.dnsProtectionWanted
	autoOff := h.dnsAutoOff
	cfgs := h.copyActiveCfgs()
	h.mu.Unlock()
	if wanted || autoOff || !fullTunnelForcesDNSProtection {
		return wanted
	}
	for _, st := range tunnelStatuses(h) {
		if st == nil || st.State != domain.StateConnected {
			continue
		}
		if cfg := cfgs[st.TunnelName]; cfg != nil && cfg.IsFullTunnel() && len(cfg.Interface.DNS) > 0 {
			return true
		}
	}
	return false
}

// reapplyDNSProtection installs DNS rules for the current tunnel set, or
// removes them when DNS protection isn't needed. With protection on but no
// connected tunnel that has DNS servers, the firewall removes its rules;
// the next connect installs them again.
func (h *Helper) reapplyDNSProtection() error {
	h.dnsMu.Lock()
	defer h.dnsMu.Unlock()
	if !h.dnsProtectionNeeded() {
		if h.firewall.IsDNSProtectionEnabled() {
			return h.firewall.DisableDNSProtection()
		}
		return nil
	}
	allow := h.dnsAllowList()
	slog.Debug("DNS protection: applying", "tunnels", len(allow))
	return h.firewall.EnableDNSProtection(allow)
}
