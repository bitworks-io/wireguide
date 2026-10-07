package helper

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/network"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// Seams for Network.ResetDNS so tests never touch pfctl, scutil or
// networksetup. Production values are the same functions crash recovery uses.
var (
	// resetRecoverJournals sweeps the split-DNS dynamic-store keys and
	// restores DNS from any leftover recovery journals (precise snapshot
	// restore; the blunt reset only when the journal says global DNS was
	// applied — see tunnel.needsDNSReset). nil firewall: flushed separately.
	resetRecoverJournals = tunnel.RecoverFromCrashReport
	resetFlushDNSCache   = network.FlushDNSCache
)

// handleResetDNS implements Network.ResetDNS: the "get me back to system
// defaults" escape hatch. connectMu is held throughout so it cannot race a
// connect; nothing is broadcast and automation is not re-evaluated while it
// is held (lock order is reevalMu -> connectMu).
//
// It resets applied state, not the user's settings: a kill switch the user
// has turned on stays wanted and is re-applied the next time the tunnel set
// changes; the report says so.
func (h *Helper) handleResetDNS(params json.RawMessage) (interface{}, error) {
	var req ipc.ResetDNSRequest
	if len(params) > 0 {
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err
		}
	}
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	return h.resetDNSHeld(req.Force), nil
}

// resetDNSHeld does the work; caller holds h.connectMu.
func (h *Helper) resetDNSHeld(force bool) ipc.ResetDNSResponse {
	var resp ipc.ResetDNSResponse
	step := func(name string, err error, okDetail string) {
		s := ipc.ResetStep{Name: name, OK: err == nil, Detail: okDetail}
		if err != nil {
			s.Detail = err.Error()
			slog.Warn("reset DNS step failed", "step", name, "error", err)
		}
		resp.Steps = append(resp.Steps, s)
	}

	connected := h.connectedTunnels()
	if len(connected) > 0 && !force {
		resp.Refused = true
		resp.ConnectedTunnels = connected
		return resp
	}
	slog.Warn("reset DNS and firewall requested", "force", force, "connected", connected)

	if len(connected) > 0 {
		// Tear the tunnels down through the normal path so their routes and
		// DNS are restored by the same code that handles a disconnect, and
		// so no journal is left half-owned. Never touch live journals here.
		if h.monitor != nil {
			h.monitor.CancelRetry()
		}
		err := h.disconnectAllHeld(domain.ChangeReasonRecovery)
		h.reconcileFirewallLocked("reset-dns-disconnect")
		h.cancelLegacyRetryIfIdle()
		step("tunnels", err, "disconnected: "+strings.Join(connected, ", "))
		if still := h.manager.ActiveTunnels(); len(still) > 0 {
			resp.ConnectedTunnels = still
			step("remaining", fmt.Errorf("tunnels still connected, remaining steps skipped: %s", strings.Join(still, ", ")), "")
			return resp
		}
		h.maybeArmShutdownAfterTeardown("reset DNS disconnected tunnels, no GUI attached")
	}

	// Firewall: Cleanup (not RecoverFromCrash, which would forget the pf
	// reference token without releasing it) flushes both pf anchors and
	// releases the reference on this live helper.
	fwErr := h.firewall.Cleanup()
	h.dnsApplied = false
	h.lastPermits = nil
	h.ksIfaces = nil
	h.mirrorDNSView()
	h.mu.Lock()
	h.fwv.ksActive = false
	h.fwv.dnsFailing = false
	h.fwv.lastErr = ""
	h.mu.Unlock()
	step("firewall", fwErr, "WireGuide firewall rules removed")
	// Mark the zero-tunnel state as reconciled so the event-loop safety net
	// does not immediately re-install a kill-switch blockade (which is wanted
	// state) and re-trap the user this reset is meant to free; the next change
	// of the tunnel set reconciles as usual.
	h.mu.Lock()
	h.reconciledKey = connectedKey(h.manager.ConnectedInterfaces())
	h.reconcileFails = 0
	h.reconcileRetryAt = time.Time{}
	h.mu.Unlock()

	_, ksWanted := h.wantedState()
	if ksWanted {
		step("kill_switch", nil, "the kill switch setting is still on and will be applied again the next time a tunnel connects")
	}

	// Split-DNS keys and journal restore. Only leftover journals can exist
	// here (a clean disconnect already restored and removed its own).
	report := resetRecoverJournals(h.dataDir, nil)
	step("split_dns", report.SplitDNSSweepErr, "split DNS entries removed")
	if len(report.Tunnels) == 0 {
		step("dns_restore", nil, "no recovery journal found; system DNS left untouched")
	} else if len(report.DNSRestored) > 0 {
		step("dns_restore", nil, "restored DNS from the saved pre-VPN state: "+strings.Join(report.DNSRestored, ", "))
	} else {
		step("dns_restore", nil, "cleaned up leftover state; the tunnel never changed system DNS")
	}

	step("dns_cache", resetFlushDNSCache(), "DNS cache flushed")
	return resp
}
