package helper

import (
	"encoding/json"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/network"
)

// Seams for Network.ResetDNS so tests never touch pfctl, scutil or the real
// tunnel manager's OS cleanup. The production values are the same primitives
// the helper uses elsewhere.
var (
	resetLiveTunnels   = func(h *Helper) []string { return h.manager.ActiveTunnels() }
	resetDisconnectAll = func(h *Helper) error { _, err := h.disconnectHeld(""); return err }
	resetSweepSplitDNS = network.CleanupStaleSplitDNS
	// Drives the live Manager's retained cleanup queue (.cleanup-* journals)
	// past its backoff. Journals are removed only when cleanup succeeds.
	resetRetryPendingCleanup = func(h *Helper) (int, []string) { return h.manager.ForcePendingCleanupRetry() }
	resetFlushDNSCache       = network.FlushDNSCache
)

// handleResetDNS implements Network.ResetDNS, the "Reset DNS & firewall"
// escape hatch. It never runs crash recovery on this live helper: startup
// recovery already adopted any leftover journals into the Manager's pending
// cleanup queue, and this only retries that queue now.
//
// connectMu is held for the whole reset so no connect can interleave (the
// DNS lock is taken inside the reconciles). Events are broadcast only after
// it is released.
func (h *Helper) handleResetDNS(params json.RawMessage) (interface{}, error) {
	var req ipc.ResetDNSRequest
	if len(params) > 0 {
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err
		}
	}
	h.connectMu.Lock()
	resp, ksTurnedOff := h.resetDNSHeld(req)
	h.connectMu.Unlock()
	if ksTurnedOff && h.server != nil {
		off := false
		h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{KillSwitch: &off})
	}
	return resp, nil
}

// resetTunnels lists every tunnel that blocks a reset: connected, wanted
// (cached for a reconnect) or pending restore. Caller holds connectMu.
func (h *Helper) resetTunnels() []string {
	names := append(resetLiveTunnels(h), h.wantedTunnelNames()...)
	slices.Sort(names)
	return slices.Compact(names)
}

// resetDNSHeld does the work; caller holds connectMu. Every refusal is
// decided before anything changes. The second result reports whether the
// kill switch setting was turned off.
func (h *Helper) resetDNSHeld(req ipc.ResetDNSRequest) (ipc.ResetDNSResponse, bool) {
	resp := ipc.ResetDNSResponse{Steps: []ipc.ResetDNSStep{}}
	step := func(name string, err error, key string, params map[string]string, detail string) {
		s := ipc.ResetDNSStep{Name: name, OK: err == nil, DetailKey: key, DetailParams: params, Detail: detail}
		if err != nil {
			s.DetailKey = "reset_dns.detail." + name + "_failed"
			s.DetailParams = map[string]string{"error": err.Error()}
			s.Detail = err.Error()
			slog.Warn("reset DNS: step failed", "step", name, "error", err)
		}
		resp.Steps = append(resp.Steps, s)
	}

	// A restore still in progress owns tunnels the sets below do not list yet.
	h.registerPendingRestore()
	tunnels := h.resetTunnels()
	if len(tunnels) > 0 && !req.Force {
		resp.Refused = true
		resp.Reason = ipc.ResetRefusedTunnels
		resp.ConnectedTunnels = tunnels
		return resp, false
	}
	// A wanted kill switch would put its zero-tunnel blockade straight back on
	// the next reconcile tick, so the reset is pointless unless it goes off too.
	h.rememberEnabledKillSwitch()
	h.mu.Lock()
	ksWanted := h.killSwitchWanted
	h.mu.Unlock()
	if ksWanted && !req.KillSwitchOff {
		resp.Refused = true
		resp.Reason = ipc.ResetRefusedKillSwitch
		return resp, false
	}
	slog.Warn("reset DNS & firewall requested by the user", "force", req.Force, "tunnels", tunnels, "kill_switch_off", ksWanted)

	if len(tunnels) > 0 {
		// An explicit user Off: latches automation, withdraws pending
		// restore and persists the desired state, like Disconnect.
		list := strings.Join(tunnels, ", ")
		step("disconnect", resetDisconnectAll(h), "reset_dns.detail.disconnect_ok",
			map[string]string{"tunnels": list}, "Disconnected: "+list)
		if still := h.resetTunnels(); len(still) > 0 {
			resp.ConnectedTunnels = still
			list := strings.Join(still, ", ")
			resp.Steps = append(resp.Steps, ipc.ResetDNSStep{
				Name: "remaining", OK: false,
				DetailKey:    "reset_dns.detail.remaining_failed",
				DetailParams: map[string]string{"tunnels": list},
				Detail:       "Still connected, nothing else was changed: " + list,
			})
			slog.Warn("reset DNS: tunnels survived the disconnect; stopping", "tunnels", still)
			return resp, false
		}
	}

	ksTurnedOff := false
	if ksWanted {
		err := h.setKillSwitchHeld(false)
		ksTurnedOff = true // the setting is off and persisted even if applying failed
		step("kill_switch", err, "reset_dns.detail.kill_switch_ok", nil, "Kill switch turned off")
	}

	err := h.firewall.Cleanup()
	if err == nil {
		// The rules are gone; make the reconciles compare against that.
		clear(h.ksIfaces)
		clear(h.permitRemovalRetries)
		h.ksApplied = ""
		h.dnsMu.Lock()
		h.dnsApplied = ""
		h.dnsMu.Unlock()
	}
	step("firewall", err, "reset_dns.detail.firewall_ok", nil, "WireGuide firewall rules removed")

	step("split_dns", resetSweepSplitDNS(), "reset_dns.detail.split_dns_ok", nil, "Split DNS entries removed")

	attempted, pending := resetRetryPendingCleanup(h)
	switch {
	case len(pending) > 0:
		list := strings.Join(pending, ", ")
		resp.Steps = append(resp.Steps, ipc.ResetDNSStep{
			Name: "dns_recovery", OK: false,
			DetailKey:    "reset_dns.detail.dns_recovery_pending",
			DetailParams: map[string]string{"tunnels": list},
			Detail:       "DNS recovery still pending for " + list + "; its journal is kept and will be retried",
		})
		slog.Warn("reset DNS: DNS recovery still pending; journals retained", "tunnels", pending)
	case attempted > 0:
		n := strconv.Itoa(attempted)
		step("dns_recovery", nil, "reset_dns.detail.dns_recovery_ok", map[string]string{"count": n},
			"Completed "+n+" pending DNS recovery task(s)")
	default:
		step("dns_recovery", nil, "reset_dns.detail.dns_recovery_none", nil, "No DNS recovery was pending")
	}

	resetFlushDNSCache()
	step("dns_cache", nil, "reset_dns.detail.dns_cache_ok", nil, "DNS cache flushed")
	return resp, ksTurnedOff
}
