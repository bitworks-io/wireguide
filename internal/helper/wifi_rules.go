package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// loadUserSettings reads the user's settings.json directly. Reading
// fresh on every SSID transition (instead of caching + IPC sync from
// the GUI) means rule edits made in Settings take effect on the next
// network change without any explicit push, and there's no "in-memory
// state diverged from disk" failure mode.
func (h *Helper) loadUserSettings() (*storage.Settings, error) {
	if h.userAppSupport == "" {
		return nil, fmt.Errorf("user app-support dir not derived")
	}
	path := filepath.Join(h.userAppSupport, "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return storage.DefaultSettings(), nil
		}
		return nil, err
	}
	s := storage.DefaultSettings()
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	return s, nil
}

// currentNetworkContext builds the NetworkContext automation rules are
// evaluated against — the single source for both the live engine
// (reevaluateAutomation) and the read-only preview, so `wireguide ctl
// automation` always shows exactly what the engine would act on.
//
// SSID staleness: on macOS the SSID only arrives via GUI reports (the
// root helper can't read it). If the GUI has exited and the machine then
// moved networks, that value is stale. A gateway MAC different from the
// one stamped at report time proves the network changed since the report,
// so the SSID is treated as unknown — SSID rules stop matching rather
// than misfiring on the old network's name, while subnet/MAC rules keep
// working off fresh data. An empty stamp (no report yet, or gateway
// unknown at report time) never invalidates.
//
// The context also carries the default-route interface, whether that is
// Wi-Fi, whether a default route exists, and whether the network
// fingerprint has settled (see automation_state.go).
func (h *Helper) currentNetworkContext() wifi.NetworkContext {
	return h.currentNetworkState().ctx
}

// handleSSIDChange is one trigger for Automation re-evaluation: the
// Wi-Fi monitor fires it on every SSID transition. The actual decision
// logic lives in reevaluateAutomation so the network-change and poll
// triggers share it.
func (h *Helper) handleSSIDChange(oldSSID, newSSID string) {
	h.reevaluateAutomation("ssid-change")
}

// reevaluateAutomation drives every tunnel that has Automation rules
// toward its desired state for the current network context (SSID +
// physical-interface subnets). This runs entirely inside the helper, so
// rules keep firing whether or not a GUI is alive.
//
// Semantics (issue #12): a rule can connect OR disconnect its tunnel
// regardless of how the tunnel was brought up — unlike the legacy path
// which only touched helper-auto-connected tunnels. A tunnel with NO
// rules is never touched. reevalMu serialises evaluations so the slow
// connect/disconnect calls from two overlapping triggers can't race.
func (h *Helper) reevaluateAutomation(reason string) {
	if !h.guiSeen.Load() { // dormant until a GUI attaches (see Helper.guiSeen)
		return
	}
	h.reevalMu.Lock()
	defer h.reevalMu.Unlock()

	settings, err := h.loadUserSettings()
	if err != nil {
		slog.Debug("automation: cannot load settings", "error", err)
		return
	}
	settings.EnsureAutomation()
	auto := settings.Automation
	if auto == nil || len(auto.PerTunnel) == 0 {
		h.pruneLatchesWithoutRules(nil)
		h.pruneAutomationDecisions(nil)
		return
	}

	st := h.currentNetworkState()
	ctx := st.ctx
	h.pruneManualOverrides(st)
	h.pruneLatchesWithoutRules(auto.PerTunnel)
	h.pruneAutomationDecisions(auto.PerTunnel)

	active := make(map[string]bool)
	for _, n := range h.automationActiveTunnels() {
		active[n] = true
	}

	// Events are broadcast only after each connect/disconnect below has
	// returned — they release connectMu before returning — so nothing is
	// ever emitted under it.
	// note records a decision and broadcasts it right away when it is
	// reportable — immediately after each connect/disconnect returns (it
	// has released connectMu by then), so a successful connect's
	// event.automation + auto_connect are not delayed behind slower work
	// on other tunnels in the same pass.
	note := func(ev *ipc.AutomationEventPayload) bool {
		if ev == nil || !h.noteAutomationDecision(*ev) {
			return false
		}
		h.emitAutomationEvents([]ipc.AutomationEventPayload{*ev})
		return true
	}

	anyNegated, anyMedium := false, false
	for _, name := range auto.TunnelNames() {
		rules := auto.PerTunnel[name]
		h.noteRulesLoaded(name, rules)
		if wifi.HasNegated(rules) {
			anyNegated = true
		}
		if wifi.UsesMedium(rules) {
			anyMedium = true
		}
		if latch, ok := h.manualLatchFor(name); ok {
			ev := automationEvent(name, ipc.AutomationActionLatched, -1, rules, ctx, nil)
			lvl := slog.LevelDebug
			if note(&ev) {
				lvl = slog.LevelInfo
			}
			slog.Log(context.Background(), lvl, "automation: tunnel latched by manual override, skipping",
				"tunnel", name, "disconnected", latch.disconnected, "reason", reason)
			continue
		}
		state, info := wifi.EvaluateDetailed(rules, ctx)
		if info.Held {
			ev := automationEvent(name, ipc.AutomationActionHeld, info.RuleIndex, rules, ctx, nil)
			lvl := slog.LevelDebug
			if note(&ev) {
				lvl = slog.LevelInfo
			}
			slog.Log(context.Background(), lvl, "automation: negated rule undecidable, holding",
				"tunnel", name, "rule", info.RuleIndex, "reason", reason,
				"ssid", ctx.SSID, "settled", ctx.Settled, "online", ctx.Online)
		}
		// A decided rule whose desired state already holds is a (silent)
		// decision too: forget the last reported one, so a later held /
		// latched episode (e.g. the next roam blip) counts as a change and
		// is reported once again.
		switch state {
		case wifi.StateConnect:
			if !active[name] {
				note(h.automationConnect(name, reason, ctx, rules, info.RuleIndex))
			} else {
				h.clearAutomationDecision(name)
			}
		case wifi.StateDisconnect:
			if active[name] {
				slog.Info("automation: rule disconnect", "tunnel", name, "reason", reason, "ssid", ctx.SSID)
				note(h.disconnectAutoManaged(name, ctx, rules, info.RuleIndex))
			} else {
				// Already down, but a health-check retry left over from a
				// failed reconnect may still be pending for it; automation
				// wants it down, so that retry must not bring it back.
				if h.monitor != nil {
					h.monitor.CancelRetryFor(name)
				}
				h.clearAutomationDecision(name)
			}
		case wifi.StateUnmanaged:
			if !info.Held {
				h.clearAutomationDecision(name)
			}
		}
	}

	// A negated rule can't act, and a manual latch can't clear, until the
	// network has been stable for the settle window, and nothing else
	// re-triggers evaluation then.
	// An unknown medium (macOS: interface not yet in the hardware-port
	// listing) is re-checked shortly, since a corrected classification
	// changes no fingerprint and triggers nothing by itself.
	delay := time.Duration(-1)
	if (anyNegated || h.hasManualOverrides()) && !ctx.Settled {
		delay = st.settleRemaining
	}
	if h.mediumRetryDue(ctx, anyMedium) && (delay < 0 || mediumRetryInterval < delay) {
		delay = mediumRetryInterval
	}
	if delay >= 0 {
		h.armSettleTimer(delay)
	}
}

// handleAutomationPreview is a read-only dry-run of the Automation
// engine: it reports the current network context and each rule-bearing
// tunnel's evaluated decision, without connecting or disconnecting
// anything. Backs `wireguide ctl automation` and answers "why did this
// tunnel (dis)connect?".
func (h *Helper) handleAutomationPreview(_ json.RawMessage) (interface{}, error) {
	settings, err := h.loadUserSettings()
	if err != nil {
		return nil, err
	}
	settings.EnsureAutomation()
	auto := settings.Automation

	st := h.peekNetworkState()
	ctx := st.ctx

	ipStrs := make([]string, 0, len(ctx.PhysicalIPs))
	for _, ip := range ctx.PhysicalIPs {
		ipStrs = append(ipStrs, ip.String())
	}

	active := make(map[string]bool)
	for _, n := range h.manager.ActiveTunnels() {
		active[n] = true
	}

	resp := ipc.AutomationPreviewResponse{
		SSID: ctx.SSID, PhysicalIPs: ipStrs, GatewayMAC: ctx.GatewayMAC,
		PrimaryIface: ctx.PrimaryIface, PrimaryIsWiFi: ctx.PrimaryIsWiFi,
		Online: ctx.Online, Settled: ctx.Settled, Medium: ctx.Medium,
		SettleRemainingSec: int((st.settleRemaining + time.Second - 1) / time.Second),
	}
	if auto != nil {
		for _, name := range auto.TunnelNames() {
			rules := auto.PerTunnel[name]
			decision := "unmanaged"
			state, info := wifi.EvaluateDetailed(rules, ctx)
			switch state {
			case wifi.StateConnect:
				decision = "connect"
			case wifi.StateDisconnect:
				decision = "disconnect"
			}
			_, latched := h.manualLatchFor(name)
			if info.Held {
				decision = "held"
			}
			if latched {
				decision = "latched"
			}
			resp.Tunnels = append(resp.Tunnels, ipc.AutomationTunnelDecision{
				Name:      name,
				RuleCount: len(rules),
				Decision:  decision,
				Active:    active[name],
				Held:      info.Held,
				Latched:   latched,
			})
		}
	}
	return resp, nil
}

// automationConnect brings up a tunnel a rule matched and records it in
// the auto-managed map. Caller holds reevalMu. It returns the event to
// broadcast (nil when there is nothing to report); the caller emits it,
// never under connectMu. ruleIndex/rules identify the deciding rule.
func (h *Helper) automationConnect(name, reason string, ctx wifi.NetworkContext, rules []wifi.Rule, ruleIndex int) *ipc.AutomationEventPayload {
	ssid := ctx.SSID
	fail := func(err error) *ipc.AutomationEventPayload {
		ev := automationEvent(name, ipc.AutomationActionConnect, ruleIndex, rules, ctx, err)
		return &ev
	}
	if h.userTunnelStore == nil {
		slog.Warn("automation: tunnel store unavailable, cannot connect", "tunnel", name)
		return fail(fmt.Errorf("tunnel store unavailable"))
	}
	cfg, err := h.userTunnelStore.Load(name)
	if err != nil {
		slog.Warn("automation: cannot load tunnel config", "tunnel", name, "error", err)
		return fail(fmt.Errorf("cannot load tunnel config: %w", err))
	}
	if cidr, addr, overlaps := overlapsLocalNetwork(cfg); overlaps {
		ev := automationEvent(name, ipc.AutomationActionSkippedOverlap, ruleIndex, rules, ctx, nil)
		lvl := slog.LevelDebug
		if h.wouldReportDecision(ev) {
			lvl = slog.LevelInfo
		}
		slog.Log(context.Background(), lvl, "automation: not connecting, tunnel AllowedIPs overlap the local network",
			"tunnel", name, "cidr", cidr, "local_address", addr.String())
		return &ev
	}
	hc, _ := h.sidecarHealthCheck(name)
	slog.Info("automation: rule connect", "tunnel", name, "reason", reason, "ssid", ssid)
	h.connectMu.Lock()
	// A manual connect/disconnect may have landed while we waited for
	// connectMu (our own route churn re-triggers evaluation within
	// milliseconds); its latch is recorded before it releases the lock.
	if _, latched := h.manualLatchFor(name); latched {
		h.connectMu.Unlock()
		slog.Info("automation: connect skipped, manual override latched", "tunnel", name)
		ev := automationEvent(name, ipc.AutomationActionLatched, -1, rules, ctx, nil)
		return &ev
	}
	commitReason, undoReason := h.beginConnectReason(name, domain.ChangeReasonAutomation)
	err = h.doConnectHeld(cfg)
	if err != nil {
		undoReason()
	} else {
		commitReason()
		h.setHealthOverride(name, hc)
		// Same firewall follow-up a manual connect does — otherwise a
		// headless automation connect gets no DNS protection and, if the
		// kill switch is already on, its endpoints are never permitted so
		// the tunnel can't pass traffic (issue #12).
		h.applyPostConnectFirewall(cfg)
	}
	h.connectMu.Unlock()
	if err != nil {
		slog.Warn("automation connect failed", "tunnel", name, "error", err)
		return fail(err)
	}
	h.wifiMu.Lock()
	h.autoConnectedBy[name] = ssid
	h.wifiMu.Unlock()
	// The caller broadcasts this event followed by auto_connect (the post-
	// connect refresh trigger every GUI relies on), in that order, so a
	// GUI that understands event.automation has the rule details first.
	ev := automationEvent(name, ipc.AutomationActionConnect, ruleIndex, rules, ctx, nil)
	return &ev
}

// disconnectAutoManaged tears down a tunnel that the wifi-rule
// engine auto-connected, then clears every cache that referenced it
// (activeCfgs, autoConnectedBy, in-flight retry). Without each of
// these cleanups the helper's various recovery paths would
// resurrect the tunnel: the reconnect monitor would fire its
// pending retry; manager.Disconnect()'s legacy "all tunnels" path
// would re-Connect from a stale activeCfgs entry; and the next
// SSID change handler would try to disconnect a tunnel already
// gone.
func (h *Helper) disconnectAutoManaged(name string, ctx wifi.NetworkContext, rules []wifi.Rule, ruleIndex int) *ipc.AutomationEventPayload {
	// Same lock the manual disconnect path holds, so a rule-driven teardown
	// can't interleave with a Connect/Disconnect from a GUI or the CLI.
	// Lock order: reevalMu (held by our caller) -> connectMu. Nothing under
	// connectMu may re-enter reevaluateAutomation or broadcast the event
	// (the caller emits the returned event after we release connectMu).
	h.connectMu.Lock()
	if _, latched := h.manualLatchFor(name); latched {
		h.connectMu.Unlock()
		slog.Info("automation: disconnect skipped, manual override latched", "tunnel", name)
		ev := automationEvent(name, ipc.AutomationActionLatched, -1, rules, ctx, nil)
		return &ev
	}
	if h.monitor != nil {
		h.monitor.CancelRetryFor(name)
	}
	undoReason := h.beginDisconnectReason(name, domain.ChangeReasonAutomation)
	disconnectErr := h.manager.DisconnectTunnel(name)
	if disconnectErr != nil {
		slog.Warn("automation disconnect failed", "tunnel", name, "error", disconnectErr)
		if !h.tunnelGone(name) {
			undoReason()
		}
	}
	h.mu.Lock()
	delete(h.activeCfgs, name)
	h.dropHealthOverrideLocked(name)
	h.mu.Unlock()
	h.wifiMu.Lock()
	delete(h.autoConnectedBy, name)
	h.wifiMu.Unlock()
	// Prune the latency cache exactly as handleDisconnect does — otherwise
	// the status broadcast keeps reporting the dead tunnel's last RTT.
	h.latencyMu.Lock()
	delete(h.latencyByTunnel, name)
	h.latencyMu.Unlock()
	// Strips the dead tunnel's kill-switch permit (issue #12) and its DNS
	// rules, exactly as handleDisconnect does.
	h.reconcileFirewallLocked("automation-disconnect")
	h.cancelLegacyRetryIfIdle()
	h.connectMu.Unlock()
	h.maybeArmShutdownAfterTeardown("rule-driven disconnect, no GUI attached")
	ev := automationEvent(name, ipc.AutomationActionDisconnect, ruleIndex, rules, ctx, disconnectErr)
	return &ev
}
