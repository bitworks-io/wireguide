package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// autoDecision is the (action, rule) pair last emitted for a tunnel. A
// held/latched/skipped_overlap event is broadcast (and its log line raised
// to Info) only when this pair changes, so a tunnel sitting in the same
// non-executed state across many network ticks produces one event, not one
// per tick.
type autoDecision struct {
	action    string
	ruleIndex int
}

// automationEvent builds the event payload for tunnel name.
func automationEvent(name, action string, ruleIndex int, rules []wifi.Rule, ctx wifi.NetworkContext, err error) ipc.AutomationEventPayload {
	ev := ipc.AutomationEventPayload{
		Tunnel:    name,
		Action:    action,
		RuleIndex: ruleIndex,
		RuleText:  wifi.DescribeRule(rules, ruleIndex),
		SSID:      ctx.SSID,
		Settled:   ctx.Settled,
		At:        time.Now().UTC().Format(time.RFC3339),
	}
	if err != nil {
		ev.Error = err.Error()
	}
	return ev
}

// noteAutomationDecision records ev as tunnel's latest decision and reports
// whether it should be broadcast: executed connects/disconnects always,
// held/latched/skipped_overlap only when the (action, rule) pair differs
// from the last one recorded for that tunnel.
func (h *Helper) noteAutomationDecision(ev ipc.AutomationEventPayload) bool {
	d := autoDecision{action: ev.Action, ruleIndex: ev.RuleIndex}
	h.autoEvMu.Lock()
	defer h.autoEvMu.Unlock()
	if h.lastAutoEvent == nil {
		h.lastAutoEvent = make(map[string]autoDecision)
	}
	prev, ok := h.lastAutoEvent[ev.Tunnel]
	h.lastAutoEvent[ev.Tunnel] = d
	switch ev.Action {
	case ipc.AutomationActionConnect, ipc.AutomationActionDisconnect:
		return true
	}
	return !ok || prev != d
}

// clearAutomationDecision forgets tunnel's last decision ("no decision"
// now), so the next held/latched/skipped state is reported again.
func (h *Helper) clearAutomationDecision(name string) {
	h.autoEvMu.Lock()
	delete(h.lastAutoEvent, name)
	h.autoEvMu.Unlock()
}

// pruneAutomationDecisions drops decision and rules-hash entries for
// tunnels that no longer have rules (rules removed, tunnel deleted).
func (h *Helper) pruneAutomationDecisions(rules map[string][]wifi.Rule) {
	h.autoEvMu.Lock()
	for name := range h.lastAutoEvent {
		if len(rules[name]) == 0 {
			delete(h.lastAutoEvent, name)
		}
	}
	h.autoEvMu.Unlock()
	h.rulesHashMu.Lock()
	for name := range h.rulesHash {
		if len(rules[name]) == 0 {
			delete(h.rulesHash, name)
		}
	}
	h.rulesHashMu.Unlock()
}

// renameAutomationState moves the per-tunnel automation bookkeeping (last
// decision, rules hash) from oldName to newName.
func (h *Helper) renameAutomationState(oldName, newName string) {
	h.autoEvMu.Lock()
	if d, ok := h.lastAutoEvent[oldName]; ok {
		delete(h.lastAutoEvent, oldName)
		h.lastAutoEvent[newName] = d
	}
	h.autoEvMu.Unlock()
	h.rulesHashMu.Lock()
	if v, ok := h.rulesHash[oldName]; ok {
		delete(h.rulesHash, oldName)
		h.rulesHash[newName] = v
	}
	h.rulesHashMu.Unlock()
}

// noteRulesLoaded logs 'automation: rules loaded' at Info when tunnel's
// rules differ from the last evaluation (first load included).
func (h *Helper) noteRulesLoaded(name string, rules []wifi.Rule) {
	b, err := json.Marshal(rules)
	if err != nil {
		return
	}
	sum := sha256.Sum256(b)
	hash := hex.EncodeToString(sum[:8])
	h.rulesHashMu.Lock()
	if h.rulesHash == nil {
		h.rulesHash = make(map[string]string)
	}
	changed := h.rulesHash[name] != hash
	h.rulesHash[name] = hash
	h.rulesHashMu.Unlock()
	if changed {
		slog.Info("automation: rules loaded", "tunnel", name, "count", len(rules))
	}
}

// emitAutomationEvents broadcasts events. Callers MUST NOT hold connectMu:
// emission always happens after the connect/disconnect has released it.
// (ipc.Server.Broadcast never blocks — a slow subscriber's event is
// dropped — but the rule keeps lock order trivially safe.)
//
// A successful connect is followed by EventAutoConnect, the post-connect
// refresh trigger every GUI relies on. Sending it after the automation
// event lets a GUI that understands event.automation claim the change with
// the rule details before the generic event arrives (one subscriber's
// stream is FIFO).
func (h *Helper) emitAutomationEvents(events []ipc.AutomationEventPayload) {
	for _, ev := range events {
		if h.emitAutomationFn != nil {
			h.emitAutomationFn(ev)
		} else if h.server != nil {
			h.server.Broadcast(ipc.EventAutomation, ev)
		}
		if ev.Action == ipc.AutomationActionConnect && ev.Error == "" && h.server != nil {
			h.server.Broadcast(ipc.EventAutoConnect, ipc.AutoConnectPayload{TunnelName: ev.Tunnel})
		}
	}
}

// wouldReportDecision reports whether ev differs from tunnel's last
// recorded decision, without recording it (log level only).
func (h *Helper) wouldReportDecision(ev ipc.AutomationEventPayload) bool {
	h.autoEvMu.Lock()
	defer h.autoEvMu.Unlock()
	prev, ok := h.lastAutoEvent[ev.Tunnel]
	return !ok || prev != (autoDecision{action: ev.Action, ruleIndex: ev.RuleIndex})
}

// tunnelGone reports whether name is no longer connected.
func (h *Helper) tunnelGone(name string) bool {
	for _, n := range h.connectedTunnels() {
		if n == name {
			return false
		}
	}
	return true
}

// automationActiveTunnels lists the tunnels automation treats as up
// (manager.ActiveTunnels; automationActiveFn overrides it in tests).
func (h *Helper) automationActiveTunnels() []string {
	if h.automationActiveFn != nil {
		return h.automationActiveFn()
	}
	return h.manager.ActiveTunnels()
}
