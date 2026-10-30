package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/ipc"
)

// autoDecision is the (action, rule) pair last recorded for a tunnel. A
// held/latched/skipped_overlap event is broadcast (and a held/latched log
// line raised to Info) only when this pair changes, so a tunnel sitting in
// the same non-executed state across many network ticks produces one event,
// not one per tick. skipped_overlap is also sent when the legacy overlap
// signature dedupe (reportAutomationOverlap) sees a new overlap.
type autoDecision struct {
	action    string
	ruleIndex int
}

// automationEvent builds the event.automation payload for tunnel name.
func automationEvent(name, action string, ruleIndex int, rules []automation.Rule, ctx automation.NetworkContext, err error) ipc.AutomationEventPayload {
	ev := ipc.AutomationEventPayload{
		Tunnel:    name,
		Action:    action,
		RuleIndex: ruleIndex,
		RuleText:  automation.DescribeRule(rules, ruleIndex),
		SSID:      ctx.SSID,
		Settled:   ctx.Settled,
		At:        time.Now().UTC().Format(time.RFC3339),
	}
	if err != nil {
		ev.Error = err.Error()
	}
	return ev
}

// recordAutomationDecision stores ev as tunnel's latest decision and
// reports whether it differs from the previous one (or there was none).
func (h *Helper) recordAutomationDecision(ev ipc.AutomationEventPayload) bool {
	d := autoDecision{action: ev.Action, ruleIndex: ev.RuleIndex}
	h.autoEvMu.Lock()
	defer h.autoEvMu.Unlock()
	if h.lastAutoEvent == nil {
		h.lastAutoEvent = make(map[string]autoDecision)
	}
	prev, ok := h.lastAutoEvent[ev.Tunnel]
	h.lastAutoEvent[ev.Tunnel] = d
	return !ok || prev != d
}

// clearAutomationDecision forgets tunnel's last decision (its desired
// state holds, or no rule decides), so the next held/latched episode is
// reported again.
func (h *Helper) clearAutomationDecision(name string) {
	h.autoEvMu.Lock()
	delete(h.lastAutoEvent, name)
	h.autoEvMu.Unlock()
}

// pruneAutomationDecisions drops decision and rules-hash entries for
// tunnels that no longer have rules (rules removed, tunnel deleted).
func (h *Helper) pruneAutomationDecisions(rules map[string][]automation.Rule) {
	h.autoEvMu.Lock()
	defer h.autoEvMu.Unlock()
	for name := range h.lastAutoEvent {
		if len(rules[name]) == 0 {
			delete(h.lastAutoEvent, name)
		}
	}
	for name := range h.rulesHash {
		if len(rules[name]) == 0 {
			delete(h.rulesHash, name)
		}
	}
}

// renameAutomationState moves the per-tunnel automation bookkeeping (last
// decision, rules hash) from oldName to newName.
func (h *Helper) renameAutomationState(oldName, newName string) {
	h.autoEvMu.Lock()
	defer h.autoEvMu.Unlock()
	if d, ok := h.lastAutoEvent[oldName]; ok {
		delete(h.lastAutoEvent, oldName)
		h.lastAutoEvent[newName] = d
	}
	if v, ok := h.rulesHash[oldName]; ok {
		delete(h.rulesHash, oldName)
		h.rulesHash[newName] = v
	}
}

// dropAutomationState forgets the per-tunnel automation bookkeeping of a
// deleted tunnel.
func (h *Helper) dropAutomationState(name string) {
	h.autoEvMu.Lock()
	delete(h.lastAutoEvent, name)
	delete(h.rulesHash, name)
	h.autoEvMu.Unlock()
}

// noteRulesLoaded logs 'automation: rules loaded' at Info when tunnel's
// rules differ from the last evaluation (first load included), so the log
// shows which tunnel's rules changed without repeating on every tick.
func (h *Helper) noteRulesLoaded(name string, rules []automation.Rule) {
	b, err := json.Marshal(rules)
	if err != nil {
		return
	}
	sum := sha256.Sum256(b)
	hash := hex.EncodeToString(sum[:8])
	h.autoEvMu.Lock()
	if h.rulesHash == nil {
		h.rulesHash = make(map[string]string)
	}
	changed := h.rulesHash[name] != hash
	h.rulesHash[name] = hash
	h.autoEvMu.Unlock()
	if changed {
		slog.Info("automation: rules loaded", "tunnel", name, "count", len(rules))
	}
}

// emitAutomationEvent broadcasts ev as event.automation. Callers MUST NOT
// hold connectMu: emission always happens after the connect/disconnect has
// released it. (ipc.Server.Broadcast never blocks, but the rule keeps the
// lock order trivially safe.)
func (h *Helper) emitAutomationEvent(ev ipc.AutomationEventPayload) {
	if h.emitAutomationFn != nil {
		h.emitAutomationFn(ev)
		return
	}
	if h.server != nil {
		h.server.Broadcast(ipc.EventAutomation, ev)
	}
}

// reportAutomationChange records a held/latched decision and broadcasts it
// only when it differs from the tunnel's previous one. It reports whether
// it did, so the caller can raise its log line from Debug to Info.
func (h *Helper) reportAutomationChange(ev ipc.AutomationEventPayload) bool {
	if !h.recordAutomationDecision(ev) {
		return false
	}
	h.emitAutomationEvent(ev)
	return true
}

// reportAutomationExecuted records and always broadcasts an executed
// rule-driven connect/disconnect (successful or failed).
func (h *Helper) reportAutomationExecuted(ev ipc.AutomationEventPayload) {
	h.recordAutomationDecision(ev)
	h.emitAutomationEvent(ev)
}

// automationActiveTunnels lists the tunnels automation treats as up
// (manager.ActiveTunnels; automationActiveFn overrides it in tests).
func (h *Helper) automationActiveTunnels() []string {
	if h.automationActiveFn != nil {
		return h.automationActiveFn()
	}
	return h.manager.ActiveTunnels()
}
