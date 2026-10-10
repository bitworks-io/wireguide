package helper

import (
	"context"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/storage"
)

// recentDisconnectTTL is how long an end reason stays in the status's
// recent_disconnects map. Long enough for any GUI status tick to see it.
const recentDisconnectTTL = time.Minute

// changeNow is the clock for change records (tests may replace it).
var changeNow = time.Now

// reasonForTrigger maps a reconnect monitor trigger to a change reason.
func reasonForTrigger(t reconnect.Trigger) string {
	switch t {
	case reconnect.TriggerWake:
		return domain.ChangeReasonWake
	case reconnect.TriggerNetworkChange:
		return domain.ChangeReasonNetworkChange
	case reconnect.TriggerHealthCheck:
		return domain.ChangeReasonHealthCheck
	}
	return domain.ChangeReasonReconnect
}

// reconnectReason is the change reason for a reconnect made under ctx.
func reconnectReason(ctx context.Context) string {
	return reasonForTrigger(reconnect.TriggerFromContext(ctx))
}

// changeRecord is one recorded reason with its wall time.
type changeRecord struct {
	reason string
	at     time.Time
}

func (r changeRecord) dto() domain.TunnelChange {
	return domain.TunnelChange{Reason: r.reason, At: r.at.UTC().Format(time.RFC3339)}
}

// beginConnectReason records why name is coming up BEFORE the connect: the
// manager lists a Connecting tunnel as active, and the GUI's history opens
// the session on that first tick, so the reason must already be there.
// The previous session's end reason is dropped as the attempt starts: the
// GUI may open a new session on the Connecting tick, and if this attempt
// fails that session must not be closed with the earlier disconnect's
// reason. undo (any failure, including already-connected) restores only the
// connect record, so a tunnel that was already up keeps its original
// reason, and leaves the end reason absent (the GUI's default applies).
// Takes only changeMu.
func (h *Helper) beginConnectReason(name, reason string) (commit, undo func()) {
	if name == "" || reason == "" {
		return func() {}, func() {}
	}
	h.changeMu.Lock()
	defer h.changeMu.Unlock()
	if h.connectReasons == nil {
		h.connectReasons = make(map[string]changeRecord)
	}
	prev, hadPrev := h.connectReasons[name]
	h.connectReasons[name] = changeRecord{reason: reason, at: changeNow()}
	delete(h.endReasons, name)
	commit = func() {
		h.changeMu.Lock()
		delete(h.endReasons, name)
		h.changeMu.Unlock()
	}
	undo = func() {
		h.changeMu.Lock()
		defer h.changeMu.Unlock()
		if hadPrev {
			h.connectReasons[name] = prev
		} else {
			delete(h.connectReasons, name)
		}
	}
	return commit, undo
}

// recordConnectReason notes why name just came up. Takes only changeMu, so
// it is safe under connectMu.
func (h *Helper) recordConnectReason(name, reason string) {
	if name == "" || reason == "" {
		return
	}
	h.changeMu.Lock()
	defer h.changeMu.Unlock()
	if h.connectReasons == nil {
		h.connectReasons = make(map[string]changeRecord)
	}
	h.connectReasons[name] = changeRecord{reason: reason, at: changeNow()}
	delete(h.endReasons, name)
}

// beginDisconnectReason records why name is about to go down, BEFORE the
// teardown, so no status tick can observe the tunnel gone without its
// reason. The returned func undoes it when the teardown failed.
func (h *Helper) beginDisconnectReason(name, reason string) (undo func()) {
	if name == "" || reason == "" {
		return func() {}
	}
	h.changeMu.Lock()
	defer h.changeMu.Unlock()
	if h.endReasons == nil {
		h.endReasons = make(map[string]changeRecord)
	}
	prev, hadPrev := h.endReasons[name]
	h.endReasons[name] = changeRecord{reason: reason, at: changeNow()}
	return func() {
		h.changeMu.Lock()
		defer h.changeMu.Unlock()
		if hadPrev {
			h.endReasons[name] = prev
		} else {
			delete(h.endReasons, name)
		}
	}
}

// renameChangeReasons moves name's records (connected tunnels can't be
// renamed, but a recent end reason can linger).
func (h *Helper) renameChangeReasons(oldName, newName string) {
	h.changeMu.Lock()
	defer h.changeMu.Unlock()
	if r, ok := h.connectReasons[oldName]; ok {
		delete(h.connectReasons, oldName)
		h.connectReasons[newName] = r
	}
	if r, ok := h.endReasons[oldName]; ok {
		delete(h.endReasons, oldName)
		h.endReasons[newName] = r
	}
}

// changeSnapshot returns the connect reasons for the given active tunnels
// and the unexpired end reasons for tunnels that are not active. Connect
// reasons of tunnels no longer active are dropped; expired end reasons are
// pruned.
func (h *Helper) changeSnapshot(active map[string]bool) (connected map[string]domain.TunnelChange, ended map[string]domain.TunnelChange) {
	now := changeNow()
	h.changeMu.Lock()
	defer h.changeMu.Unlock()
	for name, r := range h.connectReasons {
		if !active[name] {
			continue
		}
		if connected == nil {
			connected = make(map[string]domain.TunnelChange)
		}
		connected[name] = r.dto()
	}
	for name, r := range h.endReasons {
		if now.Sub(r.at) > recentDisconnectTTL {
			delete(h.endReasons, name)
			continue
		}
		if active[name] {
			continue
		}
		if ended == nil {
			ended = make(map[string]domain.TunnelChange)
		}
		ended[name] = r.dto()
	}
	return connected, ended
}

// setHealthOverride records name's override from a connect request or its
// sidecar. Unknown values count as inherit. Caller may hold connectMu.
func (h *Helper) setHealthOverride(name, v string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.healthOverride == nil {
		h.healthOverride = make(map[string]string)
	}
	switch v {
	case storage.HealthCheckOn, storage.HealthCheckOff:
		h.healthOverride[name] = v
	default:
		delete(h.healthOverride, name)
	}
}

// dropHealthOverrideLocked forgets name's override (tunnel torn down).
// Caller must hold h.mu.
func (h *Helper) dropHealthOverrideLocked(name string) {
	delete(h.healthOverride, name)
}

// sidecarHealthCheck reads name's override from its .meta.json ("" when
// there is no store, no sidecar or no value).
func (h *Helper) sidecarHealthCheck(name string) (string, bool) {
	if h.userTunnelStore == nil {
		return "", false
	}
	meta, err := h.userTunnelStore.LoadMeta(name)
	if err != nil || meta == nil {
		return "", false
	}
	return meta.HealthCheck, true
}

// healthCheckEnabledFor is the reconnect monitor's per-tunnel filter:
// "on" -> true, "off" -> false, inherit/empty/unknown -> the global setting.
// The sidecar is the live source when the helper can read it (so a change
// made while connected applies on the next tick); otherwise the value the
// GUI sent with the connect request is used.
func (h *Helper) healthCheckEnabledFor(name string, global bool) bool {
	v, ok := h.sidecarHealthCheck(name)
	if !ok {
		h.mu.Lock()
		v = h.healthOverride[name]
		h.mu.Unlock()
	}
	return resolveHealthCheck(v, global)
}

// resolveHealthCheck applies the override precedence.
func resolveHealthCheck(v string, global bool) bool {
	switch v {
	case storage.HealthCheckOn:
		return true
	case storage.HealthCheckOff:
		return false
	}
	return global
}
