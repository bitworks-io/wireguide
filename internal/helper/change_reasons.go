package helper

import (
	"context"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/reconnect"
)

// recentDisconnectTTL is how long an end reason stays in the status's
// recent_disconnects map. Long enough for any GUI status tick to see it.
const recentDisconnectTTL = time.Minute

// changeNow is the clock for change records (tests may replace it).
var changeNow = time.Now

// reasonForTrigger maps a reconnect monitor trigger to a change reason.
// An untagged retry (or one from an older caller) is a plain reconnect.
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
// reason. Takes only changeMu.
func (h *Helper) beginConnectReason(name, reason string) (undo func()) {
	if name == "" || reason == "" {
		return func() {}
	}
	h.changeMu.Lock()
	defer h.changeMu.Unlock()
	if h.connectReasons == nil {
		h.connectReasons = make(map[string]changeRecord)
	}
	prev, hadPrev := h.connectReasons[name]
	h.connectReasons[name] = changeRecord{reason: reason, at: changeNow()}
	delete(h.endReasons, name)
	return func() {
		h.changeMu.Lock()
		defer h.changeMu.Unlock()
		if hadPrev {
			h.connectReasons[name] = prev
		} else {
			delete(h.connectReasons, name)
		}
	}
}

// beginDisconnectReason records why name is about to go down, BEFORE the
// teardown, so no status tick can observe the tunnel gone without its
// reason. The returned func undoes it when the teardown failed and the
// tunnel is still up. Takes only changeMu.
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
// renamed, but a recent end reason can linger). Takes only changeMu.
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
// and the unexpired end reasons for tunnels that are not active. Expired
// end reasons are pruned. Takes only changeMu.
func (h *Helper) changeSnapshot(active map[string]bool) (connected, ended map[string]domain.TunnelChange) {
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

// tunnelListed reports whether the manager still lists name (in any state).
// Used to decide whether a failed teardown left the tunnel up.
func (h *Helper) tunnelListed(name string) bool {
	for _, n := range h.manager.ActiveTunnels() {
		if n == name {
			return true
		}
	}
	return false
}
