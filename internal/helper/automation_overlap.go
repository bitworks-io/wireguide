package helper

import (
	"log/slog"
	"net"

	"github.com/korjwl1/wireguide/internal/ipc"
)

// reportAutomationOverlap logs and broadcasts event.automation_skipped once
// per (tunnel, overlap) signature. It reports whether this call was the
// first for that signature, so automationConnect can send the matching
// event.automation skipped_overlap too. (The other callers hold connectMu
// and send only the legacy event, as before.)
func (h *Helper) reportAutomationOverlap(name, cidr string, addr net.IP) bool {
	signature := cidr + ":" + addr.String()
	h.wifiMu.Lock()
	if h.automationSkipped == nil {
		h.automationSkipped = make(map[string]string)
	}
	repeated := h.automationSkipped[name] == signature
	h.automationSkipped[name] = signature
	h.wifiMu.Unlock()
	if repeated {
		return false
	}
	slog.Info("automation: not connecting, tunnel AllowedIPs overlap the local network",
		"tunnel", name, "cidr", cidr, "local_address", addr.String())
	if h.server != nil {
		h.server.Broadcast(ipc.EventAutomationSkipped, ipc.AutomationSkippedPayload{
			TunnelName: name, Reason: "lan_overlap",
		})
	}
	return true
}

func (h *Helper) clearAutomationSkip(name string) {
	h.wifiMu.Lock()
	delete(h.automationSkipped, name)
	h.wifiMu.Unlock()
}
