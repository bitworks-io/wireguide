package domain

import (
	"fmt"
	"time"
)

// State represents the tunnel connection state.
type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateError        State = "error"
)

// ConnectionStatus is the single source of truth for tunnel connection state
// across the whole application. It carries both wire-safe fields (strings,
// JSON-tagged) that are sent to the frontend, and internal fields (time.Time,
// `json:"-"`) that the reconnect monitor and other backend services use for
// duration math.
//
// Note that `LastHandshake` is the *formatted age string* (e.g. "5s", "2m 10s")
// that the frontend displays, while `LastHandshakeTime` is the absolute
// timestamp used internally. Wire callers see only the former.
type ConnectionStatus struct {
	State             State     `json:"state"`
	TunnelName        string    `json:"tunnel_name"`
	InterfaceName     string    `json:"interface_name,omitempty"`
	ConnectedAt       time.Time `json:"-"`
	Duration          string    `json:"duration,omitempty"`
	RxBytes           int64     `json:"rx_bytes"`
	TxBytes           int64     `json:"tx_bytes"`
	LastHandshakeTime time.Time `json:"-"`
	LastHandshake     string    `json:"last_handshake,omitempty"`
	Endpoint          string    `json:"endpoint,omitempty"`
	// LatencyMs is the most recent measured round-trip time to the
	// endpoint in milliseconds. 0 means "no measurement yet" or "endpoint
	// unreachable" — the frontend treats both the same (renders "—").
	LatencyMs    float64 `json:"latency_ms,omitempty"`
	ErrorMessage string  `json:"error_message,omitempty"`

	// DNSMode / DNSServers / DNSProtected describe what the tunnel did to
	// DNS, filled by the helper for connected tunnels (additive, protocol
	// minor 3). DNSMode is "global" | "split" | "search" | "none" and is the
	// config's intent unless the platform could not apply it (then "none").
	// DNSProtected is true only when the firewall's DNS permit set currently
	// covers this tunnel's servers. Older helpers omit all three.
	DNSMode      string   `json:"dns_mode,omitempty"`
	DNSServers   []string `json:"dns_servers,omitempty"`
	DNSProtected bool     `json:"dns_protected,omitempty"`
	// RoutesSkipped lists AllowedIPs ranges the macOS LAN-overlap guard did
	// not install because they overlap the local network.
	RoutesSkipped []string `json:"routes_skipped,omitempty"`

	// LastChangeReason / LastChangeAt say what last brought this tunnel up
	// (protocol minor 4): one of the ChangeReason* values and an RFC3339
	// time. Empty when the helper does not know (older helper, or a tunnel
	// it did not connect itself).
	LastChangeReason string `json:"last_change_reason,omitempty"`
	LastChangeAt     string `json:"last_change_at,omitempty"`

	// RecentDisconnects maps a tunnel that went down in the last minute to
	// why (top-level only; protocol minor 4). A disconnected tunnel is no
	// longer in the status at all, so this is how its end reason reaches
	// the GUI's history.
	RecentDisconnects map[string]TunnelChange `json:"recent_disconnects,omitempty"`

	// ActiveTunnels lists the names of all currently connected (or connecting)
	// tunnels. Populated by the multi-tunnel manager so the frontend can show
	// which tunnels are active.
	ActiveTunnels []string `json:"active_tunnels,omitempty"`

	// Tunnels carries per-tunnel status for multi-tunnel setups. The frontend
	// uses this to show stats for the selected tunnel rather than the "primary".
	Tunnels []ConnectionStatus `json:"tunnels,omitempty"`
}

// Reasons a tunnel was connected or disconnected (ConnectionStatus
// LastChangeReason, RecentDisconnects, GUI history).
const (
	ChangeReasonUser          = "user"
	ChangeReasonAutomation    = "automation"
	ChangeReasonWake          = "wake"
	ChangeReasonNetworkChange = "network_change"
	ChangeReasonHealthCheck   = "health_check"
	ChangeReasonReconnect     = "reconnect"
	ChangeReasonRecovery      = "recovery"
)

// TunnelChange is one recorded connect/disconnect reason.
type TunnelChange struct {
	Reason string `json:"reason"`
	At     string `json:"at"` // RFC3339
}

// FormatDuration renders a duration in a compact "1h 2m 3s" form used by the
// UI. Negative durations (possible if the system clock jumps backward relative
// to a stored timestamp) are clamped to "0s" rather than producing a
// confusing "-5s" in the UI.
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
