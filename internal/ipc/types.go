package ipc

import "github.com/korjwl1/wireguide/internal/domain"

// Empty is used for requests/responses with no payload.
type Empty struct{}

// PingResponse is returned from Helper.Ping.
type PingResponse struct {
	Version    string `json:"version"`     // IPC protocol version
	AppVersion string `json:"app_version"` // Application version (e.g. "0.1.5")
	PID        int    `json:"pid"`
	// GUIAttached reports whether a non-transient control connection (the
	// GUI) is attached. Protocol minor >= 2; older helpers omit it, so use
	// PingResponse.GUIKnown before trusting a false value.
	GUIAttached bool `json:"gui_attached"`
}

// GUIKnown reports whether the helper that produced this ping reports
// GUIAttached at all (protocol minor >= 2). An older helper cannot say, and
// callers must not read its zero value as "no GUI".
func (p PingResponse) GUIKnown() bool { return MinorOf(p.Version) >= 2 }

// ConnectRequest is the parameter for Tunnel.Connect.
type ConnectRequest struct {
	Config *domain.WireGuardConfig `json:"config"`
}

// ConnectionStatus is the wire representation of the tunnel connection state.
// It is a direct alias of the domain type — there used to be a separate
// `ConnectionStatusDTO` here that drifted from the tunnel package's Status
// struct and caused a `handshake_age` vs `last_handshake` field-name bug in
// the frontend. Unifying on the domain type prevents that class of bug.
type ConnectionStatus = domain.ConnectionStatus

// KillSwitchRequest is the parameter for Firewall.SetKillSwitch.
type KillSwitchRequest struct {
	Enabled bool `json:"enabled"`
}

// DNSProtectionRequest is the parameter for Firewall.SetDNSProtection.
type DNSProtectionRequest struct {
	Enabled    bool     `json:"enabled"`
	DNSServers []string `json:"dns_servers,omitempty"`
}

// ReconnectStateDTO describes ongoing reconnection.
type ReconnectStateDTO struct {
	Reconnecting bool   `json:"reconnecting"`
	Attempt      int    `json:"attempt"`
	MaxAttempts  int    `json:"max_attempts"`
	NextRetry    string `json:"next_retry,omitempty"`
}

// LogEntry is a single structured log record forwarded from the helper
// to the GUI (and from the GUI to the frontend LogViewer). We keep it flat
// — no nested attrs — because the viewer just renders a one-line per entry.
type LogEntry struct {
	Time    string `json:"time"`    // RFC3339
	Level   string `json:"level"`   // "debug" | "info" | "warn" | "error"
	Source  string `json:"source"`  // "helper" | "gui"
	Message string `json:"message"` // human-readable text (already includes attrs)
}

// SetPinInterfaceRequest is the parameter for Network.SetPinInterface.
type SetPinInterfaceRequest struct {
	Enabled bool `json:"enabled"`
}

// SetHealthCheckRequest is the parameter for Monitor.SetHealthCheck.
type SetHealthCheckRequest struct {
	Enabled bool `json:"enabled"`
}

// SetLogLevelRequest is the parameter for Helper.SetLogLevel.
type SetLogLevelRequest struct {
	Level string `json:"level"` // "debug" | "info" | "warn" | "error"
}

// DisconnectRequest is the parameter for Tunnel.Disconnect.
// If TunnelName is empty, all tunnels are disconnected (backward compat).
type DisconnectRequest struct {
	TunnelName string `json:"tunnel_name,omitempty"`
}

// RenameRequest is the parameter for Tunnel.Rename. Helper-side rename
// closes the connect/disconnect serialization window so a Connect arriving
// between the GUI's "is it active?" check and the file rename can't leave
// the new name in activeCfgs while the file path moved underneath it.
type RenameRequest struct {
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
}

// ActiveTunnelsResponse lists all currently active tunnel names.
type ActiveTunnelsResponse struct {
	Names []string `json:"names"`
}

// BoolResponse wraps a single bool.
type BoolResponse struct {
	Value bool `json:"value"`
}

// StringResponse wraps a single string.
type StringResponse struct {
	Value string `json:"value"`
}

// RequestQuitResponse is returned from Helper.RequestQuit. NotifiedGUI
// distinguishes "the app is shutting down" from "there was no app, just a
// stray helper, and it's now stopping" so `ctl stop` can say which.
type RequestQuitResponse struct {
	NotifiedGUI bool `json:"notified_gui"`
}

// WifiSSIDPayload is broadcast by the helper whenever the system's
// active Wi-Fi SSID changes. The GUI evaluates Settings.WifiRules and
// triggers Connect / Disconnect accordingly.
type WifiSSIDPayload struct {
	OldSSID string `json:"old_ssid"`
	NewSSID string `json:"new_ssid"`
}

// ReportSSIDRequest is sent by the GUI to push the current SSID into the
// helper. On macOS 14+ the helper (a root LaunchDaemon) cannot read SSID
// via CoreWLAN because Location Services permission is tied to the GUI
// bundle. The GUI polls and forwards changes via this method.
type ReportSSIDRequest struct {
	SSID string `json:"ssid"`
}

// AutoConnectPayload is broadcast by the helper after a Wi-Fi rule auto-connects
// a tunnel. The GUI handles this by running the same post-connect refresh
// (refreshTunnels + refreshStatus) as after a manual connect click.
type AutoConnectPayload struct {
	TunnelName string `json:"tunnel_name"`
}

// CriticalErrorPayload describes a permanently-dead helper goroutine.
// Where is the goSafe name (e.g. "eventLoop", "latencyLoop"); Detail is a
// short human-readable summary of the last panic / restart-budget breach.
type CriticalErrorPayload struct {
	Where  string `json:"where"`
	Detail string `json:"detail"`
	// Code is an optional stable identifier ("dns_protection_failing",
	// "helper_unavailable") the GUI maps to a translated message; Detail
	// stays the English fallback. Action optionally names a remedy the GUI
	// can offer ("repair_helper"). Both protocol minor >= 3.
	Code   string `json:"code,omitempty"`
	Action string `json:"action,omitempty"`
}

// SettingsChangedPayload carries a single applied setting so a running
// GUI can reflect a change made through another client (the CLI). Only
// the field for the changed setting is non-nil.
type SettingsChangedPayload struct {
	KillSwitch    *bool   `json:"kill_switch,omitempty"`
	DNSProtection *bool   `json:"dns_protection,omitempty"`
	HealthCheck   *bool   `json:"health_check,omitempty"`
	PinInterface  *bool   `json:"pin_interface,omitempty"`
	LogLevel      *string `json:"log_level,omitempty"`
}

// AutomationPreviewResponse is the read-only result of Automation.Preview:
// the network context the helper currently sees plus each rule-bearing
// tunnel's evaluated decision. No connect/disconnect is performed.
type AutomationPreviewResponse struct {
	SSID        string   `json:"ssid"`
	PhysicalIPs []string `json:"physical_ips"`
	GatewayMAC  string   `json:"gateway_mac"`
	// PrimaryIface is the default-route interface ("" when unknown).
	PrimaryIface  string `json:"primary_iface,omitempty"`
	PrimaryIsWiFi bool   `json:"primary_is_wifi,omitempty"`
	Online        bool   `json:"online"`
	// Settled is true once the network has been stable long enough for
	// negated rules to act; SettleRemainingSec counts down otherwise.
	Settled            bool                       `json:"settled"`
	SettleRemainingSec int                        `json:"settle_remaining_sec,omitempty"`
	Tunnels            []AutomationTunnelDecision `json:"tunnels"`
}

// AutomationTunnelDecision is one tunnel's evaluated desired state.
type AutomationTunnelDecision struct {
	Name      string `json:"name"`
	RuleCount int    `json:"rule_count"`
	// Decision is "connect" | "disconnect" | "unmanaged", or "held" (a
	// negated rule's input is unknown, so the tunnel is left alone) or
	// "latched" (a manual connect/disconnect overrides rules until the
	// network changes).
	Decision string `json:"decision"`
	Active   bool   `json:"active"`
	Held     bool   `json:"held,omitempty"`
	Latched  bool   `json:"latched,omitempty"`
}

// FirewallPermit is one DNS permit the firewall currently allows. Interface
// is "" for "any interface". Tunnel names the tunnel the resolver belongs to
// ("" when unknown).
type FirewallPermit struct {
	Interface string `json:"interface"`
	Server    string `json:"server"`
	Tunnel    string `json:"tunnel,omitempty"`
}

// FirewallStatusResponse is the read-only result of Firewall.Status.
type FirewallStatusResponse struct {
	DNSProtectionWanted bool `json:"dns_protection_wanted"`
	// DNSProtectionActive is read back from pf on macOS (Source "pf") and
	// the helper's cached view elsewhere or when the read-back failed
	// (Source "cached").
	DNSProtectionActive bool             `json:"dns_protection_active"`
	Permits             []FirewallPermit `json:"permits"`
	KillSwitchWanted    bool             `json:"kill_switch_wanted"`
	KillSwitchActive    bool             `json:"kill_switch_active"`
	LastReconcileError  string           `json:"last_reconcile_error,omitempty"`
	// DNSReconcileError is the part of LastReconcileError that came from the
	// DNS protection step (empty when only the kill-switch step failed).
	DNSReconcileError string `json:"dns_reconcile_error,omitempty"`
	LastReconcileAt     string           `json:"last_reconcile_at,omitempty"` // RFC3339
	ReconcileFailures   int              `json:"reconcile_failures,omitempty"`
	Source              string           `json:"source,omitempty"`
	ReadBackError       string           `json:"read_back_error,omitempty"`
}

// ResetDNSRequest is the parameter for Network.ResetDNS.
type ResetDNSRequest struct {
	// Force proceeds even while tunnels are connected, disconnecting them
	// first. Without it the call refuses (Refused in the response).
	Force bool `json:"force,omitempty"`
}

// ResetStep is one line of the ResetDNS report.
type ResetStep struct {
	Name   string `json:"name"` // stable id: tunnels|firewall|kill_switch|split_dns|dns_restore|dns_cache
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// ResetDNSResponse is the result of Network.ResetDNS. Refused is true when a
// tunnel is connected and Force was not set; nothing was changed then.
type ResetDNSResponse struct {
	Refused          bool        `json:"refused,omitempty"`
	ConnectedTunnels []string    `json:"connected_tunnels,omitempty"`
	Steps            []ResetStep `json:"steps,omitempty"`
}

// HelperRecovery summarises what startup crash recovery cleaned up.
type HelperRecovery struct {
	TunnelsRecovered []string `json:"tunnels_recovered,omitempty"`
	DNSRestored      bool     `json:"dns_restored,omitempty"`
	FirewallFlushed  bool     `json:"firewall_flushed,omitempty"`
}

// Any reports whether recovery did anything worth telling the user.
func (r HelperRecovery) Any() bool {
	return r.DNSRestored || r.FirewallFlushed
}

// HelperInfoResponse is the read-only result of Helper.Info.
type HelperInfoResponse struct {
	AppVersion      string `json:"app_version"`
	ProtocolVersion string `json:"protocol_version"`
	PID             int    `json:"pid"`
	StartedAt       string `json:"started_at"` // RFC3339
	// StartMode is "launchd-socket" (launchd started the helper through its
	// socket), "legacy" (the helper listens on its own socket) or "direct".
	StartMode  string `json:"start_mode"`
	SocketPath string `json:"socket_path"`
	// ActivationReason says why the helper started in that mode, e.g.
	// "launchd socket activation" or the reason launchd was not used.
	ActivationReason string          `json:"activation_reason,omitempty"`
	GUIAttached      bool            `json:"gui_attached"`
	Recovery         *HelperRecovery `json:"recovery,omitempty"`
}
