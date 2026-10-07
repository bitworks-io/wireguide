package app

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/network"
)

// helperRepairer is set by internal/gui at startup (it owns the client
// holder, the event bridge and the data dir) so this Wails-bound package can
// trigger the administrator repair without importing internal/gui.
var helperRepairer atomic.Value // stores func(context.Context) error

// SetHelperRepairer registers the GUI-side helper repair action.
func SetHelperRepairer(f func(context.Context) error) { helperRepairer.Store(f) }

// HelperInfo is the Settings > Advanced "Helper" card. Available is false
// when the helper cannot be asked at all; fields are blank when an older
// helper does not report them (it predates Helper.Info).
type HelperInfo struct {
	Available        bool   `json:"available"`
	AppVersion       string `json:"app_version"`
	ProtocolVersion  string `json:"protocol_version"`
	PID              int    `json:"pid"`
	StartedAt        string `json:"started_at"`
	StartMode        string `json:"start_mode"`
	SocketPath       string `json:"socket_path"`
	ActivationReason string `json:"activation_reason"`
	// Recovery is what the helper's startup crash recovery cleaned up
	// (nil when nothing).
	Recovery *ipc.HelperRecovery `json:"recovery,omitempty"`
}

// GetHelperInfo describes the running helper. Never an error: the card just
// shows what it could learn.
func (s *TunnelService) GetHelperInfo() HelperInfo {
	var info ipc.HelperInfoResponse
	err := s.call(ipc.MethodHelperInfo, nil, &info)
	if err == nil {
		return HelperInfo{
			Available:        true,
			AppVersion:       info.AppVersion,
			ProtocolVersion:  info.ProtocolVersion,
			PID:              info.PID,
			StartedAt:        info.StartedAt,
			StartMode:        info.StartMode,
			SocketPath:       info.SocketPath,
			ActivationReason: info.ActivationReason,
			Recovery:         info.Recovery,
		}
	}
	if !isMethodNotFound(err) {
		return HelperInfo{}
	}
	// Older helper: fall back to what Ping knows.
	var ping ipc.PingResponse
	if perr := s.call(ipc.MethodPing, nil, &ping); perr != nil {
		return HelperInfo{}
	}
	return HelperInfo{Available: true, AppVersion: ping.AppVersion, ProtocolVersion: ping.Version, PID: ping.PID}
}

// FirewallStatus is the read-only DNS protection / kill switch state for the
// Settings sub-lines. Available is false for an older helper or on failure,
// in which case the UI falls back to the wanted setting alone.
type FirewallStatus struct {
	Available bool                        `json:"available"`
	Status    *ipc.FirewallStatusResponse `json:"status,omitempty"`
}

// GetFirewallStatus asks the helper for Firewall.Status. It reads pf on
// macOS, so callers fetch it when Settings opens and on settings changes, not
// on a timer.
func (s *TunnelService) GetFirewallStatus() FirewallStatus {
	var resp ipc.FirewallStatusResponse
	if err := s.call(ipc.MethodFirewallStatus, nil, &resp); err != nil {
		return FirewallStatus{}
	}
	return FirewallStatus{Available: true, Status: &resp}
}

// ResetDNS runs Network.ResetDNS. Without force it is refused (Refused in the
// result, nothing changed) while any tunnel is connected.
func (s *TunnelService) ResetDNS(force bool) (*ipc.ResetDNSResponse, error) {
	var resp ipc.ResetDNSResponse
	// A forced reset disconnects tunnels (seconds each) while the helper
	// answers one request at a time per connection; mark the RPC in flight so
	// the health monitor does not mistake the busy helper for a dead one and
	// swap the client out from under it (same as Connect/Disconnect).
	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()
	if err := s.callLong(ipc.MethodResetDNS, ipc.ResetDNSRequest{Force: force}, &resp); err != nil {
		if isMethodNotFound(err) {
			return nil, errors.New("this helper is too old to reset DNS; use Repair helper first")
		}
		return nil, err
	}
	return &resp, nil
}

// RepairHelper reinstalls the privileged helper through the administrator
// repair path. It is the only action here that prompts for a password, and it
// drops any connected tunnel, so it refuses while one is up.
func (s *TunnelService) RepairHelper() error {
	f, _ := helperRepairer.Load().(func(context.Context) error)
	if f == nil {
		return errors.New("helper repair is not available")
	}
	var active ipc.ActiveTunnelsResponse
	if err := s.call(ipc.MethodActiveTunnels, nil, &active); err == nil && len(active.Names) > 0 {
		return fmt.Errorf("disconnect all tunnels before repairing the helper (connected: %v)", active.Names)
	}
	return f(context.Background())
}

// GetLANOverlaps returns the AllowedIPs ranges of a stored tunnel that the
// macOS connect path will NOT route through the tunnel because they overlap
// the local network (the same rule as DarwinManager.AddRoutes). Empty on other
// platforms, which install every range. Read-only; used by the pre-connect
// "what will change" preview.
func (s *TunnelService) GetLANOverlaps(name string) ([]string, error) {
	if runtime.GOOS != "darwin" {
		return []string{}, nil
	}
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return nil, err
	}
	locals := network.LocalPhysicalAddrs()
	out := []string{}
	for _, p := range cfg.Peers {
		for _, cidr := range p.AllowedIPs {
			if _, hit := network.LocalNetworkOverlapIn(cidr, locals); hit {
				out = append(out, cidr)
			}
		}
	}
	return out, nil
}

// SplitDNSSupported reports whether connecting a config with ~domain DNS
// entries can install split DNS on this platform. Windows never can; elsewhere
// the backend may still fall back at connect time (e.g. Linux without
// systemd-resolved), which the live status then reports as dns_mode "none".
// Used by the pre-connect preview.
func (s *TunnelService) SplitDNSSupported() bool {
	return runtime.GOOS != "windows"
}
