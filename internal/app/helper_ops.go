package app

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
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
	GUIAttached      bool   `json:"gui_attached"`
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
			GUIAttached:      info.GUIAttached,
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
	return HelperInfo{
		Available:       true,
		AppVersion:      ping.AppVersion,
		ProtocolVersion: ping.Version,
		PID:             ping.PID,
		GUIAttached:     ping.GUIKnown() && ping.GUIAttached,
	}
}

// RepairHelper reinstalls the privileged helper through the administrator
// repair path. It is the only action here that prompts for a password (after
// WireGuide's own explanation), and it drops any connected tunnel, so the GUI
// side refuses while a tunnel is connected, wanted or pending restore.
func (s *TunnelService) RepairHelper() error {
	f, _ := helperRepairer.Load().(func(context.Context) error)
	if f == nil {
		return errors.New("helper repair is not available")
	}
	return f(context.Background())
}

// errResetDNSTooOld is returned when the helper predates Network.ResetDNS.
var errResetDNSTooOld = errors.New("the helper is too old to reset DNS — update the app (or use Repair helper)")

// ResetDNS runs Network.ResetDNS ("Reset DNS & firewall"). A refused request
// comes back with Refused set and nothing changed. force disconnects every
// connected, wanted or pending-restore tunnel first; killSwitchOff turns the
// kill switch setting off, which is also saved here so the next launch does
// not push it back on.
func (s *TunnelService) ResetDNS(force, killSwitchOff bool) (*ipc.ResetDNSResponse, error) {
	var resp ipc.ResetDNSResponse
	// A forced reset can tear tunnels down (seconds each): mark the RPC in
	// flight so the health monitor does not take the busy helper for dead.
	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()
	if err := s.callLong(ipc.MethodResetDNS, ipc.ResetDNSRequest{Force: force, KillSwitchOff: killSwitchOff}, &resp); err != nil {
		if isMethodNotFound(err) {
			return nil, errResetDNSTooOld
		}
		return nil, err
	}
	if resetTurnedKillSwitchOff(resp) && s.settingsStore != nil {
		if err := s.settingsStore.Update(func(st *storage.Settings) error { st.KillSwitch = false; return nil }); err != nil {
			slog.Warn("reset DNS: could not save kill switch off", "error", err)
		}
	}
	return &resp, nil
}

// resetTurnedKillSwitchOff reports whether the helper turned the kill switch
// setting off (it persists the intent even when applying it failed).
func resetTurnedKillSwitchOff(resp ipc.ResetDNSResponse) bool {
	if resp.Refused {
		return false
	}
	for _, st := range resp.Steps {
		if st.Name == "kill_switch" {
			return true
		}
	}
	return false
}
