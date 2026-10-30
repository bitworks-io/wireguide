//go:build !windows

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func serviceWithHelper(t *testing.T, handlers map[string]func(json.RawMessage) (interface{}, error)) *TunnelService {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wgh-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "s")
	l, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(l)
	// NewClient pings on connect; a test that does not care answers it.
	if _, ok := handlers[ipc.MethodPing]; !ok {
		server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
			return ipc.PingResponse{Version: ipc.ProtocolVersion}, nil
		})
	}
	for m, h := range handlers {
		server.Handle(m, h)
	}
	go server.Serve()
	t.Cleanup(server.Shutdown)
	client, err := ipc.NewClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return &TunnelService{clients: ipc.NewClientHolder(client)}
}

func TestGetHelperInfoUsesHelperInfo(t *testing.T) {
	s := serviceWithHelper(t, map[string]func(json.RawMessage) (interface{}, error){
		ipc.MethodHelperInfo: func(json.RawMessage) (interface{}, error) {
			return ipc.HelperInfoResponse{AppVersion: "1.2.3", ProtocolVersion: "1.9", PID: 42,
				StartedAt: "2026-01-02T03:04:05Z", StartMode: "launchd-socket", SocketPath: "/x", GUIAttached: true}, nil
		},
	})
	got := s.GetHelperInfo()
	if !got.Available || got.AppVersion != "1.2.3" || got.PID != 42 || got.StartMode != "launchd-socket" || !got.GUIAttached || got.SocketPath != "/x" {
		t.Fatalf("info = %+v", got)
	}
}

// An older helper answers method-not-found for Helper.Info; the card falls
// back to what Ping knows and never claims GUI state a pre-minor-2 helper
// does not report.
func TestGetHelperInfoFallsBackToPing(t *testing.T) {
	s := serviceWithHelper(t, map[string]func(json.RawMessage) (interface{}, error){
		ipc.MethodPing: func(json.RawMessage) (interface{}, error) {
			return ipc.PingResponse{Version: "1.5", AppVersion: "0.6.0", PID: 7, GUIAttached: true}, nil
		},
	})
	got := s.GetHelperInfo()
	if !got.Available || got.AppVersion != "0.6.0" || got.PID != 7 || got.StartMode != "" || !got.GUIAttached {
		t.Fatalf("fallback info = %+v", got)
	}
	s = serviceWithHelper(t, map[string]func(json.RawMessage) (interface{}, error){
		ipc.MethodPing: func(json.RawMessage) (interface{}, error) {
			return ipc.PingResponse{Version: "1", AppVersion: "0.1.0", PID: 7, GUIAttached: true}, nil
		},
	})
	if s.GetHelperInfo().GUIAttached {
		t.Fatal("GUIAttached reported by a helper that predates it")
	}
}

func TestGetHelperInfoUnavailable(t *testing.T) {
	s := &TunnelService{}
	if s.GetHelperInfo().Available {
		t.Fatal("Available with no helper client")
	}
}

func TestRepairHelperDelegatesAndErrorsWhenUnregistered(t *testing.T) {
	prev, _ := helperRepairer.Load().(func(context.Context) error)
	t.Cleanup(func() {
		if prev != nil {
			helperRepairer.Store(prev)
		}
	})
	s := &TunnelService{}
	called := false
	want := errors.New("busy")
	helperRepairer.Store(func(context.Context) error { called = true; return want })
	if err := s.RepairHelper(); !called || !errors.Is(err, want) {
		t.Fatalf("RepairHelper = %v, called=%v", err, called)
	}
}

func TestResetDNSPassesFlagsAndSavesKillSwitchOff(t *testing.T) {
	var got ipc.ResetDNSRequest
	s := serviceWithHelper(t, map[string]func(json.RawMessage) (interface{}, error){
		ipc.MethodResetDNS: func(raw json.RawMessage) (interface{}, error) {
			_ = json.Unmarshal(raw, &got)
			return ipc.ResetDNSResponse{Steps: []ipc.ResetDNSStep{{Name: "kill_switch", OK: true}, {Name: "firewall", OK: true}}}, nil
		},
	})
	s.settingsStore = storage.NewSettingsStore(t.TempDir())
	if err := s.settingsStore.Update(func(st *storage.Settings) error { st.KillSwitch = true; return nil }); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ResetDNS(true, true)
	if err != nil || resp == nil || len(resp.Steps) != 2 {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	if !got.Force || !got.KillSwitchOff {
		t.Fatalf("request = %+v", got)
	}
	if st, _ := s.settingsStore.Load(); st.KillSwitch {
		t.Fatal("kill switch off was not saved to settings")
	}
}

func TestResetDNSRefusedKeepsKillSwitchSetting(t *testing.T) {
	s := serviceWithHelper(t, map[string]func(json.RawMessage) (interface{}, error){
		ipc.MethodResetDNS: func(json.RawMessage) (interface{}, error) {
			return ipc.ResetDNSResponse{Refused: true, Reason: ipc.ResetRefusedTunnels, ConnectedTunnels: []string{"home-vpn"}}, nil
		},
	})
	s.settingsStore = storage.NewSettingsStore(t.TempDir())
	_ = s.settingsStore.Update(func(st *storage.Settings) error { st.KillSwitch = true; return nil })
	resp, err := s.ResetDNS(false, true)
	if err != nil || !resp.Refused {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	if st, _ := s.settingsStore.Load(); !st.KillSwitch {
		t.Fatal("a refused reset changed the saved kill switch setting")
	}
}

func TestResetDNSOldHelper(t *testing.T) {
	s := serviceWithHelper(t, nil)
	if _, err := s.ResetDNS(false, false); !errors.Is(err, errResetDNSTooOld) {
		t.Fatalf("err = %v, want too-old", err)
	}
}

// A forced reset disconnects tunnels for the user: it must count as a user
// disconnect while in flight and for the status lag afterwards, so the
// notifier does not announce "disconnected outside the app".
func TestResetDNSRecordsUserDisconnect(t *testing.T) {
	var during atomic.Bool
	var s *TunnelService
	s = serviceWithHelper(t, map[string]func(json.RawMessage) (interface{}, error){
		ipc.MethodResetDNS: func(json.RawMessage) (interface{}, error) {
			during.Store(s.userActions.Recent("home-vpn", false, time.Now()))
			return nil, errors.New("reset failed")
		},
	})
	s.userActions = NewUserActions()
	if _, err := s.ResetDNS(true, false); err == nil {
		t.Fatal("expected the helper's failure")
	}
	if !during.Load() {
		t.Error("reset was not recorded as a user disconnect while in flight")
	}
	if !s.userActions.Recent("home-vpn", false, time.Now()) {
		t.Error("reset must keep covering the status lag afterwards")
	}
}
