package helper

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/wifi"
)

const reasonTestConf = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.250.250.2/32

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.250.250.0/24
`

func reasonTestConfig(t *testing.T, name string) *domain.WireGuardConfig {
	t.Helper()
	cfg, err := config.Parse(reasonTestConf)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Name = name
	return cfg
}

// reasonProbe installs a fake tunnel connect that records the connect
// reason visible while the connect is in flight.
func reasonProbe(t *testing.T, h *Helper) *[]string {
	t.Helper()
	seen := &[]string{}
	h.tunnelConnectFn = func(_ context.Context, cfg *domain.WireGuardConfig) error {
		conn, _ := h.changeSnapshot(map[string]bool{cfg.Name: true})
		*seen = append(*seen, conn[cfg.Name].Reason)
		return nil
	}
	return seen
}

func assertConnectReason(t *testing.T, h *Helper, name string, inFlight []string, want string) {
	t.Helper()
	if len(inFlight) == 0 || inFlight[len(inFlight)-1] != want {
		t.Fatalf("%s: in-flight connect reason = %v, want %q", name, inFlight, want)
	}
	conn, ended := h.changeSnapshot(map[string]bool{name: true})
	if conn[name].Reason != want {
		t.Fatalf("%s: committed connect reason = %+v, want %q", name, conn[name], want)
	}
	if _, ok := ended[name]; ok {
		t.Fatalf("%s: connected tunnel must not report an end reason: %v", name, ended)
	}
}

func TestChangeReason_HandleConnectIsUser(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "Cafe")
	seen := reasonProbe(t, h)
	h.beginDisconnectReason("vpn", domain.ChangeReasonAutomation)
	params, _ := json.Marshal(ipc.ConnectRequest{Config: reasonTestConfig(t, "vpn")})
	if _, err := h.handleConnect(params); err != nil {
		t.Fatal(err)
	}
	assertConnectReason(t, h, "vpn", *seen, domain.ChangeReasonUser)
}

func TestChangeReason_AutomationConnectIsAutomation(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "Cafe")
	seen := reasonProbe(t, h)
	h.userTunnelStore = storage.NewTunnelStore(t.TempDir())
	if err := h.userTunnelStore.Save(reasonTestConfig(t, "vpn")); err != nil {
		t.Fatal(err)
	}
	rules := []wifi.Rule{{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Cafe"}, Do: wifi.ActionConnect}}
	ev := h.automationConnect("vpn", "test", h.currentNetworkState().ctx, rules, 0)
	if ev == nil || ev.Action != ipc.AutomationActionConnect || ev.Error != "" {
		t.Fatalf("unexpected automation event %+v", ev)
	}
	assertConnectReason(t, h, "vpn", *seen, domain.ChangeReasonAutomation)
}

func TestChangeReason_ReconnectFnUsesTriggerKind(t *testing.T) {
	cases := map[reconnect.Trigger]string{
		reconnect.TriggerWake:          domain.ChangeReasonWake,
		reconnect.TriggerNetworkChange: domain.ChangeReasonNetworkChange,
		reconnect.TriggerHealthCheck:   domain.ChangeReasonHealthCheck,
		"":                             domain.ChangeReasonReconnect,
	}
	for trig, want := range cases {
		h := newWiringHelper(t, &fakeFW{})
		seen := reasonProbe(t, h)
		h.activeCfgs["vpn"] = reasonTestConfig(t, "vpn")
		ctx := reconnect.WithTrigger(context.Background(), trig)
		if err := h.reconnectFn(ctx, "vpn"); err != nil {
			t.Fatalf("trigger %q: %v", trig, err)
		}
		assertConnectReason(t, h, "vpn", *seen, want)
	}
}

// A connect that fails shortly after a disconnect must not close the new
// (failed) history session with the earlier disconnect's end reason.
func TestChangeReason_FailedConnectDropsStaleEndReason(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "Cafe")
	h.beginDisconnectReason("vpn", domain.ChangeReasonUser)
	var inFlightEnded map[string]domain.TunnelChange
	h.tunnelConnectFn = func(_ context.Context, cfg *domain.WireGuardConfig) error {
		_, inFlightEnded = h.changeSnapshot(nil)
		return context.DeadlineExceeded
	}
	params, _ := json.Marshal(ipc.ConnectRequest{Config: reasonTestConfig(t, "vpn")})
	if _, err := h.handleConnect(params); err == nil {
		t.Fatal("expected connect failure")
	}
	if _, ok := inFlightEnded["vpn"]; ok {
		t.Fatalf("end reason visible during the new attempt: %v", inFlightEnded)
	}
	if _, ended := h.changeSnapshot(nil); len(ended) != 0 {
		t.Fatalf("failed connect resurrected the earlier end reason: %v", ended)
	}
}
