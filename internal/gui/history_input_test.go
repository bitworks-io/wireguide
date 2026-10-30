package gui

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

// Single tunnel: no Tunnels list, so the start reason comes from the
// primary; a tunnel that just went down reports its end reason top-level.
func TestHistoryInput_SingleTunnel(t *testing.T) {
	in := historyInput(domain.ConnectionStatus{
		TunnelName:       "home-vpn",
		RxBytes:          10,
		TxBytes:          20,
		LastChangeReason: domain.ChangeReasonAutomation,
		ActiveTunnels:    []string{"home-vpn"},
		RecentDisconnects: map[string]domain.TunnelChange{
			"office-vpn": {Reason: domain.ChangeReasonUser, At: "2026-01-02T10:00:00Z"},
			"empty":      {},
		},
	})
	if in.rx["home-vpn"] != 10 || in.tx["home-vpn"] != 20 {
		t.Fatalf("counters = %v %v", in.rx, in.tx)
	}
	if in.startReasons["home-vpn"] != domain.ChangeReasonAutomation {
		t.Fatalf("start reasons = %v", in.startReasons)
	}
	if len(in.endReasons) != 1 || in.endReasons["office-vpn"] != domain.ChangeReasonUser {
		t.Fatalf("end reasons = %v", in.endReasons)
	}
}

func TestHistoryInput_MultiTunnelAndOldHelper(t *testing.T) {
	in := historyInput(domain.ConnectionStatus{
		TunnelName: "a",
		Tunnels: []domain.ConnectionStatus{
			{TunnelName: "a", LastChangeReason: domain.ChangeReasonUser},
			{TunnelName: "b", LastChangeReason: domain.ChangeReasonWake},
		},
	})
	if in.startReasons["a"] != domain.ChangeReasonUser || in.startReasons["b"] != domain.ChangeReasonWake {
		t.Fatalf("start reasons = %v", in.startReasons)
	}
	old := historyInput(domain.ConnectionStatus{TunnelName: "a"})
	if old.startReasons != nil || old.endReasons != nil {
		t.Fatal("an older helper's status must yield nil reason maps")
	}
}

func TestCurrentSSIDCache(t *testing.T) {
	t.Cleanup(func() { setCurrentSSID("") })
	setCurrentSSID("CafeWiFi")
	if got := getCurrentSSID(); got != "CafeWiFi" {
		t.Fatalf("ssid = %q", got)
	}
}
