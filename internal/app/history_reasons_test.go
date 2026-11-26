package app

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

// reconcileWithReasons runs one status reconcile carrying the helper's
// start/end reasons and the GUI's SSID.
func reconcileWithReasons(s *TunnelService, active []string, rx, tx map[string]int64, start, end map[string]string, ssid string) {
	samples := make(map[string]counterSample, len(active))
	for _, name := range active {
		samples[name] = counterSample{name: name, rx: rx[name], tx: tx[name]}
	}
	s.reconcileHistoryFromStatus(active, samples, "", historyReasons{start: start, end: end, ssid: ssid})
}

// A session opened by a status event records the helper's start reason and
// the GUI's SSID; its close uses the helper's recent_disconnects reason.
func TestReconcileRecordsStartReasonSSIDAndHelperEndReason(t *testing.T) {
	s := newHistoryTestService(t)
	rx, tx := rxtx("a", 100, 50)
	reconcileWithReasons(s, []string{"a"}, rx, tx, map[string]string{"a": "automation"}, nil, "HomeWiFi")
	open := lastSession(t, s)
	if open.StartReason != "automation" || open.SSID != "HomeWiFi" {
		t.Fatalf("open session start_reason=%q ssid=%q", open.StartReason, open.SSID)
	}
	// Later ticks with another reason / SSID don't rewrite an open session.
	reconcileWithReasons(s, []string{"a"}, rx, tx, map[string]string{"a": "wake"}, nil, "CafeWiFi")
	reconcileWithReasons(s, nil, nil, nil, nil, map[string]string{"a": "watchdog"}, "CafeWiFi")
	closed := lastSession(t, s)
	if closed.StartReason != "automation" || closed.SSID != "HomeWiFi" {
		t.Fatalf("closed session start_reason=%q ssid=%q", closed.StartReason, closed.SSID)
	}
	if closed.DisconnectReason != "watchdog" {
		t.Fatalf("end reason = %q, want watchdog", closed.DisconnectReason)
	}
}

// The helper's end reason beats the GUI's "user" hint; without one the hint
// still applies, and without either the default "reconnect" does. The hint
// must survive the 0/0 and counter-reset ticks merge() folds in.
func TestReconcileEndReasonPriority(t *testing.T) {
	cases := []struct {
		name       string
		userHint   bool
		endReasons map[string]string
		want       string
	}{
		{"helper wins over hint", true, map[string]string{"a": "automation"}, "automation"},
		{"hint without helper reason", true, nil, "user"},
		{"other tunnel's reason ignored", true, map[string]string{"b": "automation"}, "user"},
		{"default", false, nil, "reconnect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newHistoryTestService(t)
			rx, tx := rxtx("a", 1000, 500)
			reconcileWithReasons(s, []string{"a"}, rx, tx, nil, nil, "")
			if tc.userHint {
				s.markUserDisconnect("a", 0, 0)
			}
			zrx, ztx := rxtx("a", 0, 0)
			reconcileWithReasons(s, []string{"a"}, zrx, ztx, nil, nil, "") // teardown 0/0 tick
			rrx, rtx := rxtx("a", 10, 5)
			reconcileWithReasons(s, []string{"a"}, rrx, rtx, nil, nil, "") // counter reset tick
			reconcileWithReasons(s, nil, nil, nil, nil, tc.endReasons, "")
			got := lastSession(t, s)
			if got.DisconnectReason != tc.want {
				t.Fatalf("end reason = %q, want %q", got.DisconnectReason, tc.want)
			}
			if got.RxBytes != 1010 || got.TxBytes != 505 {
				t.Fatalf("rx/tx = %d/%d, want 1010/505", got.RxBytes, got.TxBytes)
			}
		})
	}
}

func TestMergeCarriesReasonHint(t *testing.T) {
	st := lastKnownTunnelStats{reason: "user"}
	st = st.merge(100, 50)
	st = st.merge(0, 0)
	st = st.merge(5, 5)
	if st.reason != "user" {
		t.Fatalf("reason = %q after merges, want user", st.reason)
	}
}

// Single tunnel: no Tunnels list, so the start reason comes from the
// primary; a tunnel that just went down reports its end reason top-level.
func TestReasonsFromStatus_SingleTunnel(t *testing.T) {
	r := reasonsFromStatus(ConnectionStatus{
		TunnelName:       "home-vpn",
		LastChangeReason: domain.ChangeReasonAutomation,
		ActiveTunnels:    []string{"home-vpn"},
		RecentDisconnects: map[string]domain.TunnelChange{
			"office-vpn": {Reason: domain.ChangeReasonUser, At: "2026-01-02T10:00:00Z"},
			"empty":      {},
		},
	}, "HomeWiFi")
	if r.start["home-vpn"] != domain.ChangeReasonAutomation || r.ssid != "HomeWiFi" {
		t.Fatalf("start reasons = %v ssid = %q", r.start, r.ssid)
	}
	if len(r.end) != 1 || r.end["office-vpn"] != domain.ChangeReasonUser {
		t.Fatalf("end reasons = %v", r.end)
	}
}

func TestReasonsFromStatus_MultiTunnelAndOldHelper(t *testing.T) {
	r := reasonsFromStatus(ConnectionStatus{
		TunnelName: "a",
		Tunnels: []domain.ConnectionStatus{
			{TunnelName: "a", LastChangeReason: domain.ChangeReasonUser},
			{TunnelName: "b", LastChangeReason: domain.ChangeReasonWake},
		},
	}, "")
	if r.start["a"] != domain.ChangeReasonUser || r.start["b"] != domain.ChangeReasonWake {
		t.Fatalf("start reasons = %v", r.start)
	}
	old := reasonsFromStatus(ConnectionStatus{TunnelName: "a"}, "")
	if old.start != nil || old.end != nil {
		t.Fatal("an older helper's status must yield nil reason maps")
	}
}
