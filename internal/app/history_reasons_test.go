package app

import (
	"testing"
	"time"
)

// Start reason + SSID come from the helper's last_change_reason and the
// GUI's SSID; a rule-driven disconnect closes as "automation" instead of the
// old default "reconnect".
func TestReconcileHistoryRecordsReasonsAndSSID(t *testing.T) {
	s := newHistoryTestService(t)
	rx, tx := rxtx("a", 100, 50)
	s.ReconcileHistory(HistoryReconcile{Active: []string{"a"}, Rx: rx, Tx: tx,
		StartReasons: map[string]string{"a": "automation"}, SSID: "Cafe"})
	time.Sleep(1100 * time.Millisecond)
	s.ReconcileHistory(HistoryReconcile{EndReasons: map[string]string{"a": "automation"}, SSID: "Home"})
	got := lastSession(t, s)
	if got.StartReason != "automation" || got.SSID != "Cafe" || got.DisconnectReason != "automation" {
		t.Fatalf("session %+v", got)
	}
}

// Without helper reasons (older helper) the defaults are unchanged.
func TestReconcileHistoryDefaultsWithoutReasons(t *testing.T) {
	s := newHistoryTestService(t)
	rx, tx := rxtx("a", 100, 50)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	time.Sleep(1100 * time.Millisecond)
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	got := lastSession(t, s)
	if got.StartReason != "" || got.SSID != "" || got.DisconnectReason != "reconnect" {
		t.Fatalf("session %+v", got)
	}
}

// The GUI's own "user" hint still wins over the helper's end reason, and the
// helper's reason wins over the default.
func TestReconcileHistoryEndReasonPrecedence(t *testing.T) {
	s := newHistoryTestService(t)
	rx, tx := rxtx("a", 100, 50)
	s.ReconcileHistory(HistoryReconcile{Active: []string{"a"}, Rx: rx, Tx: tx})
	time.Sleep(1100 * time.Millisecond)
	s.markUserDisconnect("a", 0, 0)
	s.ReconcileHistory(HistoryReconcile{EndReasons: map[string]string{"a": "health_check"}})
	if got := lastSession(t, s); got.DisconnectReason != "user" {
		t.Fatalf("user hint must win: %+v", got)
	}

	s2 := newHistoryTestService(t)
	s2.ReconcileHistory(HistoryReconcile{Active: []string{"b"}, Rx: map[string]int64{"b": 1}, Tx: map[string]int64{"b": 1},
		StartReasons: map[string]string{"b": "wake"}})
	time.Sleep(1100 * time.Millisecond)
	s2.ReconcileHistory(HistoryReconcile{EndReasons: map[string]string{"b": "user"}})
	if got := lastSession(t, s2); got.DisconnectReason != "user" || got.StartReason != "wake" {
		t.Fatalf("helper end reason must apply: %+v", got)
	}
}
