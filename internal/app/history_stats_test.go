package app

import (
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func newHistoryTestService(t *testing.T) *TunnelService {
	t.Helper()
	hs := storage.NewHistoryStore(t.TempDir())
	return &TunnelService{historyStore: hs, clients: ipc.NewClientHolder(nil), userActions: NewUserActions()}
}

func lastSession(t *testing.T, s *TunnelService) storage.Session {
	t.Helper()
	all := s.historyStore.GetAll()
	if len(all) == 0 {
		t.Fatal("no sessions recorded")
	}
	return all[0]
}

func rxtx(name string, rx, tx int64) (map[string]int64, map[string]int64) {
	return map[string]int64{name: rx}, map[string]int64{name: tx}
}

// Regression: the helper lists a tunnel as active while it is Disconnecting
// (or Connecting during a reconnect) but reports 0/0 counters for it. The
// zero reading used to overwrite the cache, so the session closed on the next
// tick recorded 0 B rx/tx (49 of 76 sessions in the field).
func TestReconcileKeepsCountersAcrossZeroedTeardownTick(t *testing.T) {
	for _, reason := range []string{"user", "reconnect", "app_quit"} {
		t.Run(reason, func(t *testing.T) {
			s := newHistoryTestService(t)
			rx, tx := rxtx("a", 1000, 500)
			s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
			time.Sleep(1100 * time.Millisecond) // non-zero duration
			rx, tx = rxtx("a", 5000, 2500)
			s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
			if reason == "user" {
				s.markUserDisconnect("a", 0, 0)
			}
			// Teardown tick: still active, counters zeroed.
			rx, tx = rxtx("a", 0, 0)
			s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
			// Gone.
			disappear := reason
			if reason == "user" {
				disappear = ""
			}
			s.ReconcileHistoryFromStatus(nil, nil, nil, disappear)
			got := lastSession(t, s)
			if got.RxBytes != 5000 || got.TxBytes != 2500 {
				t.Errorf("rx/tx = %d/%d, want 5000/2500", got.RxBytes, got.TxBytes)
			}
		})
	}
}

// A reconnect rebuilds the WireGuard device, so its counters restart low; the
// session total must keep counting from where it was.
func TestReconcileAccumulatesAcrossCounterReset(t *testing.T) {
	s := newHistoryTestService(t)
	rx, tx := rxtx("a", 1000, 400)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	time.Sleep(1100 * time.Millisecond)
	rx, tx = rxtx("a", 0, 0)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	rx, tx = rxtx("a", 50, 20)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "reconnect")
	got := lastSession(t, s)
	if got.RxBytes != 1050 || got.TxBytes != 420 {
		t.Errorf("rx/tx = %d/%d, want 1050/420", got.RxBytes, got.TxBytes)
	}
}

// CloseHistorySessions at app quit: the helper is unreachable (zero reading),
// the cache must supply the counters.
func TestCloseHistorySessionsUsesCachedCountersWhenHelperGone(t *testing.T) {
	s := newHistoryTestService(t)
	rx, tx := rxtx("a", 7000, 3000)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	time.Sleep(1100 * time.Millisecond)
	rx, tx = rxtx("a", 0, 0) // teardown tick before quit
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.CloseHistorySessions("app_quit")
	got := lastSession(t, s)
	if got.RxBytes != 7000 || got.TxBytes != 3000 || got.DisconnectReason != "app_quit" {
		t.Errorf("got %+v", got)
	}
}
