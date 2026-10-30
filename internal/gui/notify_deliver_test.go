package gui

import (
	"errors"
	"sync"
	"testing"
)

type fakeBackend struct {
	mu       sync.Mutex
	startErr error
	granted  bool
	authErr  error
	sendErr  error
	sent     int
	asked    int
}

func (f *fakeBackend) start() error { return f.startErr }

func (f *fakeBackend) requestAuth() (bool, error) {
	f.mu.Lock()
	f.asked++
	f.mu.Unlock()
	return f.granted, f.authErr
}

func (f *fakeBackend) send(string, string, string) error {
	f.mu.Lock()
	f.sent++
	f.mu.Unlock()
	return f.sendErr
}

func deliverNotifier(b *fakeBackend) (*notifier, *int) {
	fallbacks := new(int)
	n := newNotifier(nil, nil)
	n.newBackend = func() notificationBackend { return b }
	n.fallback = func(string, string) error { *fallbacks++; return nil }
	return n, fallbacks
}

// The user said no (or turned WireGuide's notifications off): nothing is
// posted, through the service or around it, for the rest of the session.
func TestDeliverDeniedDropsWithoutFallback(t *testing.T) {
	b := &fakeBackend{granted: false}
	n, fallbacks := deliverNotifier(b)
	n.deliver("WireGuide", "one")
	n.deliver("WireGuide", "two")
	if *fallbacks != 0 {
		t.Fatalf("denied authorization must not fall back, fallbacks=%d", *fallbacks)
	}
	if b.sent != 0 {
		t.Fatalf("denied authorization must not send, sent=%d", b.sent)
	}
	if b.asked != 1 {
		t.Fatalf("authorization must be asked once, asked=%d", b.asked)
	}
}

func TestDeliverGrantedUsesService(t *testing.T) {
	b := &fakeBackend{granted: true}
	n, fallbacks := deliverNotifier(b)
	n.deliver("WireGuide", "one")
	n.deliver("WireGuide", "two")
	if b.sent != 2 || *fallbacks != 0 || b.asked != 1 {
		t.Fatalf("sent=%d fallbacks=%d asked=%d", b.sent, *fallbacks, b.asked)
	}
}

// A service that fails (cannot start, authorization or delivery errors)
// falls back.
func TestDeliverServiceFailureFallsBack(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]*fakeBackend{
		"start": {startErr: boom},
		"auth":  {authErr: boom},
		"send":  {granted: true, sendErr: boom},
	}
	for name, b := range cases {
		n, fallbacks := deliverNotifier(b)
		n.deliver("WireGuide", "one")
		if *fallbacks != 1 {
			t.Errorf("%s error: want 1 fallback, got %d", name, *fallbacks)
		}
	}
}

// Notifications arriving while the authorization prompt is open are
// dropped rather than posted around it.
func TestDeliverDuringPendingAuthDrops(t *testing.T) {
	b := &fakeBackend{granted: true}
	n, fallbacks := deliverNotifier(b)
	n.svcStarted, n.svcUsable, n.svc, n.authPending = true, true, b, true
	if got := n.sendViaService("WireGuide", "one"); got != serviceDrop {
		t.Fatalf("pending authorization: got %v, want serviceDrop", got)
	}
	n.deliver("WireGuide", "two")
	if *fallbacks != 0 || b.sent != 0 {
		t.Fatalf("fallbacks=%d sent=%d", *fallbacks, b.sent)
	}
}
