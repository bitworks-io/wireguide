package wifi

import (
	"testing"
	"time"
)

func TestSettleTracker(t *testing.T) {
	now := time.Unix(1000, 0)
	tr := NewSettleTracker(func() time.Time { return now })

	if ok, rem := tr.Observe("a"); ok || rem != NegationSettleWindow {
		t.Fatalf("first observe: settled=%v rem=%v", ok, rem)
	}
	now = now.Add(10 * time.Second)
	if ok, rem := tr.Observe("a"); ok || rem != 5*time.Second {
		t.Fatalf("after 10s: settled=%v rem=%v", ok, rem)
	}
	// A change resets the window.
	if ok, rem := tr.Observe("b"); ok || rem != NegationSettleWindow {
		t.Fatalf("after change: settled=%v rem=%v", ok, rem)
	}
	now = now.Add(NegationSettleWindow)
	if ok, rem := tr.Observe("b"); !ok || rem != 0 {
		t.Fatalf("after window: settled=%v rem=%v", ok, rem)
	}
	// Going back to a previous value is still a change.
	if ok, _ := tr.Observe("a"); ok {
		t.Fatal("revert to old fingerprint must reset the window")
	}
}

func TestNetworkFingerprint(t *testing.T) {
	a := NetworkFingerprint("Net ", "en0", "B0:38:6C:54:8B:AB", []string{"10.0.0.0/24", "192.168.1.0/24"})
	b := NetworkFingerprint("Net", "en0", "b0-38-6c-54-8b-ab", []string{"192.168.1.0/24", "10.0.0.0/24"})
	if a != b {
		t.Fatalf("expected equal fingerprints:\n%q\n%q", a, b)
	}
	if a == NetworkFingerprint("Net", "en1", "b0:38:6c:54:8b:ab", []string{"10.0.0.0/24", "192.168.1.0/24"}) {
		t.Fatal("interface change must alter fingerprint")
	}
	if a == NetworkFingerprint("Other", "en0", "b0:38:6c:54:8b:ab", []string{"10.0.0.0/24", "192.168.1.0/24"}) {
		t.Fatal("SSID change must alter fingerprint")
	}
}
