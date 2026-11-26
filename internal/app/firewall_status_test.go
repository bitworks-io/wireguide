package app

import "testing"

// Without a helper the status is "unknown" (unavailable), never a status
// that reads as "not applied".
func TestGetFirewallStatusWithoutHelperIsUnknown(t *testing.T) {
	got := (&TunnelService{}).GetFirewallStatus()
	if got.Available || got.Status != nil {
		t.Fatalf("status = %+v", got)
	}
}
