package app

import (
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
)

// A forced reset from the window disconnects tunnels at the user's request;
// it must count as a user action so the notifier stays quiet. A plain reset
// disconnects nothing and records nothing.
func TestResetDNSForceRecordsUserDisconnect(t *testing.T) {
	s := &TunnelService{clients: ipc.NewClientHolder(nil), userActions: NewUserActions()}

	_, _ = s.ResetDNS(false) // helper unavailable; only the bookkeeping matters
	if s.userActions.Recent("home-vpn", false, time.Now()) {
		t.Fatal("a non-forced reset must not be recorded as a user disconnect")
	}

	_, _ = s.ResetDNS(true)
	if !s.userActions.Recent("home-vpn", false, time.Now()) {
		t.Fatal("a forced reset must be recorded as a user disconnect of every tunnel")
	}
	if s.userActions.Recent("home-vpn", true, time.Now()) {
		t.Fatal("a forced reset is not a connect")
	}
}
