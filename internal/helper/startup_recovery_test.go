package helper

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

func TestStartupRecoveryReport(t *testing.T) {
	loaded := rulesProbe{known: true, loaded: true}
	empty := rulesProbe{known: true}
	unknown := rulesProbe{}
	tunnels := tunnel.RecoveryReport{Tunnels: []string{"home-vpn"}, DNSRestored: []string{"home-vpn"}, FirewallCleaned: true}

	if r := startupRecovery(tunnel.RecoveryReport{}, empty, empty, true); r != nil {
		t.Fatalf("clean start must report nothing, got %+v", r)
	}
	// macOS flushes the anchors on every start: that alone is not a recovery
	// unless rules were actually loaded before.
	if r := startupRecovery(tunnel.RecoveryReport{}, loaded, empty, true); r == nil || !r.FirewallFlushed || r.TunnelsRecovered != nil {
		t.Fatalf("stale rules flushed: %+v", r)
	}
	if r := startupRecovery(tunnels, unknown, unknown, true); r == nil || r.FirewallFlushed ||
		len(r.TunnelsRecovered) != 1 || len(r.DNSRestored) != 1 {
		t.Fatalf("no read-back (Linux/Windows) must not claim a flush: %+v", r)
	}
	if r := startupRecovery(tunnel.RecoveryReport{}, loaded, loaded, true); r != nil {
		t.Fatalf("rules still loaded after recovery are not flushed: %+v", r)
	}
	if r := startupRecovery(tunnel.RecoveryReport{}, loaded, empty, false); r != nil {
		t.Fatalf("no successful cleanup step, no flush: %+v", r)
	}
	if r := startupRecovery(tunnels, loaded, unknown, false); r == nil || !r.FirewallFlushed {
		t.Fatalf("journal cleanup flushed loaded rules: %+v", r)
	}
}

type fakeStateReader struct{ loaded bool }

func (f fakeStateReader) ReadBack() (firewall.Readback, error) {
	return firewall.Readback{RulesLoaded: f.loaded}, nil
}

func TestProbeFirewallRules(t *testing.T) {
	if p := probeFirewallRules(struct{}{}); p.known {
		t.Fatal("a backend without read-back must be unknown")
	}
	if p := probeFirewallRules(fakeStateReader{loaded: true}); !p.known || !p.loaded {
		t.Fatalf("probe = %+v", p)
	}
}
