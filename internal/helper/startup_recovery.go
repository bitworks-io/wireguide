package helper

import (
	"log/slog"

	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// rulesProbe is a read-back of the WireGuide firewall rules. known is false
// when the backend cannot read its rules back (Linux, Windows) or the read
// failed.
type rulesProbe struct {
	known, loaded bool
}

// probeFirewallRules reads the loaded WireGuide rules back from the OS
// without changing anything (macOS pf; see firewall.StateReader).
func probeFirewallRules(fw interface{}) rulesProbe {
	r, ok := fw.(firewall.StateReader)
	if !ok {
		return rulesProbe{}
	}
	rb, err := r.ReadBack()
	if err != nil {
		slog.Debug("startup recovery: firewall read-back failed", "error", err)
		return rulesProbe{}
	}
	return rulesProbe{known: true, loaded: rb.RulesLoaded}
}

// startupRecovery turns the crash-recovery results into the Helper.Info
// recovery report, nil when nothing was cleaned up. Firewall rules count as
// flushed only when they were read back as loaded before recovery, a cleanup
// step succeeded, and they are not read back as still loaded afterwards.
func startupRecovery(report tunnel.RecoveryReport, before, after rulesProbe, fwRecovered bool) *ipc.HelperRecovery {
	flushed := before.known && before.loaded &&
		(report.FirewallCleaned || fwRecovered) &&
		!(after.known && after.loaded)
	if len(report.Tunnels) == 0 && len(report.DNSRestored) == 0 && !flushed {
		return nil
	}
	return &ipc.HelperRecovery{
		TunnelsRecovered: report.Tunnels,
		DNSRestored:      report.DNSRestored,
		FirewallFlushed:  flushed,
	}
}
