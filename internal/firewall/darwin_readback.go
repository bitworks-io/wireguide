//go:build darwin

package firewall

import "fmt"

// ReadBack reads both WireGuide anchors back from pf (read-only pfctl
// queries) so the reported state is what the kernel will enforce, not the
// helper's own bookkeeping. It takes no lock: it only observes pf.
func (f *DarwinFirewall) ReadBack() (Readback, error) {
	dnsOut, err := pfctlQuery("-q", "-a", dnsAnchorName, "-sr")
	if err != nil {
		return Readback{}, fmt.Errorf("pfctl -a %s -sr: %w", dnsAnchorName, err)
	}
	mainOut, err := pfctlQuery("-q", "-a", anchorName, "-sr")
	if err != nil {
		return Readback{}, fmt.Errorf("pfctl -a %s -sr: %w", anchorName, err)
	}
	blocks, permits := parsePFDNSAnchor(string(dnsOut))
	return Readback{
		DNSProtectionActive: blocks,
		KillSwitchActive:    parsePFMainAnchor(string(mainOut)),
		Permits:             permits,
	}, nil
}
