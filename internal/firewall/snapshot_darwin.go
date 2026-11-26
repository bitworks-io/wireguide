//go:build darwin

package firewall

import "strings"

// Snapshot returns the currently loaded rules of both WireGuide pf anchors
// (`pfctl -a <anchor> -sr`). Read-only; the anchor names are constants.
func Snapshot() []Ruleset {
	return collectRulesets([]snapshotTarget{
		{"pf-anchor", anchorName, []string{"-a", anchorName, "-sr"}},
		{"pf-anchor", dnsAnchorName, []string{"-a", dnsAnchorName, "-sr"}},
	}, func(args ...string) ([]byte, error) {
		out, err := runPfctl(args...)
		return stripPfNoise(out), err
	})
}

// stripPfNoise drops the "No ALTQ support in kernel" lines pfctl prints to
// stderr (runPfctl captures both streams) so they do not read as rules.
func stripPfNoise(b []byte) []byte {
	var keep []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "No ALTQ support") || strings.HasPrefix(l, "ALTQ related functions disabled") {
			continue
		}
		keep = append(keep, l)
	}
	return []byte(strings.Join(keep, "\n"))
}
