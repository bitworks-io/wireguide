//go:build darwin

package firewall

import "strings"

// AnchorDump is one WireGuide pf anchor's loaded rules.
type AnchorDump struct {
	Name  string
	Rules string
	Error string
}

// DumpAnchors returns the currently loaded rules of both WireGuide pf anchors
// (`pfctl -a <anchor> -sr`). Read-only; the anchor names are fixed constants.
func DumpAnchors() []AnchorDump {
	var out []AnchorDump
	for _, name := range []string{anchorName, dnsAnchorName} {
		d := AnchorDump{Name: name}
		b, err := pfctlQuery("-a", name, "-sr")
		d.Rules = strings.TrimSpace(string(b))
		if err != nil {
			d.Error = err.Error()
		}
		out = append(out, d)
	}
	return out
}
