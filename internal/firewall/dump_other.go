//go:build !darwin

package firewall

// AnchorDump is one WireGuide pf anchor's loaded rules (macOS only).
type AnchorDump struct {
	Name  string
	Rules string
	Error string
}

// DumpAnchors returns nil: only macOS has pf anchors.
func DumpAnchors() []AnchorDump { return nil }
