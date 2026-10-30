package firewall

import "strings"

// Ruleset is one WireGuide firewall object's loaded rules: a pf anchor on
// macOS, an nftables table on Linux.
type Ruleset struct {
	// Kind is "pf-anchor" or "nft-table".
	Kind  string
	Name  string
	Rules string
	Error string
}

// snapshotTarget is a fixed, read-only listing command for one ruleset. The
// arguments are compile-time constants; nothing a client sends reaches them.
type snapshotTarget struct {
	kind string
	name string
	args []string
}

// collectRulesets runs each target through run and records the output (or
// the failure) in order. A failing target never stops the others.
func collectRulesets(targets []snapshotTarget, run func(args ...string) ([]byte, error)) []Ruleset {
	out := make([]Ruleset, 0, len(targets))
	for _, t := range targets {
		r := Ruleset{Kind: t.kind, Name: t.name}
		b, err := run(t.args...)
		r.Rules = strings.TrimSpace(string(b))
		if err != nil {
			r.Error = err.Error()
		}
		out = append(out, r)
	}
	return out
}
