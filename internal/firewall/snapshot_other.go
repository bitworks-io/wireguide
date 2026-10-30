//go:build !darwin && !linux

package firewall

// Snapshot returns nil: Windows filters live in WFP, which has no text dump.
func Snapshot() []Ruleset { return nil }
