//go:build linux

package firewall

import (
	"context"
	"os/exec"
)

// nftList runs a read-only `nft list ...` with the same bound as the other
// nft invocations. It is a seam for tests.
var nftList = func(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nftCmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "nft", args...).CombinedOutput()
}

// Snapshot returns the WireGuide nftables tables (`nft list table inet
// <name>`): the kill-switch table and the DNS protection table. A table that
// is not loaded is reported with nft's error, which is itself informative.
func Snapshot() []Ruleset {
	return collectRulesets([]snapshotTarget{
		{"nft-table", "inet " + nftTable, []string{"list", "table", "inet", nftTable}},
		{"nft-table", "inet " + nftTable + "_dns", []string{"list", "table", "inet", nftTable + "_dns"}},
	}, nftList)
}
