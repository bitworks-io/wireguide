//go:build linux

package firewall

import (
	"errors"
	"strings"
	"testing"
)

func TestSnapshotListsBothTablesReadOnly(t *testing.T) {
	orig := nftList
	t.Cleanup(func() { nftList = orig })
	var calls []string
	nftList = func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		if strings.HasSuffix(strings.Join(args, " "), "_dns") {
			return []byte("Error: No such file or directory"), errors.New("exit status 1")
		}
		return []byte("table inet wireguide {\n}\n"), nil
	}
	got := Snapshot()
	if len(calls) != 2 || calls[0] != "list table inet wireguide" || calls[1] != "list table inet wireguide_dns" {
		t.Fatalf("nft calls = %q", calls)
	}
	if len(got) != 2 || got[0].Kind != "nft-table" || got[0].Error != "" || got[1].Error == "" {
		t.Fatalf("snapshot = %+v", got)
	}
}
