//go:build darwin

package firewall

import (
	"strings"
	"testing"
)

func TestSnapshotListsBothAnchorsReadOnly(t *testing.T) {
	orig := runPfctl
	t.Cleanup(func() { runPfctl = orig })
	var calls []string
	runPfctl = func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("No ALTQ support in kernel\nALTQ related functions disabled\npass out quick on utun4\n"), nil
	}
	got := Snapshot()
	want := []string{"-a " + anchorName + " -sr", "-a " + dnsAnchorName + " -sr"}
	if len(calls) != 2 || calls[0] != want[0] || calls[1] != want[1] {
		t.Fatalf("pfctl calls = %q, want %q", calls, want)
	}
	if len(got) != 2 || got[0].Kind != "pf-anchor" || got[0].Name != anchorName || got[1].Name != dnsAnchorName {
		t.Fatalf("snapshot = %+v", got)
	}
	if got[0].Rules != "pass out quick on utun4" {
		t.Errorf("ALTQ noise not stripped: %q", got[0].Rules)
	}
}
