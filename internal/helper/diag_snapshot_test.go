package helper

import (
	"encoding/json"
	"testing"

	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
)

func TestHandleDiagSnapshotIgnoresParamsAndMapsRulesets(t *testing.T) {
	orig := firewallSnapshot
	t.Cleanup(func() { firewallSnapshot = orig })
	calls := 0
	firewallSnapshot = func() []firewall.Ruleset {
		calls++
		return []firewall.Ruleset{{Kind: "pf-anchor", Name: "com.apple/wireguide", Rules: "block drop", Error: "e"}}
	}
	h := &Helper{}
	// Hostile client parameters must have no effect on what is run.
	got, err := h.handleDiagSnapshot(json.RawMessage(`{"anchor":"x; reboot","name":"../../etc"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, ok := got.(ipc.DiagSnapshotResponse)
	if !ok || calls != 1 {
		t.Fatalf("resp = %#v, calls = %d", got, calls)
	}
	if resp.Platform == "" || len(resp.Rulesets) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if r := resp.Rulesets[0]; r.Kind != "pf-anchor" || r.Name != "com.apple/wireguide" || r.Rules != "block drop" || r.Error != "e" {
		t.Errorf("ruleset = %+v", r)
	}
}
