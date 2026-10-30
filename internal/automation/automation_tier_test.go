package automation

import (
	"encoding/json"
	"reflect"
	"testing"
)

// v061Condition is the Condition shape of 0.6.1, the last release before
// SSID lists and medium conditions: no ssids, no medium.
type v061Condition struct {
	Type       string `json:"type"`
	Negate     bool   `json:"negate,omitempty"`
	SSID       string `json:"ssid,omitempty"`
	Subnet     string `json:"subnet,omitempty"`
	GatewayMAC string `json:"gateway_mac,omitempty"`
	Label      string `json:"label,omitempty"`
}

type v061Rule struct {
	When v061Condition `json:"when"`
	Do   string        `json:"do"`
}

// legacyReader is a binary that predates negation: per_tunnel_rules only.
type legacyReader struct {
	PerTunnel map[string][]v061Rule `json:"per_tunnel_rules"`
}

// v2Reader is 0.6.1: per_tunnel_rules merged with per_tunnel_rules_v2.
type v2Reader struct {
	Legacy   map[string][]v061Rule `json:"per_tunnel_rules"`
	Extended map[string][]v061Rule `json:"per_tunnel_rules_v2"`
}

func (r v2Reader) merged() map[string][]v061Rule {
	out := map[string][]v061Rule{}
	for n, rules := range r.Legacy {
		out[n] = rules
	}
	for n, rules := range r.Extended {
		out[n] = rules
	}
	return out
}

func tierFixture() Automation {
	return Automation{PerTunnel: map[string][]Rule{
		"plain": {posSSID("HomeWiFi", ActionDisconnect)},
		"neg":   {negSSID("HomeWiFi", ActionConnect), elseRule(ActionDisconnect)},
		"list": {
			{When: Condition{Type: CondSSID, SSIDs: []string{"HomeWiFi", "CafeWiFi"}}, Do: ActionDisconnect},
			elseRule(ActionConnect),
		},
		"medium": {
			{When: Condition{Type: CondMedium, Medium: MediumWired}, Do: ActionDisconnect},
			elseRule(ActionConnect),
		},
		// Both SSID and SSIDs: a tier-2 reader would narrow it to "HomeWiFi".
		"both": {
			{When: Condition{Type: CondSSID, SSID: "HomeWiFi", SSIDs: []string{"CafeWiFi"}}, Do: ActionDisconnect},
		},
		// An SSIDs list of blanks is still tier 3 (length, not content).
		"blank-list": {
			{When: Condition{Type: CondSSID, SSID: "HomeWiFi", SSIDs: []string{""}}, Do: ActionDisconnect},
		},
		// A negated rule alongside a medium rule: the whole list is tier 3.
		"neg-medium": {
			negSSID("HomeWiFi", ActionConnect),
			{When: Condition{Type: CondMedium, Negate: true, Medium: MediumWiFi}, Do: ActionConnect},
		},
	}}
}

var tier3Tunnels = []string{"list", "medium", "both", "blank-list", "neg-medium"}

func TestRuleTier(t *testing.T) {
	a := tierFixture()
	want := map[string]int{"plain": 1, "neg": 2, "list": 3, "medium": 3, "both": 3, "blank-list": 3, "neg-medium": 3}
	for name, tier := range want {
		if got := ruleTier(a.PerTunnel[name]); got != tier {
			t.Errorf("%s: tier %d, want %d", name, got, tier)
		}
		if got := NeedsV3Storage(a.PerTunnel[name]); got != (tier == 3) {
			t.Errorf("%s: NeedsV3Storage=%v", name, got)
		}
	}
	if ruleTier(nil) != 1 {
		t.Error("empty list must be tier 1")
	}
}

func TestTierPlacement(t *testing.T) {
	b, err := json.Marshal(tierFixture())
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]map[string]json.RawMessage
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	keyOf := map[string]string{"plain": "per_tunnel_rules", "neg": "per_tunnel_rules_v2"}
	for _, n := range tier3Tunnels {
		keyOf[n] = "per_tunnel_rules_v3"
	}
	for name, key := range keyOf {
		for _, k := range []string{"per_tunnel_rules", "per_tunnel_rules_v2", "per_tunnel_rules_v3"} {
			_, present := wire[k][name]
			if present != (k == key) {
				t.Errorf("%s under %s: present=%v, want only under %s", name, k, present, key)
			}
		}
	}
}

func TestTierOmitEmptyKeys(t *testing.T) {
	b, err := json.Marshal(Automation{PerTunnel: map[string][]Rule{"plain": {posSSID("HomeWiFi", ActionConnect)}}})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["per_tunnel_rules_v2"]; ok {
		t.Error("empty v2 key written")
	}
	if _, ok := wire["per_tunnel_rules_v3"]; ok {
		t.Error("empty v3 key written")
	}
}

// Neither an engine that predates negation nor 0.6.1 may see any part of a
// tier-3 list: 0.6.1's Validate rejects medium and list-only SSID rules, so
// it would skip them and fall through to the trailing else (the opposite
// action), and it would narrow a SSID+SSIDs rule to one network.
func TestTier3DowngradeInvisible(t *testing.T) {
	b, err := json.Marshal(tierFixture())
	if err != nil {
		t.Fatal(err)
	}
	var legacy legacyReader
	if err := json.Unmarshal(b, &legacy); err != nil {
		t.Fatal(err)
	}
	var v2 v2Reader
	if err := json.Unmarshal(b, &v2); err != nil {
		t.Fatal(err)
	}
	merged := v2.merged()
	for _, name := range tier3Tunnels {
		if _, ok := legacy.PerTunnel[name]; ok {
			t.Errorf("legacy reader sees tier-3 tunnel %q", name)
		}
		if _, ok := merged[name]; ok {
			t.Errorf("0.6.1 reader sees tier-3 tunnel %q", name)
		}
	}
	// Lower tiers stay visible to the readers that understand them.
	if len(legacy.PerTunnel["plain"]) != 1 || len(merged["plain"]) != 1 {
		t.Error("tier-1 rules must stay readable by every version")
	}
	if _, ok := legacy.PerTunnel["neg"]; ok {
		t.Error("legacy reader sees a negated list")
	}
	if len(merged["neg"]) != 2 {
		t.Error("0.6.1 must still read tier-2 lists")
	}
}

func TestTierRoundTrip(t *testing.T) {
	a := tierFixture()
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var back Automation
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, back) {
		t.Fatalf("roundtrip mismatch:\n got %+v\nwant %+v", back, a)
	}
}

// A tunnel present under several keys (e.g. a stale legacy copy) takes its
// highest-tier list.
func TestTierMergeOrder(t *testing.T) {
	in := `{"per_tunnel_rules":{"t":[{"when":{"type":"ssid","ssid":"A"},"do":"connect"}]},
	"per_tunnel_rules_v2":{"t":[{"when":{"type":"ssid","negate":true,"ssid":"B"},"do":"connect"}]},
	"per_tunnel_rules_v3":{"t":[{"when":{"type":"medium","medium":"wired"},"do":"connect"}]}}`
	var a Automation
	if err := json.Unmarshal([]byte(in), &a); err != nil {
		t.Fatal(err)
	}
	if got := a.PerTunnel["t"]; len(got) != 1 || got[0].When.Type != CondMedium {
		t.Fatalf("v3 must win, got %+v", got)
	}
}
