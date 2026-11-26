package automation

import "encoding/json"

// Storage tiers. Each tunnel's WHOLE rule list is stored under the key of
// the highest tier any of its rules needs, so an older reader either sees a
// list exactly as written or not at all:
//
//   - tier 1, per_tunnel_rules: plain ssid/subnet/network/none_match rules
//     every version understands.
//   - tier 2, per_tunnel_rules_v2: negated rules. Engines that predate
//     negation ignore the negate field, which would reverse a condition.
//   - tier 3, per_tunnel_rules_v3: SSID lists (ssids) and connection-type
//     (medium) conditions. A tier-2 reader's Validate rejects type "medium"
//     and an ssid rule whose single SSID is empty, so it would skip those
//     rules and fall through to a trailing none_match — the opposite action.
//
// Keeping even the fallback rules out of an older reader's map prevents such
// fall-through actions.
const (
	tierLegacy   = 1
	tierNegated  = 2
	tierExtended = 3
)

// ruleTier returns the storage tier a tunnel's rule list needs. It tests
// the SSIDs list length, not an empty SSID: a rule with both SSID and SSIDs
// would otherwise be narrowed to its single SSID by a tier-2 reader.
func ruleTier(rules []Rule) int {
	tier := tierLegacy
	for _, r := range rules {
		if r.When.Type == CondMedium || len(r.When.SSIDs) > 0 {
			return tierExtended
		}
		if r.When.Negate {
			tier = tierNegated
		}
	}
	return tier
}

// NeedsV3Storage reports whether rules are stored under
// per_tunnel_rules_v3 (tier 3), which no older binary reads or preserves.
// Storage keeps a separate recovery copy of such lists.
func NeedsV3Storage(rules []Rule) bool {
	return ruleTier(rules) == tierExtended
}

// MarshalJSON places each tunnel's whole rule list under the key for its
// storage tier (see ruleTier).
func (a Automation) MarshalJSON() ([]byte, error) {
	legacy := make(map[string][]Rule)
	negated := make(map[string][]Rule)
	extended := make(map[string][]Rule)
	for name, rules := range a.PerTunnel {
		switch ruleTier(rules) {
		case tierExtended:
			extended[name] = rules
		case tierNegated:
			negated[name] = rules
		default:
			legacy[name] = rules
		}
	}
	return json.Marshal(struct {
		Legacy   map[string][]Rule `json:"per_tunnel_rules"`
		Negated  map[string][]Rule `json:"per_tunnel_rules_v2,omitempty"`
		Extended map[string][]Rule `json:"per_tunnel_rules_v3,omitempty"`
	}{legacy, negated, extended})
}

// UnmarshalJSON merges the tiers in order (1, then 2, then 3), so a tunnel
// present under several keys takes its highest-tier list.
func (a *Automation) UnmarshalJSON(data []byte) error {
	var wire struct {
		Legacy   map[string][]Rule `json:"per_tunnel_rules"`
		Negated  map[string][]Rule `json:"per_tunnel_rules_v2"`
		Extended map[string][]Rule `json:"per_tunnel_rules_v3"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	a.PerTunnel = wire.Legacy
	if a.PerTunnel == nil {
		a.PerTunnel = make(map[string][]Rule)
	}
	for name, rules := range wire.Negated {
		a.PerTunnel[name] = rules
	}
	for name, rules := range wire.Extended {
		a.PerTunnel[name] = rules
	}
	return nil
}
