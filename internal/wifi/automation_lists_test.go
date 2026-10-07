package wifi

import (
	"encoding/json"
	"strings"
	"testing"
)

func ssidList(negate bool, do Action, names ...string) Rule {
	return Rule{When: Condition{Type: CondSSID, Negate: negate, SSIDs: names}, Do: do}
}

func mediumRule(negate bool, m string, do Action) Rule {
	return Rule{When: Condition{Type: CondMedium, Negate: negate, Medium: m}, Do: do}
}

// ethCtx is a settled, online, non-Wi-Fi primary interface with no SSID.
func ethCtx() NetworkContext {
	return NetworkContext{Settled: true, Online: true, PrimaryIface: "en5", PrimaryIsWiFi: false, Medium: MediumWired}
}

func TestSSIDList_Evaluation(t *testing.T) {
	unsettled := settledCtx("Home")
	unsettled.Settled = false
	wifiBlank := settledCtx("")
	for _, tc := range []struct {
		name string
		rule Rule
		ctx  NetworkContext
		want DesiredState
		held bool
	}{
		{"pos first", ssidList(false, ActionConnect, "Home", "Office"), settledCtx("Home"), StateConnect, false},
		{"pos second", ssidList(false, ActionConnect, "Home", "Office"), settledCtx("Office"), StateConnect, false},
		{"pos case-insensitive", ssidList(false, ActionConnect, "Home", "Office"), settledCtx("oFFice"), StateConnect, false},
		{"pos trimmed", ssidList(false, ActionConnect, " Home ", "Office"), settledCtx("Home"), StateConnect, false},
		{"pos miss", ssidList(false, ActionConnect, "Home", "Office"), settledCtx("Cafe"), StateUnmanaged, false},
		{"pos blank wifi", ssidList(false, ActionConnect, "Home", "Office"), wifiBlank, StateUnmanaged, false},
		{"pos ethernet", ssidList(false, ActionConnect, "Home", "Office"), ethCtx(), StateUnmanaged, false},
		{"pos unsettled still matches", ssidList(false, ActionConnect, "Home"), unsettled, StateConnect, false},
		{"pos SSID+SSIDs union", Rule{When: Condition{Type: CondSSID, SSID: "Home", SSIDs: []string{"Office"}}, Do: ActionConnect}, settledCtx("home"), StateConnect, false},
		{"neg outside set", ssidList(true, ActionConnect, "Home", "Office"), settledCtx("Cafe"), StateConnect, false},
		{"neg in set", ssidList(true, ActionConnect, "Home", "Office"), settledCtx("office"), StateUnmanaged, false},
		{"neg blank on wifi holds", ssidList(true, ActionConnect, "Home", "Office"), wifiBlank, StateUnmanaged, true},
		{"neg ethernet known no-SSID", ssidList(true, ActionConnect, "Home", "Office"), ethCtx(), StateConnect, false},
		{"neg unsettled holds", ssidList(true, ActionConnect, "Home", "Office"), unsettled, StateUnmanaged, true},
	} {
		got, info := EvaluateDetailed([]Rule{tc.rule}, tc.ctx)
		if got != tc.want || info.Held != tc.held {
			t.Errorf("%s: got %v held=%v, want %v held=%v", tc.name, got, info.Held, tc.want, tc.held)
		}
	}
}

func TestSSIDList_NegatedHoldBlocksElse(t *testing.T) {
	rules := []Rule{ssidList(true, ActionConnect, "Home", "Office"), elseRule(ActionDisconnect)}
	if got := Evaluate(rules, settledCtx("")); got != StateUnmanaged {
		t.Errorf("held negated list must stop evaluation, got %v", got)
	}
	if got := Evaluate(rules, settledCtx("Home")); got != StateDisconnect {
		t.Errorf("in-set falls through to else, got %v", got)
	}
}

func TestMedium_Evaluation(t *testing.T) {
	wired := ethCtx()
	unsettledWired := ethCtx()
	unsettledWired.Settled = false
	unknown := ethCtx()
	unknown.Medium = ""
	tether := ethCtx()
	tether.Medium = MediumTethered
	offline := NetworkContext{Settled: true}
	for _, tc := range []struct {
		name string
		rule Rule
		ctx  NetworkContext
		want DesiredState
		held bool
	}{
		{"pos equal", mediumRule(false, "wired", ActionConnect), wired, StateConnect, false},
		{"pos equal no settle wait", mediumRule(false, "wired", ActionConnect), unsettledWired, StateConnect, false},
		{"pos case", mediumRule(false, "Wired", ActionConnect), wired, StateConnect, false},
		{"pos different", mediumRule(false, "wifi", ActionConnect), wired, StateUnmanaged, false},
		{"pos unknown", mediumRule(false, "wired", ActionConnect), unknown, StateUnmanaged, false},
		{"pos tethered", mediumRule(false, "tethered", ActionDisconnect), tether, StateDisconnect, false},
		{"neg different settled", mediumRule(true, "wifi", ActionConnect), wired, StateConnect, false},
		{"neg same", mediumRule(true, "wired", ActionConnect), wired, StateUnmanaged, false},
		{"neg unsettled holds", mediumRule(true, "wifi", ActionConnect), unsettledWired, StateUnmanaged, true},
		{"neg unknown holds", mediumRule(true, "wifi", ActionConnect), unknown, StateUnmanaged, true},
		{"neg offline holds", mediumRule(true, "wifi", ActionConnect), offline, StateUnmanaged, true},
	} {
		got, info := EvaluateDetailed([]Rule{tc.rule, elseRule(ActionDisconnect)}, tc.ctx)
		if tc.want == StateUnmanaged && !tc.held {
			// Non-matching positive/negated rules fall through to else.
			tc.want = StateDisconnect
		}
		if got != tc.want || info.Held != tc.held {
			t.Errorf("%s: got %v held=%v, want %v held=%v", tc.name, got, info.Held, tc.want, tc.held)
		}
	}
}

func TestValidate_ListsAndMedium(t *testing.T) {
	for _, tc := range []struct {
		c  Condition
		ok bool
	}{
		{Condition{Type: CondSSID, SSIDs: []string{"A", "B"}}, true},
		{Condition{Type: CondSSID, SSIDs: []string{"", " ", "B"}}, true},
		{Condition{Type: CondSSID, SSIDs: []string{"", " "}}, false},
		{Condition{Type: CondSSID}, false},
		{Condition{Type: CondSSID, Negate: true, SSIDs: []string{"A"}}, true},
		{Condition{Type: CondMedium, Medium: "wifi"}, true},
		{Condition{Type: CondMedium, Medium: "wired"}, true},
		{Condition{Type: CondMedium, Medium: "tethered", Negate: true}, true},
		{Condition{Type: CondMedium, Medium: "ethernet"}, false},
		{Condition{Type: CondMedium}, false},
	} {
		if err := tc.c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%+v: err=%v want ok=%v", tc.c, err, tc.ok)
		}
	}
	// A malformed medium rule never fires (fails closed).
	if got := Evaluate([]Rule{mediumRule(false, "bogus", ActionConnect)}, ethCtx()); got != StateUnmanaged {
		t.Errorf("bogus medium fired: %v", got)
	}
}

func TestSSIDSet_DedupeOrder(t *testing.T) {
	got := SSIDSet(Condition{SSID: " Home ", SSIDs: []string{"home", "Office", "", "OFFICE"}})
	if strings.Join(got, ",") != "Home,Office" {
		t.Errorf("got %v", got)
	}
}

// The user's real config shape and negated rules must round-trip byte-
// identically: the new fields are omitempty.
func TestConditionJSON_RoundTripByteIdentical(t *testing.T) {
	for _, in := range []string{
		`{"home-vpn":[{"when":{"type":"ssid","ssid":"CafeWiFi"},"do":"connect"}]}`,
		`{"t":[{"when":{"type":"ssid","negate":true,"ssid":"CafeWiFi"},"do":"connect"},{"when":{"type":"subnet","negate":true,"subnet":"10.0.0.0/24"},"do":"disconnect"},{"when":{"type":"network","negate":true,"gateway_mac":"aa:bb:cc:dd:ee:ff","label":"Office"},"do":"connect"},{"when":{"type":"none_match"},"do":"disconnect"}]}`,
		`{"t":[{"when":{"type":"ssid","ssids":["A","B"]},"do":"connect"},{"when":{"type":"medium","negate":true,"medium":"wired"},"do":"connect"}]}`,
	} {
		var m map[string][]Rule
		if err := json.Unmarshal([]byte(in), &m); err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != in {
			t.Errorf("round-trip changed bytes:\n in: %s\nout: %s", in, out)
		}
	}
}

func TestDescribeCondition_ListsAndMedium(t *testing.T) {
	for _, tc := range []struct {
		c    Condition
		want string
	}{
		{Condition{Type: CondSSID, SSID: "CafeWiFi"}, "SSID is CafeWiFi"},
		{Condition{Type: CondSSID, SSID: "CafeWiFi", Negate: true}, "SSID is not CafeWiFi"},
		{Condition{Type: CondSSID, SSIDs: []string{"A"}}, "SSID is A"},
		{Condition{Type: CondSSID, SSIDs: []string{"A", "B"}}, "SSID is one of A, B"},
		{Condition{Type: CondSSID, SSIDs: []string{"A", "B"}, Negate: true}, "SSID is none of A, B"},
		{Condition{Type: CondMedium, Medium: "wired"}, "connection is wired"},
		{Condition{Type: CondMedium, Medium: "wifi", Negate: true}, "connection is not Wi-Fi"},
	} {
		if got := DescribeCondition(tc.c); got != tc.want {
			t.Errorf("%+v: got %q want %q", tc.c, got, tc.want)
		}
	}
}
