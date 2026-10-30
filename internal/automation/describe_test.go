package automation

import "testing"

func TestDescribeRule(t *testing.T) {
	rules := []Rule{
		{When: Condition{Type: CondSSID, SSID: "HomeWiFi"}, Do: ActionDisconnect},
		{When: Condition{Type: CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: ActionConnect},
		{When: Condition{Type: CondSubnet, Subnet: "192.168.50.0/24"}, Do: ActionConnect},
		{When: Condition{Type: CondSubnet, Negate: true, Subnet: "10.66.66.0/24"}, Do: ActionConnect},
		{When: Condition{Type: CondNetwork, GatewayMAC: "b0:38:6c:54:8b:ab"}, Do: ActionConnect},
		{When: Condition{Type: CondNetwork, GatewayMAC: "b0:38:6c:54:8b:ab", Label: "Office"}, Do: ActionConnect},
		{When: Condition{Type: CondNoneMatch}, Do: ActionDisconnect},
		{When: Condition{Type: "future"}, Do: ActionConnect},
		{When: Condition{Type: CondSSID, SSIDs: []string{"HomeWiFi", "CafeWiFi"}}, Do: ActionConnect},
		{When: Condition{Type: CondSSID, Negate: true, SSIDs: []string{"HomeWiFi", "CafeWiFi"}}, Do: ActionConnect},
		{When: Condition{Type: CondSSID, SSIDs: []string{"HomeWiFi"}}, Do: ActionConnect},
		{When: Condition{Type: CondMedium, Medium: MediumWired}, Do: ActionConnect},
		{When: Condition{Type: CondMedium, Negate: true, Medium: MediumWiFi}, Do: ActionConnect},
	}
	want := []string{
		"SSID is HomeWiFi",
		"SSID is not HomeWiFi",
		"subnet is 192.168.50.0/24",
		"subnet is not 10.66.66.0/24",
		"network is b0:38:6c:54:8b:ab",
		"network is Office",
		"no other rule matches",
		"future",
		"SSID is any of HomeWiFi, CafeWiFi",
		"SSID is none of HomeWiFi, CafeWiFi",
		"SSID is HomeWiFi",
		"connection type is wired",
		"connection type is not wifi",
	}
	for i, w := range want {
		if got := DescribeRule(rules, i); got != w {
			t.Errorf("rule %d: got %q, want %q", i, got, w)
		}
	}
	for _, i := range []int{-1, len(rules)} {
		if got := DescribeRule(rules, i); got != "" {
			t.Errorf("out-of-range index %d: got %q, want empty", i, got)
		}
	}
}
