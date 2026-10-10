package app

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/wifi"
)

func TestBuildAutomationPreview(t *testing.T) {
	rules := map[string][]wifi.Rule{
		"home": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Home"}, Do: wifi.ActionDisconnect}},
		"corp": {
			{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Corp", Negate: true}, Do: wifi.ActionConnect},
		},
		"lan": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Cafe"}, Do: wifi.ActionConnect}},
		"man": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Cafe"}, Do: wifi.ActionConnect}},
	}
	resp := ipc.AutomationPreviewResponse{
		SSID: "Cafe", Online: true, Settled: false, SettleRemainingSec: 9,
		PrimaryIsWiFi: true,
		Tunnels: []ipc.AutomationTunnelDecision{
			{Name: "home", Decision: "disconnect"},
			{Name: "corp", Decision: "held", Held: true},
			{Name: "lan", Decision: "connect"},
			{Name: "man", Decision: "latched", Latched: true},
			{Name: "none", Decision: "unmanaged"},
		},
	}
	got := buildAutomationPreview(resp, rules, func(name string) (string, bool) {
		return "192.168.1.0/24", name == "lan"
	})
	if !got.Available || got.SSIDUnknown || got.SettleRemainingSec != 9 || !got.HasNegatedRules {
		t.Fatalf("header: %+v", got)
	}
	want := map[string]string{
		"home": VerdictDisconnect, "corp": VerdictHeld, "lan": VerdictOverlap,
		"man": VerdictPaused, "none": VerdictNoMatch,
	}
	for _, v := range got.Tunnels {
		if v.Verdict != want[v.Name] {
			t.Errorf("%s: verdict %q, want %q", v.Name, v.Verdict, want[v.Name])
		}
	}
	for _, v := range got.Tunnels {
		if v.Name == "lan" && v.OverlapCIDR != "192.168.1.0/24" {
			t.Errorf("overlap cidr %q", v.OverlapCIDR)
		}
		if v.Name == "man" && (v.RuleIndex != 0 && v.RuleType != "ssid") {
			t.Errorf("man rule: %+v", v)
		}
	}
	if got.Tunnels[1].RuleIndex != 1 || !got.Tunnels[1].RuleNegate || got.Tunnels[1].RuleValue != "Corp" {
		t.Errorf("held rule info: %+v", got.Tunnels[1])
	}
	if got.Tunnels[4].RuleIndex != 0 {
		t.Errorf("no_match should clear rule info: %+v", got.Tunnels[4])
	}
}

func TestBuildAutomationPreviewSSIDUnknown(t *testing.T) {
	build := func(r ipc.AutomationPreviewResponse) AutomationPreview {
		return buildAutomationPreview(r, nil, nil)
	}
	if got := build(ipc.AutomationPreviewResponse{PrimaryIface: "en0", PrimaryIsWiFi: true, Online: true}); !got.SSIDUnknown || !got.PrimaryKnown {
		t.Fatalf("blank SSID on a known Wi-Fi primary must read as unknown: %+v", got)
	}
	if got := build(ipc.AutomationPreviewResponse{PrimaryIface: "en5", Online: true}); got.SSIDUnknown {
		t.Fatal("blank SSID on Ethernet is a real 'no Wi-Fi'")
	}
	// Offline: the helper reports an unknown iface as Wi-Fi; must not blame Location Services.
	if got := build(ipc.AutomationPreviewResponse{PrimaryIsWiFi: true, Online: false}); got.SSIDUnknown || got.PrimaryKnown || got.Online {
		t.Fatalf("offline: %+v", got)
	}
	// Unknown interface while online (Windows, utun default route).
	if got := build(ipc.AutomationPreviewResponse{PrimaryIsWiFi: true, Online: true}); got.SSIDUnknown || got.PrimaryKnown {
		t.Fatalf("unknown iface online: %+v", got)
	}
}

func TestBuildAutomationPreviewMediumAndLists(t *testing.T) {
	rules := map[string][]wifi.Rule{
		"wired": {
			{When: wifi.Condition{Type: wifi.CondSSID, SSIDs: []string{"Home", "Office"}}, Do: wifi.ActionDisconnect},
			{When: wifi.Condition{Type: wifi.CondMedium, Medium: "wired"}, Do: wifi.ActionConnect},
		},
		"list": {{When: wifi.Condition{Type: wifi.CondSSID, Negate: true, SSIDs: []string{"Home", "Office"}}, Do: wifi.ActionConnect}},
	}
	resp := ipc.AutomationPreviewResponse{
		Online: true, Settled: true, PrimaryIface: "en5", Medium: "wired",
		Tunnels: []ipc.AutomationTunnelDecision{
			{Name: "wired", Decision: "connect"},
			{Name: "list", Decision: "connect"},
		},
	}
	got := buildAutomationPreview(resp, rules, nil)
	if got.Medium != "wired" {
		t.Fatalf("medium %q", got.Medium)
	}
	if v := got.Tunnels[0]; v.RuleIndex != 2 || v.RuleType != "medium" || v.RuleValue != "wired" {
		t.Errorf("medium rule must be named via local re-eval: %+v", v)
	}
	if v := got.Tunnels[1]; v.RuleIndex != 1 || !v.RuleNegate || v.RuleValue != "Home, Office" || !v.RuleMulti {
		t.Errorf("list rule: %+v", v)
	}
}
