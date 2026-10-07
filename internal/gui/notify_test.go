package gui

import (
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/wifi"
)

func TestNotifyTextLanguages(t *testing.T) {
	for _, lang := range []string{"en", "ko", "ja"} {
		for _, k := range []msgKind{msgUp, msgDown, msgAuto, msgCritical} {
			title, body := notifyText(lang, k, "Home")
			if title != "WireGuide" || !strings.Contains(body, "Home") || strings.Contains(body, "%!") {
				t.Errorf("%s/%d: %q %q", lang, k, title, body)
			}
		}
	}
	_, fb := notifyText("fr", msgAuto, "X")
	if !strings.HasPrefix(fb, "Automation") {
		t.Errorf("unknown language must fall back to English, got %q", fb)
	}
}

func TestPickLanguage(t *testing.T) {
	cases := map[string]string{
		"(\n    \"ko-KR\",\n    \"en-US\"\n)": "ko",
		"(\n    \"en-US\",\n    \"ja-JP\"\n)": "en",
		"(\n    \"de-DE\",\n    \"ko-KR\"\n)": "en",
		"ja_JP.UTF-8":                         "ja",
		"de_DE.UTF-8":                         "en",
		"":                                    "en",
	}
	for in, want := range cases {
		if got := pickLanguage(in); got != want {
			t.Errorf("pickLanguage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAppleScriptEscape(t *testing.T) {
	got := appleScriptEscape("a\"b\\c\nd")
	if got != `a\"b\\c d` {
		t.Errorf("got %q", got)
	}
}

func TestAutomationNotifyTextLocalised(t *testing.T) {
	rules := []wifi.Rule{
		{When: wifi.Condition{Type: wifi.CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: wifi.ActionConnect},
		{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Office"}, Do: wifi.ActionConnect},
	}
	ev := ipc.AutomationEventPayload{Tunnel: "home-vpn", Action: ipc.AutomationActionConnect,
		RuleIndex: 0, RuleText: "SSID is not HomeWiFi", SSID: "Cafe"}
	_, en := automationNotifyText("en", ev, rules)
	if en != "Automation connected “home-vpn” — SSID is not HomeWiFi (Wi-Fi: Cafe)" {
		t.Errorf("en: %q", en)
	}
	for _, lang := range []string{"ko", "ja"} {
		_, body := automationNotifyText(lang, ev, rules)
		if !strings.Contains(body, "home-vpn") || !strings.Contains(body, "HomeWiFi") ||
			strings.Contains(body, "SSID is not") || strings.Contains(body, "%!") {
			t.Errorf("%s not localised: %q", lang, body)
		}
	}
	// Positive SSID rule already names the network.
	ev2 := ipc.AutomationEventPayload{Tunnel: "t", Action: ipc.AutomationActionConnect, RuleIndex: 1, RuleText: "SSID is Office", SSID: "Office"}
	if _, b := automationNotifyText("en", ev2, rules); b != "Automation connected “t” — SSID is Office" {
		t.Errorf("positive ssid: %q", b)
	}
	if _, b := automationNotifyText("en", ev2, nil); b != "Automation connected “t” — SSID is Office" {
		t.Errorf("fallback positive ssid: %q", b)
	}
	// Rules changed since the helper evaluated: fall back to rule_text.
	ev3 := ev
	ev3.RuleText = "subnet is 10.0.0.0/24"
	if _, b := automationNotifyText("ko", ev3, rules); !strings.Contains(b, "subnet is 10.0.0.0/24") {
		t.Errorf("stale rules must fall back to rule_text: %q", b)
	}
	// No rule text at all: generic message.
	if _, b := automationNotifyText("en", ipc.AutomationEventPayload{Tunnel: "t", RuleIndex: -1}, nil); b != "Automation connected “t”." {
		t.Errorf("generic fallback: %q", b)
	}
	// Every condition kind renders in every language.
	conds := []wifi.Condition{
		{Type: wifi.CondSSID, SSID: "a"}, {Type: wifi.CondSSID, SSID: "a", Negate: true},
		{Type: wifi.CondSubnet, Subnet: "10.0.0.0/8"}, {Type: wifi.CondSubnet, Subnet: "10.0.0.0/8", Negate: true},
		{Type: wifi.CondNetwork, GatewayMAC: "aa:bb:cc:dd:ee:ff"}, {Type: wifi.CondNetwork, Label: "Office", Negate: true},
		{Type: wifi.CondNoneMatch},
		{Type: wifi.CondSSID, SSIDs: []string{"a", "b"}}, {Type: wifi.CondSSID, SSIDs: []string{"a", "b"}, Negate: true},
		{Type: wifi.CondSSID, SSIDs: []string{"a"}},
		{Type: wifi.CondMedium, Medium: "wifi"}, {Type: wifi.CondMedium, Medium: "wired", Negate: true},
		{Type: wifi.CondMedium, Medium: "tethered"},
	}
	for _, lang := range []string{"en", "ko", "ja"} {
		for _, c := range conds {
			if d := describeConditionLocalized(lang, c); d == "" || strings.Contains(d, "%!") {
				t.Errorf("%s %+v: %q", lang, c, d)
			}
		}
	}
}

func TestHistoryInputFromStatus(t *testing.T) {
	st := domain.ConnectionStatus{
		TunnelName: "a", RxBytes: 5, TxBytes: 6, LastChangeReason: "automation",
		ActiveTunnels:     []string{"a", "b"},
		Tunnels:           []domain.ConnectionStatus{{TunnelName: "a", RxBytes: 5, TxBytes: 6, LastChangeReason: "automation"}, {TunnelName: "b", LastChangeReason: "wake"}},
		RecentDisconnects: map[string]domain.TunnelChange{"c": {Reason: "automation"}},
	}
	in := historyInput(st, "Cafe")
	if in.SSID != "Cafe" || in.StartReasons["a"] != "automation" || in.StartReasons["b"] != "wake" ||
		in.EndReasons["c"] != "automation" || in.Rx["a"] != 5 || in.Tx["a"] != 6 || len(in.Active) != 2 {
		t.Fatalf("history input %+v", in)
	}
	old := historyInput(domain.ConnectionStatus{TunnelName: "a", ActiveTunnels: []string{"a"}}, "")
	if old.StartReasons != nil || old.EndReasons != nil {
		t.Fatalf("older helper must yield no reasons: %+v", old)
	}
}

func TestDescribeConditionLocalizedListsAndMedium(t *testing.T) {
	for _, tc := range []struct {
		lang string
		c    wifi.Condition
		want string
	}{
		{"en", wifi.Condition{Type: wifi.CondSSID, SSIDs: []string{"A", "B"}}, "SSID is one of A, B"},
		{"en", wifi.Condition{Type: wifi.CondSSID, SSIDs: []string{"A", "B"}, Negate: true}, "SSID is none of A, B"},
		{"en", wifi.Condition{Type: wifi.CondMedium, Medium: "wired"}, "connection is wired"},
		{"ko", wifi.Condition{Type: wifi.CondMedium, Medium: "tethered", Negate: true}, "연결 유형이 테더링이(가) 아님"},
		{"ja", wifi.Condition{Type: wifi.CondMedium, Medium: "wired"}, "接続種別が 有線"},
	} {
		if got := describeConditionLocalized(tc.lang, tc.c); got != tc.want {
			t.Errorf("%s %+v: got %q want %q", tc.lang, tc.c, got, tc.want)
		}
	}
	// A positive multi-SSID rule doesn't name the network: keep the suffix.
	rules := []wifi.Rule{{When: wifi.Condition{Type: wifi.CondSSID, SSIDs: []string{"A", "B"}}, Do: wifi.ActionConnect}}
	ev := ipc.AutomationEventPayload{Tunnel: "t", SSID: "B", RuleIndex: 0, RuleText: wifi.DescribeRule(rules, 0)}
	if _, b := automationNotifyText("en", ev, rules); b != "Automation connected “t” — SSID is one of A, B (Wi-Fi: B)" {
		t.Errorf("got %q", b)
	}
}
