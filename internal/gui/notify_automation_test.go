package gui

import (
	"strings"
	"testing"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func autoEvent(tunnel, action string) ipc.AutomationEventPayload {
	return ipc.AutomationEventPayload{Tunnel: tunnel, Action: action, RuleIndex: 0, RuleText: "SSID is not HomeWiFi", SSID: "CafeWiFi", Settled: true}
}

const namedConnect = "Automation connected “Office”. Rule: SSID is not HomeWiFi. Wi-Fi: CafeWiFi."

func wantOne(t *testing.T, c *captured, want string) {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
	msgs := c.all()
	if len(msgs) != 1 || (want != "" && msgs[0] != want) {
		t.Fatalf("want exactly %q, got %v", want, msgs)
	}
}

// The helper sends event.automation before auto_connected; with the status
// tick that makes three signals for one change and one notification.
func TestNotifierAutomationEventThenAutoConnectedThenStatus(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.onAutomationEvent(autoEvent("Office", ipc.AutomationActionConnect))
	n.onAutoConnected("Office")
	n.onStatus([]string{"Office"})
	wantOne(t, c, namedConnect)
}

// The status tick lands first; the event inside the hold-back replaces the
// generic message.
func TestNotifierStatusThenAutomationEventWithinDelay(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.onStatus([]string{"Office"})
	n.onAutomationEvent(autoEvent("Office", ipc.AutomationActionConnect))
	n.onAutoConnected("Office")
	wantOne(t, c, namedConnect)
}

// A slow connect: the generic message already went out, so the late event
// (and auto_connected) add nothing.
func TestNotifierStatusThenAutomationEventAfterDelay(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.onStatus([]string{"Office"})
	time.Sleep(100 * time.Millisecond)
	n.onAutomationEvent(autoEvent("Office", ipc.AutomationActionConnect))
	n.onAutoConnected("Office")
	wantOne(t, c, "“Office” connected outside the app.")
}

func TestNotifierAutomationDisconnectDedupes(t *testing.T) {
	n, c := testNotifier()
	n.onStatus([]string{"Office"})
	n.onAutomationEvent(autoEvent("Office", ipc.AutomationActionDisconnect))
	n.onStatus(nil)
	wantOne(t, c, "Automation disconnected “Office”. Rule: SSID is not HomeWiFi. Wi-Fi: CafeWiFi.")
}

// Held, latched, skipped and failed decisions never notify and claim
// nothing, so a later outside change still does.
func TestNotifierAutomationNonActionsSilent(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	for _, a := range []string{ipc.AutomationActionHeld, ipc.AutomationActionLatched, ipc.AutomationActionSkippedOverlap} {
		n.onAutomationEvent(autoEvent("Office", a))
	}
	failed := autoEvent("Office", ipc.AutomationActionConnect)
	failed.Error = "handshake failed"
	n.onAutomationEvent(failed)
	time.Sleep(60 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("non-actions must be silent, got %v", c.all())
	}
	n.onStatus([]string{"Office"})
	wantOne(t, c, "“Office” connected outside the app.")
}

// Connect, disconnect, connect again: each cycle is announced once.
func TestNotifierAutomationRepeatedCycles(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.onAutomationEvent(autoEvent("Office", ipc.AutomationActionConnect))
	n.onStatus([]string{"Office"})
	n.onAutomationEvent(autoEvent("Office", ipc.AutomationActionDisconnect))
	n.onStatus(nil)
	n.onAutomationEvent(autoEvent("Office", ipc.AutomationActionConnect))
	n.onStatus([]string{"Office"})
	time.Sleep(150 * time.Millisecond)
	if got := c.count(); got != 3 {
		t.Fatalf("want 3 (one per change), got %v", c.all())
	}
}

// The rule is localized from the user's settings when it still matches the
// helper's description; otherwise the helper's English text is used.
func TestNotifierAutomationRuleLocalized(t *testing.T) {
	store := storage.NewSettingsStore(t.TempDir())
	if err := store.Update(func(s *storage.Settings) error {
		s.NotifyAutoChanges = true
		s.Language = "ko"
		s.Automation = &automation.Automation{PerTunnel: map[string][]automation.Rule{
			"Office": {{When: automation.Condition{Type: automation.CondMedium, Medium: automation.MediumWired}, Do: automation.ActionConnect}},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c := &captured{}
	n := newNotifier(store, wgapp.NewUserActions())
	n.post = c.add
	n.pendingDelay = 30 * time.Millisecond
	ev := ipc.AutomationEventPayload{Tunnel: "Office", Action: ipc.AutomationActionConnect, RuleIndex: 0, RuleText: "connection type is wired"}
	n.onAutomationEvent(ev)
	wantOne(t, c, "자동화가 “Office” 터널을 연결했습니다. 규칙: 연결 유형이 유선 (이더넷).")

	// Rules changed since the decision: fall back to the helper's text.
	c2 := &captured{}
	n2 := newNotifier(store, wgapp.NewUserActions())
	n2.post = c2.add
	ev.RuleText = "SSID is HomeWiFi"
	ev.Tunnel, ev.SSID = "Office", "HomeWiFi"
	n2.onAutomationEvent(ev)
	wantOne(t, c2, "자동화가 “Office” 터널을 연결했습니다. 규칙: SSID is HomeWiFi. Wi-Fi: HomeWiFi.")
}

func TestAutomationNotifyTextLanguages(t *testing.T) {
	cond := automation.Condition{Type: automation.CondSSID, Negate: true, SSIDs: []string{"HomeWiFi", "CafeWiFi"}}
	rule := notifyRule{cond: &cond, text: "x", ok: true}
	for _, lang := range []string{"en", "ko", "ja", "zh"} {
		for _, up := range []bool{true, false} {
			body := automationNotifyText(lang, up, "Office", rule, "CafeWiFi")
			if !strings.Contains(body, "Office") || !strings.Contains(body, "HomeWiFi, CafeWiFi") || strings.Contains(body, "{") {
				t.Errorf("%s up=%v: %q", lang, up, body)
			}
		}
	}
	if got := automationNotifyText("fr", false, "Office", notifyRule{}, ""); got != "Automation disconnected “Office”." {
		t.Errorf("fallback without rule/SSID: %q", got)
	}
	// Every condition type has a phrase in every language.
	for lang, tbl := range automationStrings {
		for _, c := range []automation.Condition{
			{Type: automation.CondSSID, SSID: "a"}, {Type: automation.CondSubnet, Subnet: "10.66.66.0/24", Negate: true},
			{Type: automation.CondNetwork, GatewayMAC: "b0:38:6c:54:8b:ab"}, {Type: automation.CondMedium, Medium: "tethered"},
			{Type: automation.CondNoneMatch},
		} {
			if tbl.condition(c) == "" {
				t.Errorf("%s: no phrase for %+v", lang, c)
			}
		}
	}
}
