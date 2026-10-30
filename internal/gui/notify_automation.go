package gui

import (
	"strings"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/ipc"
)

// onAutomationEvent handles the helper's event.automation (protocol minor
// >= 7). An executed rule connect or disconnect is announced with the rule
// that decided it and the Wi-Fi network; it claims the matching status-diff
// change, and the auto_connected that follows a connect stays silent, so the
// change notifies once. Held, latched and skipped decisions and failed
// actions never notify and claim nothing: a later real change still does.
func (n *notifier) onAutomationEvent(ev ipc.AutomationEventPayload) {
	if n == nil || ev.Tunnel == "" || ev.Error != "" {
		return
	}
	var up bool
	kind := wgapp.NotifyAutoConnected
	switch ev.Action {
	case ipc.AutomationActionConnect:
		up = true
	case ipc.AutomationActionDisconnect:
		kind = wgapp.NotifyAutoDisconnected
	default:
		return
	}
	key := changeKey(ev.Tunnel, up)
	now := time.Now()
	ok := n.claim(key, now)
	n.mu.Lock()
	recentLocked(n.named, key, now) // prune
	n.named[key] = now
	n.forgetAnnouncedLocked(key)
	n.mu.Unlock()
	if !ok {
		return // the status diff already announced this change
	}
	if !wgapp.ShouldNotify(n.enabled(), wgapp.NotifyEvent{Kind: kind, Tunnel: ev.Tunnel}, n.actions, now) {
		return
	}
	rule := n.ruleFor(ev)
	n.sendRendered(func(lang string) (string, string) {
		return "WireGuide", automationNotifyText(lang, up, ev.Tunnel, rule, ev.SSID)
	})
}

// ruleFor returns the deciding rule from the user's settings when it still
// matches what the helper decided on (same index and same description), so
// it can be localized; otherwise only the helper's English rule_text is
// known. Its ok is false when no single rule decided.
func (n *notifier) ruleFor(ev ipc.AutomationEventPayload) notifyRule {
	if ev.RuleIndex < 0 || ev.RuleText == "" {
		return notifyRule{}
	}
	r := notifyRule{text: ev.RuleText, ok: true}
	if n.settings == nil {
		return r
	}
	s, err := n.settings.Load()
	if err != nil || s == nil || s.Automation == nil {
		return r
	}
	rules := s.Automation.PerTunnel[ev.Tunnel]
	if ev.RuleIndex < len(rules) && automation.DescribeRule(rules, ev.RuleIndex) == ev.RuleText {
		c := rules[ev.RuleIndex].When
		r.cond = &c
	}
	return r
}

// notifyRule is the deciding rule of an automation notification: its
// condition when known (localized), else the helper's English text.
type notifyRule struct {
	cond *automation.Condition
	text string
	ok   bool
}

// automationNotifyText renders "Automation connected “X”. Rule: …. Wi-Fi: …."
// in lang (English fallback). The rule and SSID sentences are left out when
// unknown.
func automationNotifyText(lang string, up bool, tunnel string, rule notifyRule, ssid string) string {
	t, ok := automationStrings[lang]
	if !ok {
		t = automationStrings["en"]
	}
	body := t.disconnected
	if up {
		body = t.connected
	}
	body = strings.ReplaceAll(body, "{tunnel}", tunnel)
	if rule.ok {
		text := rule.text
		if rule.cond != nil {
			if loc := t.condition(*rule.cond); loc != "" {
				text = loc
			}
		}
		body += strings.ReplaceAll(t.rule, "{rule}", text)
	}
	if ssid != "" {
		body += strings.ReplaceAll(t.ssid, "{ssid}", ssid)
	}
	return body
}

// automationTexts is one language's automation notification table. The
// condition phrases match the Automation status strip (frontend
// automation.why.cond_*).
type automationTexts struct {
	connected, disconnected string
	rule, ssid              string
	// cond maps "<type>_is" / "<type>_not" (and "none") to a phrase with
	// {value}.
	cond   map[string]string
	medium map[string]string
}

// condition localizes c, "" for a condition type this table does not know.
func (t automationTexts) condition(c automation.Condition) string {
	if c.Type == automation.CondNoneMatch {
		return t.cond["none"]
	}
	var value string
	switch c.Type {
	case automation.CondSSID:
		value = strings.Join(automation.SSIDSet(c), ", ")
	case automation.CondSubnet:
		value = c.Subnet
	case automation.CondNetwork:
		value = c.GatewayMAC
		if c.Label != "" {
			value = c.Label
		}
	case automation.CondMedium:
		value = c.Medium
		if m, ok := t.medium[c.Medium]; ok {
			value = m
		}
	default:
		return ""
	}
	suffix := "_is"
	if c.Negate {
		suffix = "_not"
	}
	phrase, ok := t.cond[c.Type+suffix]
	if !ok {
		return ""
	}
	return strings.ReplaceAll(phrase, "{value}", value)
}

var automationStrings = map[string]automationTexts{
	"en": {
		connected:    "Automation connected “{tunnel}”.",
		disconnected: "Automation disconnected “{tunnel}”.",
		rule:         " Rule: {rule}.",
		ssid:         " Wi-Fi: {ssid}.",
		cond: map[string]string{
			"ssid_is": "ssid is {value}", "ssid_not": "ssid is not {value}",
			"subnet_is": "subnet is {value}", "subnet_not": "subnet is not {value}",
			"network_is": "network is {value}", "network_not": "network is not {value}",
			"medium_is": "connection type is {value}", "medium_not": "connection type is not {value}",
			"none": "otherwise",
		},
		medium: map[string]string{"wifi": "Wi-Fi", "wired": "Wired (Ethernet)", "tethered": "Tethered (phone USB/Bluetooth)"},
	},
	"ko": {
		connected:    "자동화가 “{tunnel}” 터널을 연결했습니다.",
		disconnected: "자동화가 “{tunnel}” 터널의 연결을 해제했습니다.",
		rule:         " 규칙: {rule}.",
		ssid:         " Wi-Fi: {ssid}.",
		cond: map[string]string{
			"ssid_is": "SSID가 {value}", "ssid_not": "SSID가 {value} 아님",
			"subnet_is": "서브넷이 {value}", "subnet_not": "서브넷이 {value} 아님",
			"network_is": "네트워크가 {value}", "network_not": "네트워크가 {value} 아님",
			"medium_is": "연결 유형이 {value}", "medium_not": "연결 유형이 {value} 아님",
			"none": "그 외",
		},
		medium: map[string]string{"wifi": "Wi-Fi", "wired": "유선 (이더넷)", "tethered": "테더링 (휴대폰 USB/블루투스)"},
	},
	"ja": {
		connected:    "自動化が “{tunnel}” を接続しました。",
		disconnected: "自動化が “{tunnel}” を切断しました。",
		rule:         " ルール: {rule}。",
		ssid:         " Wi-Fi: {ssid}。",
		cond: map[string]string{
			"ssid_is": "SSID が {value}", "ssid_not": "SSID が {value} でない",
			"subnet_is": "サブネットが {value}", "subnet_not": "サブネットが {value} でない",
			"network_is": "ネットワークが {value}", "network_not": "ネットワークが {value} でない",
			"medium_is": "接続の種類が {value}", "medium_not": "接続の種類が {value} でない",
			"none": "それ以外",
		},
		medium: map[string]string{"wifi": "Wi-Fi", "wired": "有線 (イーサネット)", "tethered": "テザリング (スマートフォン USB/Bluetooth)"},
	},
	"zh": {
		connected:    "自动化已连接“{tunnel}”。",
		disconnected: "自动化已断开“{tunnel}”。",
		rule:         "规则：{rule}。",
		ssid:         "Wi-Fi：{ssid}。",
		cond: map[string]string{
			"ssid_is": "SSID 是 {value}", "ssid_not": "SSID 不是 {value}",
			"subnet_is": "子网是 {value}", "subnet_not": "子网不是 {value}",
			"network_is": "网络是 {value}", "network_not": "网络不是 {value}",
			"medium_is": "连接类型是 {value}", "medium_not": "连接类型不是 {value}",
			"none": "其他情况",
		},
		medium: map[string]string{"wifi": "Wi-Fi", "wired": "有线 (以太网)", "tethered": "共享网络 (手机 USB/蓝牙)"},
	},
}
