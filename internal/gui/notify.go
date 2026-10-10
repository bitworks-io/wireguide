package gui

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// upNotifyDelay holds back "tunnel connected outside the app" so the
// helper's auto_connected event (which names the automation) can claim the
// same change first and we don't notify twice.
const upNotifyDelay = 1500 * time.Millisecond

// autoClaimTTL is how long an auto_connected event claims its tunnel: an
// up notification for the same tunnel inside this window is skipped,
// whichever of the status tick and the event arrived first.
const autoClaimTTL = 10 * time.Second

// execTimeout bounds the osascript and defaults child processes.
const execTimeout = 4 * time.Second

// notificationBackend is the platform notification service. Implemented
// over the Wails notifications service on macOS and Linux
// (notify_service_desktop.go); Windows has no backend (notify_service_other.go)
// because the service's toast dependency is not vendored in go.sum.
type notificationBackend interface {
	start() error
	requestAuth() (bool, error)
	send(id, title, body string) error
}

// notifier turns helper-driven tunnel changes into native notifications.
//
// It deliberately never fires for something the user did in this GUI
// process (window or tray — both go through TunnelService, which records
// them in UserActions). Changes made by the CLI or the helper itself
// (automation, wake, health check) are "outside the app" and do notify.
//
// The Wails notifications service is used directly rather than registered
// in application.Options.Services: its Startup fails on an unbundled build
// (go run / dev), and a failing service startup would abort the whole app.
// Starting it lazily here keeps that failure local — delivery then falls
// back to osascript on macOS and to a no-op elsewhere.
type notifier struct {
	settings *storage.SettingsStore
	actions  *wgapp.UserActions
	differ   wgapp.StatusDiffer

	mu         sync.Mutex
	pendingUp  map[string]*time.Timer
	recentAuto map[string]time.Time // tunnel -> when auto_connected was seen
	// detailedAuto marks tunnels whose automation connect was already
	// announced from event.automation (with the rule); the generic
	// auto_connected that follows it is then skipped.
	detailedAuto map[string]time.Time
	quitting     bool
	// upNotifyDelay overrides the package default (tests).
	upNotifyDelay time.Duration

	// post delivers one notification; deliver in production, a stub in tests.
	post func(title, body string)

	svcMu       sync.Mutex // guards the fields below; never held across a blocking call
	svc         notificationBackend
	svcStarted  bool
	svcUsable   bool
	authAsked   bool
	authPending bool
}

func newNotifier(settings *storage.SettingsStore, actions *wgapp.UserActions) *notifier {
	n := &notifier{
		settings:     settings,
		actions:      actions,
		pendingUp:    map[string]*time.Timer{},
		recentAuto:   map[string]time.Time{},
		detailedAuto: map[string]time.Time{},
	}
	n.post = n.deliver
	return n
}

// stop silences the notifier for the rest of the session (app quit): the
// helper tearing tunnels down must not read as "outside the app".
func (n *notifier) stop() {
	n.mu.Lock()
	n.quitting = true
	for name, t := range n.pendingUp {
		t.Stop()
		delete(n.pendingUp, name)
	}
	n.mu.Unlock()
}

// autoClaimed reports whether auto_connected recently named the tunnel.
// Caller holds n.mu.
func (n *notifier) autoClaimed(name string, now time.Time) bool {
	t, ok := n.recentAuto[name]
	if ok && now.Sub(t) >= autoClaimTTL {
		delete(n.recentAuto, name)
		return false
	}
	return ok
}

func (n *notifier) enabled() bool {
	if n.settings == nil {
		return true
	}
	s, err := n.settings.Load()
	if err != nil || s == nil {
		return true // unreadable settings: default is on
	}
	return s.NotifyAutoChanges
}

// reset forgets the status baseline (helper restart) and any pending
// connect notifications.
func (n *notifier) reset() {
	n.differ.Reset()
	n.mu.Lock()
	for name, t := range n.pendingUp {
		t.Stop()
		delete(n.pendingUp, name)
	}
	n.mu.Unlock()
}

// onStatus is called for every status event with the active tunnel set.
func (n *notifier) onStatus(active []string) {
	events := n.differ.Observe(active)
	if len(events) == 0 {
		return
	}
	enabled := n.enabled()
	now := time.Now()
	for _, ev := range events {
		switch ev.Kind {
		case wgapp.NotifyTunnelDown:
			n.cancelPendingUp(ev.Tunnel)
			if wgapp.ShouldNotify(enabled, ev, n.actions, now) {
				n.send(msgDown, ev.Tunnel)
			}
		case wgapp.NotifyTunnelUp:
			n.schedulePendingUp(ev)
		}
	}
}

func (n *notifier) schedulePendingUp(ev wgapp.NotifyEvent) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.quitting || n.autoClaimed(ev.Tunnel, time.Now()) {
		return // auto_connected already announced (or will, via the claim)
	}
	if old, ok := n.pendingUp[ev.Tunnel]; ok {
		old.Stop()
	}
	n.pendingUp[ev.Tunnel] = time.AfterFunc(n.upDelay(), func() {
		n.mu.Lock()
		delete(n.pendingUp, ev.Tunnel)
		skip := n.quitting || n.autoClaimed(ev.Tunnel, time.Now())
		n.mu.Unlock()
		if skip {
			return
		}
		if wgapp.ShouldNotify(n.enabled(), ev, n.actions, time.Now()) {
			n.send(msgUp, ev.Tunnel)
		}
	})
}

func (n *notifier) upDelay() time.Duration {
	if n.upNotifyDelay > 0 {
		return n.upNotifyDelay
	}
	return upNotifyDelay
}

func (n *notifier) cancelPendingUp(name string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	t, ok := n.pendingUp[name]
	if ok {
		t.Stop()
		delete(n.pendingUp, name)
	}
	return ok
}

// claimAuto records that an automation connect of name was seen at now
// (suppressing the generic "connected outside the app" for it) and reports
// whether event.automation already announced it in detail. detailed marks
// this call as that detailed announcement.
func (n *notifier) claimAuto(name string, now time.Time, detailed bool) (alreadyDetailed bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, t := range n.recentAuto { // prune
		if now.Sub(t) >= autoClaimTTL {
			delete(n.recentAuto, k)
		}
	}
	for k, t := range n.detailedAuto {
		if now.Sub(t) >= autoClaimTTL {
			delete(n.detailedAuto, k)
		}
	}
	_, alreadyDetailed = n.detailedAuto[name]
	n.recentAuto[name] = now
	if detailed {
		n.detailedAuto[name] = now
	} else {
		delete(n.detailedAuto, name) // consumed by this auto_connected
	}
	return alreadyDetailed
}

// onAutoConnected handles the helper's auto_connected event. When the
// helper (protocol minor >= 4) already sent event.automation for this
// connect, that notification named the rule and this one is skipped.
func (n *notifier) onAutoConnected(name string) {
	detailed := n.claimAuto(name, time.Now(), false)
	n.cancelPendingUp(name) // same change; this message is more specific
	if detailed {
		return
	}
	if wgapp.ShouldNotify(n.enabled(), wgapp.NotifyEvent{Kind: wgapp.NotifyAutoConnected, Tunnel: name}, n.actions, time.Now()) {
		n.send(msgAuto, name)
	}
}

// onAutomation handles the helper's event.automation. Only a successful
// executed connect notifies — naming the rule and SSID — with the same
// dedupe (it claims the tunnel like auto_connected) and user-action
// suppression as the generic message. Held/latched/skipped decisions and
// failed connects never notify; disconnects keep the status-diff path.
func (n *notifier) onAutomation(ev ipc.AutomationEventPayload) {
	if ev.Action != ipc.AutomationActionConnect || ev.Error != "" || ev.Tunnel == "" {
		return
	}
	n.claimAuto(ev.Tunnel, time.Now(), true)
	n.cancelPendingUp(ev.Tunnel)
	if !wgapp.ShouldNotify(n.enabled(), wgapp.NotifyEvent{Kind: wgapp.NotifyAutoConnected, Tunnel: ev.Tunnel}, n.actions, time.Now()) {
		return
	}
	rules := n.rulesFor(ev.Tunnel)
	n.mu.Lock()
	q := n.quitting
	n.mu.Unlock()
	if q {
		return
	}
	go func() {
		title, body := automationNotifyText(n.language(), ev, rules)
		n.post(title, body)
	}()
}

// rulesFor returns tunnel's current automation rules from settings (nil
// when unavailable).
func (n *notifier) rulesFor(tunnel string) []wifi.Rule {
	if n.settings == nil {
		return nil
	}
	s, err := n.settings.Load()
	if err != nil || s == nil {
		return nil
	}
	s.EnsureAutomation()
	if s.Automation == nil {
		return nil
	}
	return s.Automation.PerTunnel[tunnel]
}

// onCriticalError handles the helper's critical_error event.
func (n *notifier) onCriticalError(where string) {
	if wgapp.ShouldNotify(n.enabled(), wgapp.NotifyEvent{Kind: wgapp.NotifyCriticalError}, n.actions, time.Now()) {
		n.send(msgCritical, where)
	}
}

func (n *notifier) send(kind msgKind, arg string) {
	n.mu.Lock()
	q := n.quitting
	n.mu.Unlock()
	if q {
		return
	}
	// Language lookup may exec `defaults`; keep it off the event goroutine.
	go func() {
		title, body := notifyText(n.language(), kind, arg)
		n.post(title, body)
	}()
}

func (n *notifier) language() string {
	lang := "auto"
	var s *storage.Settings
	var err error
	if n.settings != nil {
		s, err = n.settings.Load()
	}
	if err == nil && s != nil && s.Language != "" {
		lang = s.Language
	}
	if lang == "auto" {
		return systemLanguage()
	}
	return lang
}

// deliver posts through the Wails notifications service, requesting
// authorization lazily on first use, and falls back to osascript on macOS
// when authorization or delivery fails (or is still pending).
func (n *notifier) deliver(title, body string) {
	if n.sendViaService(title, body) {
		return
	}
	if runtime.GOOS == "darwin" {
		if err := osascriptNotify(title, body); err != nil {
			slog.Warn("notification fallback failed", "error", err)
		}
	}
}

// sendViaService returns true when the service delivered the notification.
// svcMu is only held for state changes, never across the authorization
// wait (which can block until the user answers the macOS prompt), so other
// notifications fall back immediately while a prompt is pending.
func (n *notifier) sendViaService(title, body string) bool {
	n.svcMu.Lock()
	if !n.svcStarted {
		n.svcStarted = true
		n.svc = newNotificationBackend()
		if err := n.svc.start(); err != nil {
			slog.Info("notifications service unavailable, using fallback", "error", err)
		} else {
			n.svcUsable = true
		}
	}
	if !n.svcUsable || n.authPending {
		n.svcMu.Unlock()
		return false
	}
	svc := n.svc
	if !n.authAsked {
		n.authPending = true
		n.svcMu.Unlock()
		ok, err := svc.requestAuth()
		n.svcMu.Lock()
		n.authPending = false
		n.authAsked = true // ask at most once per session, even on error/timeout
		if err != nil || !ok {
			slog.Info("notification authorization not granted, using fallback", "granted", ok, "error", err)
			n.svcUsable = false
			n.svcMu.Unlock()
			return false
		}
	}
	n.svcMu.Unlock()
	if err := svc.send(fmt.Sprintf("wireguide-%d", time.Now().UnixNano()), title, body); err != nil {
		slog.Info("notification delivery failed, using fallback", "error", err)
		return false
	}
	return true
}

// osascriptNotify posts a notification through AppleScript, which needs no
// bundle identifier or authorization of our own.
func osascriptNotify(title, body string) error {
	script := fmt.Sprintf(`display notification "%s" with title "%s"`, appleScriptEscape(body), appleScriptEscape(title))
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "osascript", "-e", script).Run()
}

func appleScriptEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// --- localisation -------------------------------------------------------

type msgKind int

const (
	msgUp msgKind = iota
	msgDown
	msgAuto
	msgCritical
)

var notifyStrings = map[string]map[msgKind]string{
	"en": {
		msgUp:       "“%s” connected outside the app.",
		msgDown:     "“%s” disconnected outside the app.",
		msgAuto:     "Automation connected “%s”.",
		msgCritical: "Helper problem (%s). Restart WireGuide to recover.",
	},
	"ko": {
		msgUp:       "“%s” 터널이 앱 밖에서 연결되었습니다.",
		msgDown:     "“%s” 터널이 앱 밖에서 연결 해제되었습니다.",
		msgAuto:     "자동화가 “%s” 터널을 연결했습니다.",
		msgCritical: "헬퍼 문제 (%s). 복구하려면 WireGuide를 다시 시작하세요.",
	},
	"ja": {
		msgUp:       "“%s” がアプリ外で接続されました。",
		msgDown:     "“%s” がアプリ外で切断されました。",
		msgAuto:     "自動化が “%s” を接続しました。",
		msgCritical: "ヘルパーの問題 (%s)。復旧するには WireGuide を再起動してください。",
	},
}

// ruleStrings localise an automation rule's condition (see
// wifi.DescribeCondition for the English log form).
var ruleStrings = map[string]map[string]string{
	"en": {
		"ssid": "SSID is %s", "ssid_not": "SSID is not %s",
		"subnet": "subnet is %s", "subnet_not": "subnet is not %s",
		"network": "network is %s", "network_not": "network is not %s",
		"ssid_in": "SSID is one of %s", "ssid_not_in": "SSID is none of %s",
		"medium": "connection is %s", "medium_not": "connection is not %s",
		"m_wifi": "Wi-Fi", "m_wired": "wired", "m_tethered": "tethered",
		"none_match": "no other rule matches",
		"auto_rule":  "Automation connected “%s” — %s",
		"on_wifi":    "%s (Wi-Fi: %s)",
	},
	"ko": {
		"ssid": "SSID가 %s임", "ssid_not": "SSID가 %s이(가) 아님",
		"subnet": "서브넷이 %s임", "subnet_not": "서브넷이 %s이(가) 아님",
		"network": "네트워크가 %s임", "network_not": "네트워크가 %s이(가) 아님",
		"ssid_in": "SSID가 %s 중 하나임", "ssid_not_in": "SSID가 %s 중 어느 것도 아님",
		"medium": "연결 유형이 %s임", "medium_not": "연결 유형이 %s이(가) 아님",
		"m_wifi": "Wi-Fi", "m_wired": "유선", "m_tethered": "테더링",
		"none_match": "다른 규칙이 일치하지 않음",
		"auto_rule":  "자동화가 “%s” 터널을 연결했습니다 — %s",
		"on_wifi":    "%s (Wi-Fi: %s)",
	},
	"ja": {
		"ssid": "SSID が %s", "ssid_not": "SSID が %s ではない",
		"subnet": "サブネットが %s", "subnet_not": "サブネットが %s ではない",
		"network": "ネットワークが %s", "network_not": "ネットワークが %s ではない",
		"ssid_in": "SSID が %s のいずれか", "ssid_not_in": "SSID が %s のいずれでもない",
		"medium": "接続種別が %s", "medium_not": "接続種別が %s ではない",
		"m_wifi": "Wi-Fi", "m_wired": "有線", "m_tethered": "テザリング",
		"none_match": "他のルールに一致しない",
		"auto_rule":  "自動化が “%s” を接続しました — %s",
		"on_wifi":    "%s（Wi-Fi: %s）",
	},
}

// describeConditionLocalized renders c in lang (English fallback).
func describeConditionLocalized(lang string, c wifi.Condition) string {
	table, ok := ruleStrings[lang]
	if !ok {
		table = ruleStrings["en"]
	}
	key, val := c.Type, ""
	switch c.Type {
	case wifi.CondSSID:
		val = c.SSID
		if set := wifi.SSIDSet(c); len(c.SSIDs) > 0 && len(set) > 1 {
			key, val = "ssid_in", strings.Join(set, ", ")
		} else if len(c.SSIDs) > 0 && len(set) == 1 {
			val = set[0]
		}
	case wifi.CondMedium:
		val = c.Medium
		if m, ok := table["m_"+strings.ToLower(strings.TrimSpace(c.Medium))]; ok {
			val = m
		}
	case wifi.CondSubnet:
		val = c.Subnet
	case wifi.CondNetwork:
		val = c.GatewayMAC
		if c.Label != "" {
			val = c.Label
		}
	case wifi.CondNoneMatch:
		return table["none_match"]
	default:
		return wifi.DescribeCondition(c)
	}
	if c.Negate {
		if key == "ssid_in" {
			key = "ssid_not_in"
		} else {
			key += "_not"
		}
	}
	return fmt.Sprintf(table[key], val)
}

// automationNotifyText is the body for an automation connect: the tunnel,
// the deciding rule (localised from the tunnel's current rules when they
// still match what the helper evaluated, else the helper's English
// rule_text) and the SSID unless a positive SSID rule already names it.
func automationNotifyText(lang string, ev ipc.AutomationEventPayload, rules []wifi.Rule) (title, body string) {
	table, ok := ruleStrings[lang]
	if !ok {
		table = ruleStrings["en"]
	}
	rule := ev.RuleText
	positiveSSID := ev.SSID != "" && ev.RuleText == wifi.DescribeCondition(wifi.Condition{Type: wifi.CondSSID, SSID: ev.SSID})
	if ev.RuleIndex >= 0 && ev.RuleIndex < len(rules) && wifi.DescribeRule(rules, ev.RuleIndex) == ev.RuleText {
		c := rules[ev.RuleIndex].When
		rule = describeConditionLocalized(lang, c)
		// A multi-SSID rule doesn't name the network, so keep the suffix.
		positiveSSID = c.Type == wifi.CondSSID && !c.Negate && len(wifi.SSIDSet(c)) <= 1
	}
	if rule == "" {
		return notifyText(lang, msgAuto, ev.Tunnel)
	}
	if ev.SSID != "" && !positiveSSID {
		rule = fmt.Sprintf(table["on_wifi"], rule, ev.SSID)
	}
	return "WireGuide", fmt.Sprintf(table["auto_rule"], ev.Tunnel, rule)
}

// notifyText returns the notification title and body for lang (falling
// back to English). arg is the tunnel name, or the failing subsystem for
// critical errors.
func notifyText(lang string, kind msgKind, arg string) (title, body string) {
	table, ok := notifyStrings[lang]
	if !ok {
		table = notifyStrings["en"]
	}
	return "WireGuide", fmt.Sprintf(table[kind], arg)
}

var (
	sysLangOnce sync.Once
	sysLang     = "en"
)

// systemLanguage maps the OS language to en/ko/ja (default en).
func systemLanguage() string {
	sysLangOnce.Do(func() {
		var raw string
		if runtime.GOOS == "darwin" {
			if out, err := defaultsRead(); err == nil {
				raw = string(out)
			}
		}
		if raw == "" {
			for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
				if v := os.Getenv(k); v != "" {
					raw = v
					break
				}
			}
		}
		sysLang = pickLanguage(raw)
	})
	return sysLang
}

func defaultsRead() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "defaults", "read", "-g", "AppleLanguages").Output()
}

// pickLanguage maps the FIRST language in raw (an AppleLanguages dump like
// `("ko-KR", "en-US")` or a LANG value like `ja_JP.UTF-8`) to en/ko/ja,
// English otherwise. Only the primary language counts, matching the
// frontend's detectLanguage (navigator.language).
func pickLanguage(raw string) string {
	tokens := strings.FieldsFunc(strings.ToLower(raw), func(r rune) bool { return r < 'a' || r > 'z' })
	if len(tokens) > 0 {
		switch tokens[0] {
		case "ko", "ja":
			return tokens[0]
		}
	}
	return "en"
}
