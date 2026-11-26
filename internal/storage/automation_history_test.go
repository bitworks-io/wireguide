package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/automation"
)

func historySSIDRule(ssid string) automation.Rule {
	return automation.Rule{Do: automation.ActionConnect, When: automation.Condition{Type: automation.CondSSID, SSID: ssid}}
}

func historyRules(ssids ...string) *automation.Automation {
	var rules []automation.Rule
	for _, s := range ssids {
		rules = append(rules, historySSIDRule(s))
	}
	return &automation.Automation{PerTunnel: map[string][]automation.Rule{"t": rules}}
}

func TestHistoryRotationKeepsNewestFive(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 8; i++ {
		if _, err := writeHistorySnapshot(dir, historyRules(string(rune('A'+i))), base.Add(time.Duration(i)*time.Second), false); err != nil {
			t.Fatal(err)
		}
	}
	list := ListAutomationHistory(dir, "t")
	if len(list) != MaxAutomationHistory {
		t.Fatalf("kept %d, want %d", len(list), MaxAutomationHistory)
	}
	if list[0].Time != "2026-01-01T00:00:07Z" || list[4].Time != "2026-01-01T00:00:03Z" {
		t.Fatalf("wrong window: %+v", list)
	}
	if list[0].RuleCount != 1 || list[0].TotalRules != 1 {
		t.Fatalf("counts: %+v", list[0])
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, AutomationHistoryDir)); len(entries) != MaxAutomationHistory {
		t.Fatalf("%d files on disk", len(entries))
	}
}

func TestHistorySkipsIdenticalAndNil(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if wrote, err := writeHistorySnapshot(dir, nil, now, false); wrote || err != nil {
		t.Fatalf("nil snapshot: wrote=%v err=%v", wrote, err)
	}
	for i := 0; i < 2; i++ {
		if _, err := writeHistorySnapshot(dir, historyRules("X"), now.Add(time.Duration(i)*time.Second), false); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(ListAutomationHistory(dir, "t")); n != 1 {
		t.Fatalf("got %d snapshots", n)
	}
}

func TestHistorySameMillisecondStaysOrdered(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, s := range []string{"A", "B", "C"} {
		if _, err := writeHistorySnapshot(dir, historyRules(s), now, false); err != nil {
			t.Fatal(err)
		}
	}
	list := ListAutomationHistory(dir, "t")
	if len(list) != 3 {
		t.Fatalf("got %d snapshots", len(list))
	}
	rules, err := AutomationHistoryRules(dir, list[0].Name, "t")
	if err != nil || rules[0].When.SSID != "C" {
		t.Fatalf("newest is not the last write: %v %v", rules, err)
	}
}

// A burst of in-place edits (same rule count) must not push the state
// before the burst out of the slots; adding or removing a rule always
// gets its own slot.
func TestHistoryCoalescesInPlaceEditsOnly(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := historyRules("Home", "Work")
	typed := ""
	for i, c := range "HomeWiFi" {
		typed += string(c)
		next := historyRules("Home", typed)
		if err := SnapshotAutomationHistory(dir, prev, next, base.Add(time.Duration(i)*400*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		prev = next
	}
	list := ListAutomationHistory(dir, "t")
	if len(list) != 2 {
		t.Fatalf("burst used %d slots, want 2 (before + latest)", len(list))
	}
	r, err := AutomationHistoryRules(dir, list[1].Name, "t")
	if err != nil || len(r) != 2 || r[1].When.SSID != "Work" {
		t.Fatalf("pre-burst state lost: %v %v", r, err)
	}
	if err := SnapshotAutomationHistory(dir, prev, historyRules("Home"), base.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	got := ListAutomationHistory(dir, "t")
	if len(got) != 3 || got[0].RuleCount != 1 || got[1].RuleCount != 2 {
		t.Fatalf("removal was coalesced: %+v", got)
	}
	// An in-place edit after the window takes a new slot.
	if err := SnapshotAutomationHistory(dir, historyRules("Home"), historyRules("Cafe"), base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := len(ListAutomationHistory(dir, "t")); n != 4 {
		t.Fatalf("edit outside the window was coalesced: %d", n)
	}
}

func TestHistoryNameSafety(t *testing.T) {
	dir := t.TempDir()
	good := "2026-01-01T00-00-00.000Z.json"
	if !ValidAutomationHistoryName(good) {
		t.Fatal("good name rejected")
	}
	// A config.json next to the history directory must never be reachable.
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"per_tunnel_rules":{"t":[]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "../config.json", "../../etc/passwd", "a/b.json", good + "/..", "..\\x.json",
		good + ".bak", "x" + good, "/" + good, "2026-01-01T00:00:00.000Z.json", ".." + string(filepath.Separator) + good} {
		if ValidAutomationHistoryName(bad) {
			t.Errorf("accepted %q", bad)
		}
		if _, err := AutomationHistoryRules(dir, bad, "t"); err == nil {
			t.Errorf("read accepted %q", bad)
		}
	}
	// Files that do not match the pattern are neither listed nor pruned.
	hdir := filepath.Join(dir, AutomationHistoryDir)
	if err := os.MkdirAll(hdir, 0700); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(hdir, "notes.json")
	if err := os.WriteFile(stray, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 7; i++ {
		_, _ = writeHistorySnapshot(dir, historyRules(string(rune('A'+i))), base.Add(time.Duration(i)*time.Second), false)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Fatal("pruning removed a file it does not own")
	}
}

func TestHistoryRulesValidated(t *testing.T) {
	dir := t.TempDir()
	hdir := filepath.Join(dir, AutomationHistoryDir)
	if err := os.MkdirAll(hdir, 0700); err != nil {
		t.Fatal(err)
	}
	name := "2026-01-01T00-00-00.000Z.json"
	write := func(s string) {
		if err := os.WriteFile(filepath.Join(hdir, name), []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"per_tunnel_rules":{"t":[{"when":{"type":"ssid","ssid":""},"do":"connect"}]}}`)
	if _, err := AutomationHistoryRules(dir, name, "t"); err == nil {
		t.Fatal("invalid rule accepted")
	}
	write(`{"per_tunnel_rules":{},"per_tunnel_rules_v3":{"t":[{"when":{"type":"medium","medium":"wired"},"do":"connect"}]}}`)
	rules, err := AutomationHistoryRules(dir, name, "t")
	if err != nil || len(rules) != 1 || rules[0].When.Medium != automation.MediumWired {
		t.Fatalf("tier-3 snapshot: rules=%v err=%v", rules, err)
	}
	if rules, err := AutomationHistoryRules(dir, name, "other"); err != nil || rules == nil || len(rules) != 0 {
		t.Fatalf("absent tunnel: %v %v", rules, err)
	}
	write("not json")
	if _, err := AutomationHistoryRules(dir, name, "t"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func withHistoryClock(t *testing.T, start time.Time) func(time.Duration) {
	t.Helper()
	now := start
	historyNow = func() time.Time { return now }
	t.Cleanup(func() { historyNow = time.Now })
	return func(d time.Duration) { now = now.Add(d) }
}

// The snapshot is taken in the storage save path, so an Update (the path
// `wireguide ctl automation` uses) is recorded with its pre-change state.
// Unrelated settings saves record nothing.
func TestSaveRecordsRuleHistory(t *testing.T) {
	dir := t.TempDir()
	store := NewSettingsStore(dir)
	advance := withHistoryClock(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	s := DefaultSettings()
	s.Automation = historyRules("Home", "Work")
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	advance(time.Minute)
	if err := store.Update(func(s *Settings) error { s.Theme = "dark"; return nil }); err != nil {
		t.Fatal(err)
	}
	if n := len(store.ListAutomationHistory("t")); n != 1 {
		t.Fatalf("after first save and an unrelated save: %d snapshots", n)
	}
	advance(time.Minute)
	if err := store.Update(func(s *Settings) error {
		s.Automation.PerTunnel["t"] = s.Automation.PerTunnel["t"][:1]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	list := store.ListAutomationHistory("t")
	if len(list) != 2 || list[0].RuleCount != 1 || list[1].RuleCount != 2 {
		t.Fatalf("history=%+v", list)
	}
	rules, err := store.AutomationHistoryRules(list[1].Name, "t")
	if err != nil || len(rules) != 2 || rules[1].When.SSID != "Work" {
		t.Fatalf("removed rule not recoverable: %v %v", rules, err)
	}
}

// Rules written by an older version as legacy wifi_rules are migrated on
// load; the first save afterwards still records them as the prior state.
func TestSaveRecordsMigratedLegacyRulesAsPriorState(t *testing.T) {
	dir := t.TempDir()
	store := NewSettingsStore(dir)
	withHistoryClock(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	legacy := `{"wifi_rules":{"trusted_ssids":["HomeWiFi"],"per_tunnel":{"t":{"auto_connect_ssids":["CafeWiFi"]}}}}`
	if err := os.WriteFile(store.path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	loaded.EnsureAutomation()
	if len(loaded.Automation.PerTunnel["t"]) == 0 {
		t.Fatal("legacy fixture did not migrate to rules for t")
	}
	delete(loaded.Automation.PerTunnel, "t")
	if err := store.Save(loaded); err != nil {
		t.Fatal(err)
	}
	list := store.ListAutomationHistory("t")
	if len(list) == 0 || list[len(list)-1].RuleCount == 0 {
		t.Fatalf("migrated rules not recorded before removal: %+v", list)
	}
}

// A renamed tunnel's rules show up under its new name in the newest
// snapshot; older snapshots keep the old name and count 0 for the new one.
func TestHistoryAfterTunnelRename(t *testing.T) {
	dir := t.TempDir()
	store := NewSettingsStore(dir)
	advance := withHistoryClock(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	s := DefaultSettings()
	s.Automation = historyRules("Home")
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	advance(time.Second)
	if err := store.Update(func(s *Settings) error { s.RenameTunnelRules("t", "renamed"); return nil }); err != nil {
		t.Fatal(err)
	}
	list := store.ListAutomationHistory("renamed")
	if len(list) != 2 || list[0].RuleCount != 1 || list[1].RuleCount != 0 {
		t.Fatalf("history for new name=%+v", list)
	}
	if old := store.ListAutomationHistory("t"); old[1].RuleCount != 1 {
		t.Fatalf("history for old name=%+v", old)
	}
}

// History is best effort: an unwritable history directory never fails a
// rules save.
func TestUnwritableHistoryDoesNotFailSave(t *testing.T) {
	dir := t.TempDir()
	store := NewSettingsStore(dir)
	if err := os.WriteFile(filepath.Join(dir, AutomationHistoryDir), []byte("not a dir"), 0600); err != nil {
		t.Fatal(err)
	}
	s := DefaultSettings()
	s.Automation = historyRules("Home")
	if err := store.Save(s); err != nil {
		t.Fatalf("history failure failed the save: %v", err)
	}
	if active, err := store.Load(); err != nil || len(active.Automation.PerTunnel["t"]) != 1 {
		t.Fatal("rules not saved")
	}
}
