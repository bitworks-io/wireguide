package storage

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/korjwl1/wireguide/internal/automation"
)

// legacyAutomation is 0.6.1's on-disk automation shape: it knows
// per_tunnel_rules and per_tunnel_rules_v2 only. Rules stay raw so the
// simulation never depends on this version's Condition type.
type legacyAutomation struct {
	Legacy  map[string][]json.RawMessage `json:"per_tunnel_rules"`
	Negated map[string][]json.RawMessage `json:"per_tunnel_rules_v2,omitempty"`
}

var (
	ruleNegated  = json.RawMessage(`{"when":{"type":"ssid","ssid":"HomeWiFi","negate":true},"do":"connect"}`)
	rulePlain    = json.RawMessage(`{"when":{"type":"ssid","ssid":"HomeWiFi"},"do":"connect"}`)
	ruleNegated2 = json.RawMessage(`{"when":{"type":"ssid","ssid":"CafeWiFi","negate":true},"do":"disconnect"}`)
)

func tier3Rules() []automation.Rule {
	return []automation.Rule{
		{When: automation.Condition{Type: automation.CondMedium, Medium: automation.MediumWired}, Do: automation.ActionDisconnect},
		{When: automation.Condition{Type: automation.CondSSID, SSIDs: []string{"HomeWiFi", "CafeWiFi"}}, Do: automation.ActionConnect},
	}
}

func negatedRules() []automation.Rule {
	return []automation.Rule{{When: automation.Condition{Type: automation.CondSSID, SSID: "HomeWiFi", Negate: true}, Do: automation.ActionConnect}}
}

// save061 rewrites config.json the way 0.6.1 does: it decodes the
// automation keys it knows, applies edit, and writes them back, dropping
// per_tunnel_rules_v3. It returns 0.6.1's marshaled automation bytes, the
// content 0.6.1 writes to its .automation-v2-backup.
func save061(t *testing.T, store *SettingsStore, edit func(*legacyAutomation)) []byte {
	t.Helper()
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var auto legacyAutomation
	if err := json.Unmarshal(doc["automation"], &auto); err != nil {
		t.Fatal(err)
	}
	if auto.Legacy == nil {
		auto.Legacy = map[string][]json.RawMessage{}
	}
	if auto.Negated == nil {
		auto.Negated = map[string][]json.RawMessage{}
	}
	if edit != nil {
		edit(&auto)
	}
	if len(auto.Negated) == 0 {
		auto.Negated = nil
	}
	autoBytes, err := json.MarshalIndent(auto, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	doc["automation"] = autoBytes
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.path, out, 0600); err != nil {
		t.Fatal(err)
	}
	return autoBytes
}

func readFileT(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// assertTier3Recoverable checks, after an older binary has run, that the
// v3 backup is untouched, survives an unrelated save by this binary, is
// reported, and restores the dropped list.
func assertTier3Recoverable(t *testing.T, store *SettingsStore, v3Before []byte) {
	t.Helper()
	v3Path := store.path + automationV3BackupSuffix
	if got := readFileT(t, v3Path); string(got) != string(v3Before) {
		t.Fatal("older binary's save changed the tier-3 backup")
	}
	active, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Automation.PerTunnel["list"]) != 0 {
		t.Fatal("simulation did not drop the tier-3 list")
	}
	active.Theme = "dark"
	if err := store.Save(active); err != nil {
		t.Fatal(err)
	}
	if got := readFileT(t, v3Path); string(got) != string(v3Before) {
		t.Fatal("unrelated save after downgrade changed the tier-3 backup")
	}
	status := store.AutomationBackupStatus()
	if !status.V3.Available || !reflect.DeepEqual(status.V3.Recoverable, []string{"list"}) || status.V3.Error != "" {
		t.Fatalf("v3 status=%+v", status.V3)
	}
	restored, err := store.RestoreAutomationV3Backup()
	if err != nil || !reflect.DeepEqual(restored, []string{"list"}) {
		t.Fatalf("restored=%v err=%v", restored, err)
	}
	active, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(active.Automation.PerTunnel["list"], tier3Rules()) {
		t.Fatalf("restored list=%+v", active.Automation.PerTunnel["list"])
	}
	if status := store.AutomationBackupStatus(); len(status.V3.Recoverable) != 0 {
		t.Fatalf("restored list still reported missing: %+v", status.V3)
	}
}

func saveCurrent(t *testing.T, store *SettingsStore, perTunnel map[string][]automation.Rule) *Settings {
	t.Helper()
	s := DefaultSettings()
	s.Automation = &automation.Automation{PerTunnel: perTunnel}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// 0.6.1 edits a negated (tier-2) tunnel: it rewrites config.json without
// per_tunnel_rules_v3 and overwrites the v2 backup with its own view.
func TestTier3SurvivesOlderBinaryEditingNegatedTunnel(t *testing.T) {
	store := NewSettingsStore(t.TempDir())
	saveCurrent(t, store, map[string][]automation.Rule{"neg": negatedRules(), "list": tier3Rules()})
	v3 := readFileT(t, store.path+automationV3BackupSuffix)
	readFileT(t, store.path+automationBackupSuffix)
	backup := save061(t, store, func(a *legacyAutomation) { a.Negated["neg"] = []json.RawMessage{ruleNegated2} })
	if err := os.WriteFile(store.path+automationBackupSuffix, backup, 0600); err != nil {
		t.Fatal(err)
	}
	assertTier3Recoverable(t, store, v3)
}

// 0.6.1 removes the last negation: config.json loses v2 and v3, and 0.6.1
// retires the shared v2 backup.
func TestTier3SurvivesOlderBinaryRetiringV2Backup(t *testing.T) {
	store := NewSettingsStore(t.TempDir())
	saveCurrent(t, store, map[string][]automation.Rule{"neg": negatedRules(), "list": tier3Rules()})
	v3 := readFileT(t, store.path+automationV3BackupSuffix)
	save061(t, store, func(a *legacyAutomation) {
		delete(a.Negated, "neg")
		a.Legacy["neg"] = []json.RawMessage{rulePlain}
	})
	if err := os.Remove(store.path + automationBackupSuffix); err != nil {
		t.Fatal(err)
	}
	assertTier3Recoverable(t, store, v3)
}

// Only tier-3 rules exist, so (as upstream) there is no v2 backup. 0.6.1
// adds a negated rule and creates the v2 backup from its own view.
func TestTier3SurvivesOlderBinaryCreatingV2Backup(t *testing.T) {
	store := NewSettingsStore(t.TempDir())
	saveCurrent(t, store, map[string][]automation.Rule{"list": tier3Rules()})
	if _, err := os.Stat(store.path + automationBackupSuffix); !os.IsNotExist(err) {
		t.Fatal("tier-3-only rules wrote the v2 backup; upstream writes it for negated rules only")
	}
	v3 := readFileT(t, store.path+automationV3BackupSuffix)
	backup := save061(t, store, func(a *legacyAutomation) { a.Negated["neg"] = []json.RawMessage{ruleNegated} })
	if err := os.WriteFile(store.path+automationBackupSuffix, backup, 0600); err != nil {
		t.Fatal(err)
	}
	assertTier3Recoverable(t, store, v3)
}

// After a downgrade drops "list", editing another tunnel's tier-3 rules
// in this binary must not overwrite the not-yet-restored "list" entry; an
// explicit removal here drops only that tunnel; the file retires only when
// this binary saves with no tier-3 lists left to keep.
func TestTier3BackupCarriesDroppedListsAndRetiresOnlyWhenEmpty(t *testing.T) {
	store := NewSettingsStore(t.TempDir())
	saveCurrent(t, store, map[string][]automation.Rule{"list": tier3Rules()})
	save061(t, store, nil)
	v3Path := store.path + automationV3BackupSuffix

	s := saveCurrent(t, store, map[string][]automation.Rule{"other": tier3Rules()})
	backup, _, err := readV3Backup(v3Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(backup) != 2 || backup["list"] == nil || backup["other"] == nil {
		t.Fatalf("backup tunnels=%v", backup)
	}

	// Explicit removal of "other" by this binary drops only its entry.
	delete(s.Automation.PerTunnel, "other")
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	backup, _, err = readV3Backup(v3Path)
	if err != nil || len(backup) != 1 || backup["list"] == nil {
		t.Fatalf("backup tunnels=%v err=%v", backup, err)
	}

	if _, err := store.RestoreAutomationV3Backup(); err != nil {
		t.Fatal(err)
	}
	active, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	active.Automation.PerTunnel["list"] = negatedRules()
	if err := store.Save(active); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(v3Path); !os.IsNotExist(err) {
		t.Fatal("explicit removal of the last tier-3 list kept the backup")
	}
	if _, err := os.Stat(store.path + automationBackupSuffix); err != nil {
		t.Fatal("negated rules lost their v2 backup")
	}
}

// Restore never replaces a tunnel that has rules, and validates the backup.
func TestRestoreAutomationV3BackupValidatesAndKeepsExistingRules(t *testing.T) {
	store := NewSettingsStore(t.TempDir())
	saveCurrent(t, store, map[string][]automation.Rule{"list": tier3Rules(), "kept": tier3Rules()})
	save061(t, store, func(a *legacyAutomation) { a.Legacy["kept"] = []json.RawMessage{rulePlain} })
	if status := store.AutomationBackupStatus(); !reflect.DeepEqual(status.V3.Recoverable, []string{"list"}) {
		t.Fatalf("v3 status=%+v", status.V3)
	}
	before := readFileT(t, store.path)
	bad := `{"per_tunnel_rules":{},"per_tunnel_rules_v3":{"list":[{"when":{"type":"medium","medium":"satellite"},"do":"connect"}]}}`
	if err := os.WriteFile(store.path+automationV3BackupSuffix, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreAutomationV3Backup(); err == nil {
		t.Fatal("invalid backup rule was restored")
	}
	if string(readFileT(t, store.path)) != string(before) {
		t.Fatal("failed restore changed config.json")
	}
}

// As with the v2 backup, an unwritable v3 backup never blocks unrelated
// settings saves, but fails an automation edit.
func TestUnrelatedSaveDoesNotRequireWritableV3Backup(t *testing.T) {
	store := NewSettingsStore(t.TempDir())
	s := saveCurrent(t, store, map[string][]automation.Rule{"list": tier3Rules()})
	v3Path := store.path + automationV3BackupSuffix
	if err := os.Remove(v3Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(v3Path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(s *Settings) error { s.Theme = "dark"; return nil }); err != nil {
		t.Fatalf("unrelated settings blocked by backup failure: %v", err)
	}
	if status := store.AutomationBackupStatus(); status.V3.Error == "" {
		t.Fatal("v3 backup failure was not visible to the UI")
	}
	s.Theme = "dark"
	s.Automation.PerTunnel["list"] = tier3Rules()[:1]
	if err := store.Save(s); err == nil {
		t.Fatal("automation edit ignored its failed tier-3 backup")
	}
}
