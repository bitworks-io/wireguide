package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/wifi"
)

func ssidRuleApp(s string) wifi.Rule {
	return wifi.Rule{Do: wifi.ActionConnect, When: wifi.Condition{Type: wifi.CondSSID, SSID: s}}
}

func TestSaveWritesBackupAndRestoreRoundTrips(t *testing.T) {
	dir := t.TempDir()
	svc := &TunnelService{settingsStore: storage.NewSettingsStore(dir)}
	if err := svc.SaveAutomationRules("t", []wifi.Rule{ssidRuleApp("A")}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SaveAutomationRules("t", nil); err != nil { // user removes all rules
		t.Fatal(err)
	}
	list := svc.ListAutomationBackups("t")
	if len(list) < 2 || list[0].RuleCount != 0 || list[1].RuleCount != 1 {
		t.Fatalf("list=%+v", list)
	}
	if err := svc.RestoreAutomationBackup(list[1].Name, "t"); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.settingsStore.Load()
	if len(st.Automation.PerTunnel["t"]) != 1 {
		t.Fatalf("not restored: %+v", st.Automation)
	}
}

func TestRestoreRejectsTraversalAndInvalid(t *testing.T) {
	dir := t.TempDir()
	svc := &TunnelService{settingsStore: storage.NewSettingsStore(dir)}
	// A decoy valid-JSON file outside the backups dir must be unreachable.
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0600)
	for _, n := range []string{"../config.json", "..", "", "x.json"} {
		if err := svc.RestoreAutomationBackup(n, "t"); err == nil {
			t.Errorf("accepted %q", n)
		}
	}
	if err := svc.RestoreAutomationBackup("2026-01-01T00-00-00.000Z.json", ""); err == nil {
		t.Error("empty tunnel accepted")
	}
}

// Rules written outside SaveAutomationRules (CLI, older version) must be
// recoverable after the very first GUI save removes one.
func TestFirstSaveSnapshotsPreChangeState(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewSettingsStore(dir)
	if err := store.Update(func(st *storage.Settings) error {
		st.EnsureAutomation()
		st.Automation.PerTunnel["p"] = []wifi.Rule{ssidRuleApp("Home"), ssidRuleApp("Work")}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	svc := &TunnelService{settingsStore: store}
	if err := svc.SaveAutomationRules("p", []wifi.Rule{ssidRuleApp("Home")}); err != nil {
		t.Fatal(err)
	}
	var two string
	for _, b := range svc.ListAutomationBackups("p") {
		if b.RuleCount == 2 {
			two = b.Name
		}
	}
	if two == "" {
		t.Fatalf("pre-change two-rule state not backed up: %+v", svc.ListAutomationBackups("p"))
	}
	rules, err := svc.AutomationBackupRules(two, "p")
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules=%v err=%v", rules, err)
	}
	if err := svc.RestoreAutomationBackup(two, "p"); err != nil {
		t.Fatal(err)
	}
	st, _ := store.Load()
	if len(st.Automation.PerTunnel["p"]) != 2 {
		t.Fatalf("not restored: %+v", st.Automation)
	}
}
