package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/storage"
)

func TestRestoreAutomationHistoryUsesValidatedSavePath(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewSettingsStore(dir)
	s := &TunnelService{settingsStore: store}
	home := automation.Rule{When: automation.Condition{Type: automation.CondSSID, SSID: "HomeWiFi"}, Do: automation.ActionConnect}
	cafe := automation.Rule{When: automation.Condition{Type: automation.CondSSID, SSIDs: []string{"CafeWiFi", "HomeWiFi"}}, Do: automation.ActionDisconnect}
	if err := s.SaveAutomationRules("home-vpn", []automation.Rule{home, cafe}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAutomationRules("home-vpn", []automation.Rule{home}); err != nil {
		t.Fatal(err)
	}
	list := s.ListAutomationHistory("home-vpn")
	if len(list) != 2 || list[1].RuleCount != 2 {
		t.Fatalf("history=%+v", list)
	}
	if err := s.RestoreAutomationHistory(list[1].Name, "home-vpn"); err != nil {
		t.Fatal(err)
	}
	current, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := current.Automation.PerTunnel["home-vpn"]; len(got) != 2 || len(got[1].When.SSIDs) != 2 {
		t.Fatalf("restored rules=%+v", got)
	}
	// The restore is itself recorded, so it can be undone the same way.
	if after := s.ListAutomationHistory("home-vpn"); after[0].RuleCount != 2 || after[1].RuleCount != 1 {
		t.Fatalf("restore not recorded: %+v", after)
	}

	if err := s.RestoreAutomationHistory(list[1].Name, ""); err == nil {
		t.Fatal("empty tunnel name accepted")
	}
	if err := s.RestoreAutomationHistory("../config.json", "home-vpn"); err == nil {
		t.Fatal("path traversal accepted")
	}
	bad := filepath.Join(dir, storage.AutomationHistoryDir, "2030-01-01T00-00-00.000Z.json")
	if err := os.WriteFile(bad, []byte(`{"per_tunnel_rules":{"home-vpn":[{"when":{"type":"medium","medium":"satellite"},"do":"connect"}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreAutomationHistory("2030-01-01T00-00-00.000Z.json", "home-vpn"); err == nil {
		t.Fatal("invalid snapshot rule restored")
	}
	if current, _ := store.Load(); len(current.Automation.PerTunnel["home-vpn"]) != 2 {
		t.Fatal("failed restore changed the rules")
	}
}
