package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/wifi"
)

func ssidRule(ssid string) wifi.Rule {
	return wifi.Rule{Do: wifi.ActionConnect, When: wifi.Condition{Type: wifi.CondSSID, SSID: ssid}}
}

func TestBackupRotationKeepsNewestFive(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 8; i++ {
		a := &wifi.Automation{PerTunnel: map[string][]wifi.Rule{"t": {ssidRule(string(rune('A' + i)))}}}
		if err := WriteAutomationBackup(dir, a, base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	list := ListAutomationBackups(dir, "t")
	if len(list) != MaxAutomationBackups {
		t.Fatalf("kept %d, want %d", len(list), MaxAutomationBackups)
	}
	if list[0].Time != "2026-01-01T00:00:07Z" || list[4].Time != "2026-01-01T00:00:03Z" {
		t.Fatalf("wrong window: %+v", list)
	}
	if list[0].RuleCount != 1 || list[0].TotalRules != 1 {
		t.Fatalf("counts: %+v", list[0])
	}
}

func TestBackupSkipsIdenticalAndNil(t *testing.T) {
	dir := t.TempDir()
	a := &wifi.Automation{PerTunnel: map[string][]wifi.Rule{"t": {ssidRule("X")}}}
	now := time.Now()
	_ = WriteAutomationBackup(dir, nil, now)
	_ = WriteAutomationBackup(dir, a, now)
	_ = WriteAutomationBackup(dir, a, now.Add(time.Second))
	if n := len(ListAutomationBackups(dir, "t")); n != 1 {
		t.Fatalf("got %d backups", n)
	}
}

func TestBackupSameMillisecondStaysOrdered(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, s := range []string{"A", "B"} {
		_ = WriteAutomationBackup(dir, &wifi.Automation{PerTunnel: map[string][]wifi.Rule{"t": {ssidRule(s)}}}, now)
	}
	if n := len(ListAutomationBackups(dir, "t")); n != 2 {
		t.Fatalf("got %d backups", n)
	}
}

func TestBackupNameSafety(t *testing.T) {
	good := "2026-01-01T00-00-00.000Z.json"
	if !ValidBackupName(good) {
		t.Fatal("good name rejected")
	}
	for _, bad := range []string{"", "../config.json", "../../etc/passwd", "a/b.json", good + "/..", "..\\x.json",
		"2026-01-01T00-00-00.000Z.json.bak", "x" + good, "/" + good, "2026-01-01T00:00:00.000Z.json"} {
		if ValidBackupName(bad) {
			t.Errorf("accepted %q", bad)
		}
		if _, err := ReadAutomationBackupRules(t.TempDir(), bad, "t"); err == nil {
			t.Errorf("read accepted %q", bad)
		}
	}
}

func TestRestoreValidatesRules(t *testing.T) {
	dir := t.TempDir()
	bdir := filepath.Join(dir, AutomationBackupsDir)
	_ = os.MkdirAll(bdir, 0700)
	name := "2026-01-01T00-00-00.000Z.json"
	bad := `{"per_tunnel_rules":{"t":[{"when":{"type":"ssid","ssid":""},"do":"connect"}]}}`
	_ = os.WriteFile(filepath.Join(bdir, name), []byte(bad), 0600)
	if _, err := ReadAutomationBackupRules(dir, name, "t"); err == nil {
		t.Fatal("invalid rule accepted")
	}
	good := `{"per_tunnel_rules":{"t":[{"when":{"type":"ssid","ssid":"Home"},"do":"connect"}]}}`
	_ = os.WriteFile(filepath.Join(bdir, name), []byte(good), 0600)
	rules, err := ReadAutomationBackupRules(dir, name, "t")
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules=%v err=%v", rules, err)
	}
	if rules, err := ReadAutomationBackupRules(dir, name, "other"); err != nil || len(rules) != 0 {
		t.Fatalf("absent tunnel: %v %v", rules, err)
	}
	_ = os.WriteFile(filepath.Join(bdir, name), []byte("not json"), 0600)
	if _, err := ReadAutomationBackupRules(dir, name, "t"); err == nil {
		t.Fatal("garbage accepted")
	}
}

// A burst of keystroke-style saves (same rule count) must not push the
// pre-burst state out of the 5 slots.
func TestSnapshotBurstKeepsPreBurstState(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(ss ...string) *wifi.Automation {
		var rs []wifi.Rule
		for _, s := range ss {
			rs = append(rs, ssidRule(s))
		}
		return &wifi.Automation{PerTunnel: map[string][]wifi.Rule{"t": rs}}
	}
	prev := mk("Home", "Work")
	typed := ""
	for i, c := range "HomeWiFi" {
		typed += string(c)
		next := mk("Home", typed)
		if err := SnapshotAutomation(dir, prev, next, base.Add(time.Duration(i)*400*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		prev = next
	}
	list := ListAutomationBackups(dir, "t")
	if len(list) > 3 {
		t.Fatalf("burst consumed %d slots", len(list))
	}
	r, err := ReadAutomationBackupRules(dir, list[len(list)-1].Name, "t")
	if err != nil || len(r) != 2 || r[1].When.SSID != "Work" {
		t.Fatalf("pre-burst state lost: %v %v", r, err)
	}
	// Removing a rule is never coalesced away.
	if err := SnapshotAutomation(dir, prev, mk("Home"), base.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := ListAutomationBackups(dir, "t"); got[0].RuleCount != 1 || got[1].RuleCount != 2 {
		t.Fatalf("%+v", got)
	}
}
