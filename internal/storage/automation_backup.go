package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/korjwl1/wireguide/internal/wifi"
)

// AutomationBackupsDir is the directory (next to config.json) holding
// snapshots of the automation block, one file per successful save.
const AutomationBackupsDir = "automation-backups"

// MaxAutomationBackups is how many snapshots are kept (newest first).
const MaxAutomationBackups = 5

const backupTimeLayout = "2006-01-02T15-04-05.000Z"

// backupNameRe is the ONLY shape of file name ever read, restored or
// deleted. It carries no path separators or dots beyond the fixed ones, so
// a name accepted by it cannot traverse out of the backups directory.
var backupNameRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z\.json$`)

// ValidBackupName reports whether name is a well-formed backup file name.
func ValidBackupName(name string) bool { return backupNameRe.MatchString(name) }

// AutomationBackupInfo describes one snapshot for the GUI list.
type AutomationBackupInfo struct {
	Name       string `json:"name"`
	Time       string `json:"time"`        // RFC3339 (UTC)
	RuleCount  int    `json:"rule_count"`  // rules for the requested tunnel
	TotalRules int    `json:"total_rules"` // rules across all tunnels
}

func ruleCount(a *wifi.Automation, tunnel string) (forTunnel, total int) {
	if a == nil {
		return 0, 0
	}
	for n, rs := range a.PerTunnel {
		total += len(rs)
		if n == tunnel {
			forTunnel = len(rs)
		}
	}
	return
}

func listBackupNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && ValidBackupName(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names))) // fixed-width UTC => lexical == chronological
	return names
}

// BackupCoalesceWindow is how recent the newest snapshot must be for
// SnapshotAutomation to replace it with the post-change state instead of
// adding a slot. The editor saves ~300 ms after every keystroke pause, so
// without this a few seconds of typing would push every older state out.
const BackupCoalesceWindow = 60 * time.Second

// WriteAutomationBackup snapshots the automation block into
// <configDir>/automation-backups/<timestamp>.json and prunes to the newest
// MaxAutomationBackups. A snapshot identical to the newest one is skipped.
// A nil block writes nothing.
func WriteAutomationBackup(configDir string, a *wifi.Automation, now time.Time) error {
	_, err := writeBackup(configDir, a, now, false)
	return err
}

// SnapshotAutomation records one save: the state BEFORE the change (so the
// rules a user just removed are always recoverable, even when they were
// written by the CLI or an older version) and the state after it. The
// post-change state replaces the newest slot instead of adding one when the
// pre-change state was already that newest slot, it is recent, and the
// save only edited rules in place (same rule count per tunnel: a burst of
// debounced keystroke saves). Adding or removing a rule always gets its own
// slot, and the pre-burst image survives rotation.
func SnapshotAutomation(configDir string, pre, post *wifi.Automation, now time.Time) error {
	wrotePre, err := writeBackup(configDir, pre, now, false)
	if err != nil {
		return err
	}
	_, err = writeBackup(configDir, post, now, !wrotePre && sameShape(pre, post))
	return err
}

func sameShape(a, b *wifi.Automation) bool {
	if a == nil || b == nil || len(a.PerTunnel) != len(b.PerTunnel) {
		return false
	}
	for n, rs := range a.PerTunnel {
		o, ok := b.PerTunnel[n]
		if !ok || len(o) != len(rs) {
			return false
		}
	}
	return true
}

// writeBackup reports whether a new file was written. With coalesce, a
// newest snapshot younger than BackupCoalesceWindow is replaced.
func writeBackup(configDir string, a *wifi.Automation, now time.Time, coalesce bool) (bool, error) {
	if a == nil {
		return false, nil
	}
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return false, err
	}
	dir := filepath.Join(configDir, AutomationBackupsDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return false, err
	}
	names := listBackupNames(dir)
	var replace string
	if len(names) > 0 {
		if prev, err := os.ReadFile(filepath.Join(dir, names[0])); err == nil && bytes.Equal(prev, data) {
			return false, nil
		}
		if coalesce {
			if t, err := time.Parse(backupTimeLayout, names[0][:len(names[0])-len(".json")]); err == nil &&
				now.Sub(t) >= 0 && now.Sub(t) < BackupCoalesceWindow {
				replace = names[0]
			}
		}
	}
	name := now.UTC().Format(backupTimeLayout) + ".json"
	if len(names) > 0 && name <= names[0] {
		// Clock went backwards or same millisecond: keep ordering monotonic.
		if t, err := time.Parse(backupTimeLayout, names[0][:len(names[0])-len(".json")]); err == nil {
			name = t.Add(time.Millisecond).UTC().Format(backupTimeLayout) + ".json"
		}
	}
	tmp, err := os.CreateTemp(dir, ".backup-*.tmp")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return false, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return false, err
	}
	if err := os.Chmod(tmpName, 0600); err != nil && !os.IsPermission(err) {
		os.Remove(tmpName)
		return false, err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		os.Remove(tmpName)
		return false, err
	}
	if replace != "" {
		os.Remove(filepath.Join(dir, replace))
		names = names[1:]
	}
	names = append([]string{name}, names...)
	for _, old := range names[min(len(names), MaxAutomationBackups):] {
		os.Remove(filepath.Join(dir, old))
	}
	return true, nil
}

// ListAutomationBackups returns snapshots newest first, counting the rules
// that belong to tunnel (TotalRules counts all). Unreadable or malformed
// files are skipped.
func ListAutomationBackups(configDir, tunnel string) []AutomationBackupInfo {
	dir := filepath.Join(configDir, AutomationBackupsDir)
	out := []AutomationBackupInfo{}
	for _, name := range listBackupNames(dir) {
		a, err := readBackup(dir, name)
		if err != nil {
			continue
		}
		t, err := time.Parse(backupTimeLayout, name[:len(name)-len(".json")])
		if err != nil {
			continue
		}
		forT, total := ruleCount(a, tunnel)
		out = append(out, AutomationBackupInfo{
			Name: name, Time: t.UTC().Format(time.RFC3339), RuleCount: forT, TotalRules: total,
		})
	}
	return out
}

func readBackup(dir, name string) (*wifi.Automation, error) {
	if !ValidBackupName(name) {
		return nil, fmt.Errorf("invalid backup name")
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	var a wifi.Automation
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("backup %s is not valid: %w", name, err)
	}
	return &a, nil
}

// ReadAutomationBackupRules loads one tunnel's rules from the named
// snapshot, validating the name (no path traversal) and every rule. A
// tunnel absent from the snapshot yields an empty list.
func ReadAutomationBackupRules(configDir, name, tunnel string) ([]wifi.Rule, error) {
	if !ValidBackupName(name) {
		return nil, fmt.Errorf("automation backup: invalid name")
	}
	a, err := readBackup(filepath.Join(configDir, AutomationBackupsDir), name)
	if err != nil {
		return nil, err
	}
	rules := a.PerTunnel[tunnel]
	for i, r := range rules {
		if err := wifi.ValidateRule(r); err != nil {
			return nil, fmt.Errorf("automation backup: rule %d: %w", i+1, err)
		}
	}
	return rules, nil
}
