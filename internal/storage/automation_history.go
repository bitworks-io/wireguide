package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/automation"
)

// Rule history: recent snapshots of the automation rules, so a rule removed
// by mistake (in the GUI, the CLI or another process) can be put back. It
// is a convenience separate from the downgrade backups in
// automation_backup.go: those protect rules an older version cannot read,
// these keep the last few states of every rule edit.

// AutomationHistoryDir is the directory next to config.json that holds the
// snapshots, one file per state.
const AutomationHistoryDir = "automation-history"

// MaxAutomationHistory is how many snapshots are kept (newest first).
const MaxAutomationHistory = 5

// AutomationHistoryCoalesceWindow is how recent the newest snapshot must be
// for an in-place edit to replace it instead of taking a new slot. The
// editor saves ~300 ms after each pause in typing, so without this a few
// seconds of typing would push every older state out.
const AutomationHistoryCoalesceWindow = 60 * time.Second

const historyTimeLayout = "2006-01-02T15-04-05.000Z"

// historyNameRe is the ONLY shape of file name ever read, restored or
// deleted. It has no path separators and no dots beyond the fixed ones, so
// an accepted name cannot leave the history directory.
var historyNameRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z\.json$`)

// ValidAutomationHistoryName reports whether name is a well-formed
// snapshot file name.
func ValidAutomationHistoryName(name string) bool { return historyNameRe.MatchString(name) }

// AutomationHistoryEntry describes one snapshot for the GUI list.
type AutomationHistoryEntry struct {
	Name       string `json:"name"`
	Time       string `json:"time"`        // RFC3339, UTC
	RuleCount  int    `json:"rule_count"`  // rules for the requested tunnel
	TotalRules int    `json:"total_rules"` // rules across all tunnels
}

func historyTime(name string) (time.Time, error) {
	return time.Parse(historyTimeLayout, name[:len(name)-len(".json")])
}

func listHistoryNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && ValidAutomationHistoryName(e.Name()) {
			names = append(names, e.Name())
		}
	}
	// Fixed-width UTC names: lexical order is chronological.
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names
}

// SnapshotAutomationHistory records one rules change: the state before it
// (so rules just removed are recoverable even when an older version or the
// CLI wrote them) and the state after it. The post-change state replaces
// the newest slot instead of adding one when the pre-change state already
// was that slot, it is recent, and the change only edited rules in place
// (same tunnels, same rule count each: a burst of debounced keystroke
// saves). Adding or removing a rule always gets its own slot, so the state
// before a burst survives rotation.
func SnapshotAutomationHistory(configDir string, pre, post *automation.Automation, now time.Time) error {
	wrotePre, err := writeHistorySnapshot(configDir, pre, now, false)
	if err != nil {
		return err
	}
	_, err = writeHistorySnapshot(configDir, post, now, !wrotePre && sameRuleShape(pre, post))
	return err
}

func sameRuleShape(a, b *automation.Automation) bool {
	if a == nil || b == nil || len(a.PerTunnel) != len(b.PerTunnel) {
		return false
	}
	for name, rules := range a.PerTunnel {
		other, ok := b.PerTunnel[name]
		if !ok || len(other) != len(rules) {
			return false
		}
	}
	return true
}

// writeHistorySnapshot reports whether a new file was written. A state
// identical to the newest snapshot is skipped. With coalesce, a newest
// snapshot younger than the coalesce window is replaced.
func writeHistorySnapshot(configDir string, a *automation.Automation, now time.Time, coalesce bool) (bool, error) {
	if a == nil {
		return false, nil
	}
	data := automationBytes(a)
	dir := filepath.Join(configDir, AutomationHistoryDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return false, err
	}
	names := listHistoryNames(dir)
	var replace string
	if len(names) > 0 {
		if newest, err := readAutomationBackup(filepath.Join(dir, names[0])); err == nil && bytes.Equal(newest, data) {
			return false, nil
		}
		if coalesce {
			if t, err := historyTime(names[0]); err == nil && now.Sub(t) >= 0 && now.Sub(t) < AutomationHistoryCoalesceWindow {
				replace = names[0]
			}
		}
	}
	name := now.UTC().Format(historyTimeLayout) + ".json"
	if len(names) > 0 && name <= names[0] {
		// Same millisecond or the clock went back: keep names ordered.
		if t, err := historyTime(names[0]); err == nil {
			name = t.Add(time.Millisecond).UTC().Format(historyTimeLayout) + ".json"
		}
	}
	if err := atomicfile.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		return false, err
	}
	if replace != "" {
		os.Remove(filepath.Join(dir, replace))
		names = names[1:]
	}
	names = append([]string{name}, names...)
	for _, old := range names[min(len(names), MaxAutomationHistory):] {
		os.Remove(filepath.Join(dir, old))
	}
	return true, nil
}

// ListAutomationHistory returns the snapshots newest first, with the number
// of rules each holds for tunnel. Unreadable or malformed files are skipped.
func ListAutomationHistory(configDir, tunnel string) []AutomationHistoryEntry {
	dir := filepath.Join(configDir, AutomationHistoryDir)
	out := []AutomationHistoryEntry{}
	for _, name := range listHistoryNames(dir) {
		a, err := readHistorySnapshot(dir, name)
		if err != nil {
			continue
		}
		t, err := historyTime(name)
		if err != nil {
			continue
		}
		entry := AutomationHistoryEntry{Name: name, Time: t.UTC().Format(time.RFC3339)}
		for n, rules := range a.PerTunnel {
			entry.TotalRules += len(rules)
			if n == tunnel {
				entry.RuleCount = len(rules)
			}
		}
		out = append(out, entry)
	}
	return out
}

func readHistorySnapshot(dir, name string) (*automation.Automation, error) {
	if !ValidAutomationHistoryName(name) {
		return nil, fmt.Errorf("rule history: invalid snapshot name")
	}
	data, err := readAutomationBackup(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	var a automation.Automation
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("rule history: snapshot %s is not valid: %w", name, err)
	}
	return &a, nil
}

// AutomationHistoryRules returns one tunnel's rules from the named
// snapshot. The name is checked against the strict pattern (no path
// traversal) and every rule is validated. A tunnel absent from the
// snapshot yields an empty list.
func AutomationHistoryRules(configDir, name, tunnel string) ([]automation.Rule, error) {
	a, err := readHistorySnapshot(filepath.Join(configDir, AutomationHistoryDir), name)
	if err != nil {
		return nil, err
	}
	rules := a.PerTunnel[tunnel]
	for i, r := range rules {
		if err := automation.ValidateRule(r); err != nil {
			return nil, fmt.Errorf("rule history: rule %d: %w", i+1, err)
		}
	}
	if rules == nil {
		rules = []automation.Rule{}
	}
	return rules, nil
}

// previousAutomationForHistory reads the automation rules currently on
// disk, migrating legacy wifi_rules the same way Load does, so the first
// save after an upgrade still records what was there before.
func (s *SettingsStore) previousAutomationForHistory() *automation.Automation {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil
	}
	var previous Settings
	if json.Unmarshal(data, &previous) != nil {
		return nil
	}
	previous.EnsureAutomation()
	return previous.Automation
}

// snapshotAutomationHistory is called by saveLocked after config.json was
// written, so GUI, CLI and helper edits are all captured, serialised by
// the settings lock. It is best effort: history never fails a save.
func (s *SettingsStore) snapshotAutomationHistory(pre, post *automation.Automation) {
	if post == nil || bytes.Equal(automationBytes(pre), automationBytes(post)) {
		return
	}
	if err := SnapshotAutomationHistory(filepath.Dir(s.path), pre, post, historyNow()); err != nil {
		slog.Warn("could not record automation rule history", "error", err)
	}
}

// historyNow is replaced in tests.
var historyNow = time.Now

// ListAutomationHistory lists this store's rule history for tunnel.
func (s *SettingsStore) ListAutomationHistory(tunnel string) []AutomationHistoryEntry {
	return ListAutomationHistory(filepath.Dir(s.path), tunnel)
}

// AutomationHistoryRules reads tunnel's rules from one of this store's
// history snapshots (see the package function).
func (s *SettingsStore) AutomationHistoryRules(name, tunnel string) ([]automation.Rule, error) {
	return AutomationHistoryRules(filepath.Dir(s.path), name, tunnel)
}
