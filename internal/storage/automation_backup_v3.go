package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/automation"
)

// automationV3BackupSuffix names the recovery copy of tier-3 rule lists
// (SSID lists, connection-type conditions), stored under
// per_tunnel_rules_v3. 0.6.1 and earlier drop that key whenever they save
// config.json, and they also own the .automation-v2-backup file: editing
// automation rules there overwrites or retires it without seeing any
// tier-3 content. This file is never read, written or removed by those
// versions, so tier-3 lists stay recoverable however the older binary is
// used. The v2 backup keeps its upstream behaviour unchanged.
const automationV3BackupSuffix = ".automation-v3-backup"

// v3Lists returns the tunnels whose whole rule list is stored at tier 3.
func v3Lists(a *automation.Automation) map[string][]automation.Rule {
	out := make(map[string][]automation.Rule)
	if a != nil {
		for name, rules := range a.PerTunnel {
			if automation.NeedsV3Storage(rules) {
				out[name] = rules
			}
		}
	}
	return out
}

// readV3Backup returns the tier-3 lists in the v3 backup and its raw bytes.
// Lists that are not tier 3 are ignored: the file only ever holds tier-3
// lists, and anything else in it was not written by this code.
func readV3Backup(path string) (map[string][]automation.Rule, []byte, error) {
	data, err := readAutomationBackup(path)
	if err != nil {
		return nil, nil, err
	}
	var a automation.Automation
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, data, fmt.Errorf("automation v3 backup: %w", err)
	}
	return v3Lists(&a), data, nil
}

// prepareV3Backup refreshes the tier-3 recovery copy before config.json is
// written and reports whether it should be removed afterwards.
//
// The new content is the tier-3 lists being saved plus every list already
// in the backup whose tunnel has no tier-3 list in either the on-disk
// config or the new settings. Such a tunnel lost its list to an older
// binary (which drops per_tunnel_rules_v3) and has not been restored yet;
// carrying it forward keeps it recoverable when other tunnels' tier-3
// rules are edited first. A tunnel whose tier-3 list was on disk and is
// gone from the new settings was changed by this binary, so its entry is
// dropped. The file is retired only when that leaves nothing to keep.
//
// Failure semantics follow the v2 backup: when the automation rules change,
// a backup failure fails the save; an unrelated settings save only warns.
func (s *SettingsStore) prepareV3Backup(settings *Settings) (bool, error) {
	previous, previousErr := s.currentAutomation()
	changed := previousErr != nil || !bytes.Equal(automationBytes(previous), automationBytes(settings.Automation))
	retire, err := s.refreshV3Backup(previous, settings.Automation, changed)
	if err != nil {
		if changed {
			return false, err
		}
		slog.Warn("could not refresh tier-3 automation backup", "error", err)
		return false, nil
	}
	return retire, nil
}

func (s *SettingsStore) refreshV3Backup(previous, current *automation.Automation, changed bool) (bool, error) {
	path := s.path + automationV3BackupSuffix
	old, oldData, err := readV3Backup(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			oldData = nil
		} else if oldData == nil {
			return false, err
		} else {
			// Unparseable: keep the bytes aside rather than overwrite them.
			archive := fmt.Sprintf("%s.recovery-%x", path, sha256.Sum256(oldData))
			if err := atomicfile.WriteFile(archive, oldData, 0600); err != nil {
				return false, fmt.Errorf("preserve unreadable tier-3 automation backup: %w", err)
			}
			old = nil
		}
	}
	onDisk := v3Lists(previous)
	next := v3Lists(current)
	for name, rules := range old {
		if _, ok := next[name]; ok {
			continue
		}
		if _, ok := onDisk[name]; ok {
			continue
		}
		next[name] = rules
	}
	if len(next) == 0 {
		return oldData != nil && changed, nil
	}
	data := automationBytes(&automation.Automation{PerTunnel: next})
	if bytes.Equal(data, oldData) {
		return false, nil
	}
	return false, writeAutomationBackup(path, data)
}

// AutomationV3BackupStatus describes the tier-3 recovery copy.
type AutomationV3BackupStatus struct {
	// Available is true when the v3 backup file exists.
	Available bool `json:"available"`
	// Recoverable lists the backed-up tunnels that have no rules at all in
	// config.json, typically because an older version dropped them.
	// RestoreAutomationV3Backup puts these back.
	Recoverable []string `json:"recoverable"`
	Error       string   `json:"error,omitempty"`
}

// v3Recoverable lists the backup's tunnels that have no rules in current.
func v3Recoverable(backup map[string][]automation.Rule, current *automation.Automation) []string {
	var names []string
	for name := range backup {
		if current == nil || len(current.PerTunnel[name]) == 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (s *SettingsStore) automationV3BackupStatus() AutomationV3BackupStatus {
	status := AutomationV3BackupStatus{Recoverable: []string{}}
	backup, _, err := readV3Backup(s.path + automationV3BackupSuffix)
	if errors.Is(err, os.ErrNotExist) {
		return status
	}
	status.Available = true
	if err != nil {
		status.Error = err.Error()
		return status
	}
	current, err := s.currentAutomation()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		status.Error = err.Error()
		return status
	}
	status.Recoverable = v3Recoverable(backup, current)
	return status
}

// RestoreAutomationV3Backup puts the backed-up tier-3 rule lists back for
// tunnels that have no rules in config.json, and returns their names. It
// never replaces a tunnel's existing rules. The backup is untrusted input,
// so every rule is validated first; any invalid rule aborts the restore.
// It runs as a locked read-modify-write like any other automation edit.
func (s *SettingsStore) RestoreAutomationV3Backup() ([]string, error) {
	var restored []string
	err := s.Update(func(settings *Settings) error {
		backup, _, err := readV3Backup(s.path + automationV3BackupSuffix)
		if err != nil {
			return err
		}
		settings.EnsureAutomation()
		names := v3Recoverable(backup, settings.Automation)
		for _, name := range names {
			for i, r := range backup[name] {
				if err := automation.ValidateRule(r); err != nil {
					return fmt.Errorf("automation backup: %s rule %d: %w", name, i+1, err)
				}
			}
		}
		if settings.Automation.PerTunnel == nil {
			settings.Automation.PerTunnel = map[string][]automation.Rule{}
		}
		for _, name := range names {
			settings.Automation.PerTunnel[name] = backup[name]
		}
		restored = names
		return nil
	})
	if err != nil {
		return nil, err
	}
	if restored == nil {
		restored = []string{}
	}
	return restored, nil
}
