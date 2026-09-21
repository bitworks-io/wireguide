package helper

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

// Desired tunnel state — the set of tunnels that SHOULD be active, persisted
// across helper restarts so a helper crash doesn't silently drop the user's
// VPN (issue #44).
//
// Background: the tunnel (utun/wintun) lives inside the helper process, so a
// helper crash kills every tunnel with it. After launchd (or the service
// manager) restarts the helper, every reconnect source was in-memory:
// activeCfgs started empty, the crash journal in internal/tunnel/recovery.go
// only restores system state (DNS, firewall, routes), and the reconnect
// monitor's wake/network triggers skip when the manager reports nothing
// active. The user's only recourse was a manual reconnect — reported live as
// "every time the Mac woke from sleep, WireGuide was disconnected".
//
// This file closes that gap with a small intent file,
// <dataDir>/desired-tunnels.json:
//
//   - Written on user-intent transitions only: successful Connect
//     (doConnectHeld), Disconnect, and tunnel rename. Clean shutdown clears
//     it (cleanup). The monitor's internal teardown-before-reconnect
//     deliberately does NOT touch it — a tunnel mid-reconnect is still
//     wanted. A failed Connect needs no write: activeCfgs rolls back to the
//     pre-call state, which is what the file already records.
//   - Restored once at helper startup: if the file is non-empty and was
//     written during the CURRENT boot, each listed tunnel is reloaded from
//     the user's tunnel store and reconnected. A file older than the current
//     boot means the tunnels died with a previous power cycle — after a
//     reboot the user's expectation is "off", so the file is cleared.
//   - Restore failures (e.g. no network yet right after a crash-restart)
//     keep their entry so the existing wake/network-change triggers retry
//     them; reconnectFn rebuilds its config cache from this file when the
//     in-memory one is empty.
//
// Semantics by exit path:
//
//	helper crash / kill -9 mid-session   → restore (same boot, file fresh)
//	crash while the machine is asleep    → restore on launchd restart / wake
//	upgrade ForceShutdown (no teardown)  → restore (tunnel continuity across updates)
//	clean Quit / `wireguide ctl stop`    → no restore (cleanup cleared the file)
//	reboot / power loss                  → no restore (file predates current boot)

const desiredStateFile = "desired-tunnels.json"

// bootTimeSlack absorbs clock-source skew between a file's mtime (wall
// clock) and the platform boot time (kern.boottime / /proc/uptime /
// GetTickCount64 — wall-clock derived but sampled and rounded differently).
// Two seconds is far below any real power cycle while comfortably above
// sampling noise.
const bootTimeSlack = 2 * time.Second

type desiredStateJSON struct {
	Tunnels []string `json:"tunnels"`
}

func desiredStatePath(dataDir string) string {
	return filepath.Join(dataDir, desiredStateFile)
}

// loadDesiredState returns the persisted tunnel names, or nil when absent.
// A missing file is the common case (nothing wanted), not an error; neither
// is a corrupt file — both mean "nothing to restore".
func loadDesiredState(dataDir string) []string {
	if dataDir == "" {
		return nil
	}
	data, err := os.ReadFile(desiredStatePath(dataDir))
	if err != nil {
		return nil
	}
	var st desiredStateJSON
	if err := json.Unmarshal(data, &st); err != nil {
		return nil
	}
	return st.Tunnels
}

// saveDesiredState writes sorted, de-duplicated names atomically (temp file
// + rename). An empty list removes the file entirely.
func saveDesiredState(dataDir string, names []string) error {
	if dataDir == "" {
		return nil
	}
	sorted := normalizeTunnelNames(names)
	if len(sorted) == 0 {
		clearDesiredState(dataDir)
		return nil
	}
	data, err := json.MarshalIndent(desiredStateJSON{Tunnels: sorted}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(desiredStatePath(dataDir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, desiredStateFile+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// 0600: root-owned file in a root-owned dir; names aren't secret, but
	// keep parity with the crash-recovery journal's permissions.
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, desiredStatePath(dataDir))
}

// clearDesiredState removes the file (best-effort, errors logged).
func clearDesiredState(dataDir string) {
	if dataDir == "" {
		return
	}
	if err := os.Remove(desiredStatePath(dataDir)); err != nil && !os.IsNotExist(err) {
		slog.Warn("desired-state: remove failed", "error", err)
	}
}

func normalizeTunnelNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// desiredStatePredatesBoot reports whether the file's last write happened
// before the current boot — i.e. the tunnels it lists died with a previous
// power cycle and must not be resurrected after a reboot.
func desiredStatePredatesBoot(modTime, bootTime time.Time) bool {
	return modTime.Add(bootTimeSlack).Before(bootTime)
}

// persistDesiredState snapshots activeCfgs into the desired-state file.
// Called on user-intent transitions (connect success, disconnect, rename).
// An empty snapshot removes the file, so a helper that cleanly ends with no
// tunnels leaves nothing to restore on its next start.
func (h *Helper) persistDesiredState() {
	if h.dataDir == "" {
		return
	}
	h.mu.Lock()
	names := make([]string, 0, len(h.activeCfgs))
	for name := range h.activeCfgs {
		names = append(names, name)
	}
	h.mu.Unlock()
	if err := saveDesiredState(h.dataDir, names); err != nil {
		slog.Warn("desired-state: save failed", "error", err)
	}
}

// desiredActiveFn is handed to the reconnect monitor. When the manager
// reports nothing active but the desired-state file lists tunnels, wake and
// network-change triggers must still fire (issue #44: the old guard skipped
// them, so a crash-restarted helper whose restore attempt failed never
// retried and the user had to reconnect by hand).
func (h *Helper) desiredActiveFn() bool {
	return len(loadDesiredState(h.dataDir)) > 0
}

// loadDesiredCfgs rebuilds a config set from the desired-state file plus the
// user's tunnel store, priming activeCfgs so per-tunnel reconnect paths also
// find their configs. Used by reconnectFn when the in-memory cache is empty
// (fresh helper after a crash-restart whose startup restore failed).
func (h *Helper) loadDesiredCfgs() map[string]*domain.WireGuardConfig {
	names := loadDesiredState(h.dataDir)
	if len(names) == 0 || h.userTunnelStore == nil {
		return nil
	}
	cfgs := make(map[string]*domain.WireGuardConfig, len(names))
	var loaded []string
	for _, name := range names {
		cfg, err := h.userTunnelStore.Load(name)
		if err != nil {
			slog.Warn("desired-state: config no longer loadable, dropping",
				"tunnel", name, "error", err)
			continue
		}
		cfgs[name] = cfg
		loaded = append(loaded, name)
	}
	if len(loaded) != len(names) {
		// Some listed tunnels vanished from disk — rewrite the file so the
		// same failures aren't re-logged on every trigger.
		if err := saveDesiredState(h.dataDir, loaded); err != nil {
			slog.Warn("desired-state: save after drop failed", "error", err)
		}
	}
	h.mu.Lock()
	for name, cfg := range cfgs {
		if _, exists := h.activeCfgs[name]; !exists {
			h.activeCfgs[name] = cfg
		}
	}
	h.mu.Unlock()
	return cfgs
}

// systemBootTimeNow is a test seam over the platform-specific boot-time
// readers in boottime_*.go.
var systemBootTimeNow = systemBootTime

// restoreDesiredTunnels runs once at helper startup (via goSafe). It is the
// issue #44 fix: re-establish tunnels that were active when the previous
// helper instance died without a clean shutdown.
//
// The whole loop holds connectMu: a GUI Connect/Disconnect issued during the
// restore must not interleave with the per-tunnel connects or the final
// desired-state rewrite. The helper only just started, so the blocking
// window is a fresh session's first seconds.
func (h *Helper) restoreDesiredTunnels() {
	names := loadDesiredState(h.dataDir)
	if len(names) == 0 {
		return
	}

	if boot, err := systemBootTimeNow(); err == nil {
		if info, ierr := os.Stat(desiredStatePath(h.dataDir)); ierr == nil &&
			desiredStatePredatesBoot(info.ModTime(), boot) {
			slog.Info("desired-state predates current boot; clearing (tunnels died with a previous power cycle)",
				"tunnels", names,
				"file_mtime", info.ModTime().Format(time.RFC3339),
				"boot", boot.Format(time.RFC3339))
			clearDesiredState(h.dataDir)
			return
		}
	} else {
		// Boot time unavailable (unusual platform / syscall failure):
		// restore without the reboot check. The crash-during-sleep case this
		// fixes is same-boot by definition, and an unwanted restore after a
		// reboot is recoverable with one disconnect.
		slog.Warn("desired-state: boot time unavailable, skipping reboot check", "error", err)
	}

	if h.userTunnelStore == nil {
		slog.Warn("desired-state: no tunnel store available; leaving file for later triggers",
			"tunnels", names)
		return
	}

	restored, failed, missing := 0, 0, 0
	remaining := make([]string, 0, len(names))

	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	for _, name := range names {
		// Bounded shutdown: cleanup() closes h.done before DisconnectAll;
		// stop restoring so we don't fight the teardown.
		select {
		case <-h.done:
			return
		default:
		}
		// A GUI or automation connect may have raced us onto this tunnel
		// while earlier restores were in flight — don't double-connect.
		if h.tunnelActive(name) {
			restored++
			remaining = append(remaining, name)
			continue
		}
		cfg, err := h.userTunnelStore.Load(name)
		if err != nil {
			missing++
			slog.Warn("desired-state: tunnel config missing, dropping",
				"tunnel", name, "error", err)
			continue
		}
		if err := h.doConnectHeld(cfg); err != nil {
			failed++
			slog.Warn("desired-state: restore connect failed; keeping entry for reconnect triggers",
				"tunnel", name, "error", err)
			remaining = append(remaining, name)
			continue
		}
		// Same firewall follow-up a manual/automation connect gets — a
		// headless restore must not skip DNS protection / kill-switch
		// permits (parity with issue #12).
		h.applyPostConnectFirewall(cfg)
		restored++
		remaining = append(remaining, name)
	}

	// Rewrite the file from what should STILL be wanted: restored tunnels
	// plus failed ones (so wake/network triggers retry them), minus tunnels
	// whose configs no longer exist. doConnectHeld's own persists wrote
	// intermediate snapshots without the failed entries; this final write
	// restores them. Skipped when shutdown began mid-restore — cleanup's
	// clearDesiredState then has the last word.
	select {
	case <-h.done:
		return
	default:
	}
	if err := saveDesiredState(h.dataDir, remaining); err != nil {
		slog.Warn("desired-state: final save failed", "error", err)
	}
	slog.Info("desired-state restore complete",
		"restored", restored, "failed", failed, "missing_configs", missing, "total", len(names))
}

// tunnelActive reports whether the manager currently has name connected.

func (h *Helper) tunnelActive(name string) bool {
	for _, st := range h.manager.AllStatuses() {
		if st != nil && st.TunnelName == name && st.State == domain.StateConnected {
			return true
		}
	}
	return false
}
