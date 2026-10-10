package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// Desired tunnel state — the set of tunnels that SHOULD be active, persisted
// across helper restarts so a helper crash doesn't silently drop the user's
// VPN (issue #44).
//
// Background: the tunnel (utun/wintun) lives inside the helper process, so a
// helper crash kills every tunnel with it. After launchd (macOS) or the GUI's
// recovery (Windows/Linux) restarts the helper, every reconnect source was in-memory:
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
//   - Firewall intent rides along: the file also records whether the kill
//     switch and DNS protection were on. Both live only in the helper's
//     memory (the GUI re-sends them after its own connects), so without
//     this a restored tunnel would come back unprotected. Restore puts the
//     kill switch back BEFORE reconnecting, so a restore that fails keeps
//     the blockade the user had instead of leaking.
//   - Automation rules win: restore runs under reevalMu and skips a tunnel
//     whose rule says "off" on the current network, and a rule-driven
//     disconnect withdraws a pending entry.
//   - Restore failures (e.g. no network yet right after a crash-restart)
//     are kept in pendingDesired, so every later write still lists them and
//     the existing wake/network-change triggers retry them; reconnectFn
//     connects them through the full connect path. Retries come from that
//     set only, never from file entries a concurrent Disconnect just
//     dropped. A Disconnect of the same
//     tunnel withdraws the pending entry.
//
// Semantics by exit path:
//
//	helper crash / kill -9 mid-session   → restore (macOS: launchd restart;
//	                                       Windows/Linux: GUI respawn with
//	                                       --restore-desired)
//	crash while the machine is asleep    → restore on launchd restart / wake
//	upgrade ForceShutdown (no teardown)  → macOS: restore; Windows/Linux: the
//	                                       relaunched GUI is a fresh start, so no
//	clean Quit / `wireguide ctl stop`    → no restore (cleanup cleared the file)
//	reboot / power loss                  → no restore (file predates current boot)
//	Windows logoff / Fast Startup        → no restore (fresh GUI start; boot
//	                                       time alone can't tell)

const desiredStateFile = "desired-tunnels.json"

// bootTimeSlack absorbs clock-source skew between a file's mtime (wall
// clock) and the platform boot time (kern.boottime / /proc/uptime /
// GetTickCount64 — wall-clock derived but sampled and rounded differently).
// Two seconds is far below any real power cycle while comfortably above
// sampling noise.
const bootTimeSlack = 2 * time.Second

type desiredStateJSON struct {
	Tunnels       []string `json:"tunnels"`
	KillSwitch    bool     `json:"kill_switch,omitempty"`
	DNSProtection bool     `json:"dns_protection,omitempty"`
}

func desiredStatePath(dataDir string) string {
	return filepath.Join(dataDir, desiredStateFile)
}

// loadDesiredState returns the persisted tunnel names, or nil when absent.
func loadDesiredState(dataDir string) []string {
	return loadDesiredIntent(dataDir).Tunnels
}

// loadDesiredIntent returns the whole persisted intent. A missing file is the
// common case (nothing wanted), not an error; neither is a corrupt file —
// both mean "nothing to restore".
func loadDesiredIntent(dataDir string) desiredStateJSON {
	if dataDir == "" {
		return desiredStateJSON{}
	}
	data, err := os.ReadFile(desiredStatePath(dataDir))
	if err != nil {
		return desiredStateJSON{}
	}
	var st desiredStateJSON
	if err := json.Unmarshal(data, &st); err != nil {
		return desiredStateJSON{}
	}
	return st
}

// saveDesiredState writes names with no firewall intent.
func saveDesiredState(dataDir string, names []string) error {
	return saveDesiredIntent(dataDir, desiredStateJSON{Tunnels: names})
}

// saveDesiredIntent writes sorted, de-duplicated names plus the firewall
// intent atomically (temp file + rename). No tunnels removes the file
// entirely: firewall intent is only restored together with tunnels.
func saveDesiredIntent(dataDir string, st desiredStateJSON) error {
	if dataDir == "" {
		return nil
	}
	st.Tunnels = normalizeTunnelNames(st.Tunnels)
	if len(st.Tunnels) == 0 {
		clearDesiredState(dataDir)
		return nil
	}
	data, err := json.MarshalIndent(st, "", "  ")
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

// persistDesiredState snapshots activeCfgs plus pendingDesired into the
// desired-state file. Called on user-intent transitions (connect success,
// disconnect, rename). An empty snapshot removes the file, so a helper that
// cleanly ends with no tunnels leaves nothing to restore on its next start.
func (h *Helper) persistDesiredState() {
	if h.dataDir == "" {
		return
	}
	var st desiredStateJSON
	if h.firewall != nil {
		st.KillSwitch = h.firewall.IsKillSwitchEnabled()
		st.DNSProtection = h.firewall.IsDNSProtectionEnabled()
	}
	h.mu.Lock()
	for name := range h.activeCfgs {
		st.Tunnels = append(st.Tunnels, name)
	}
	for name := range h.pendingDesired {
		st.Tunnels = append(st.Tunnels, name)
	}
	// A reconnect suspends the firewall and remembers what was on; record
	// that, not the momentary "off" (issue #44).
	st.KillSwitch = st.KillSwitch || h.fwSavedKillSwitch
	st.DNSProtection = st.DNSProtection || h.fwSavedDNSProtection
	h.mu.Unlock()
	h.desiredMu.Lock()
	defer h.desiredMu.Unlock()
	select {
	case <-h.done:
		// Shutdown began: cleanup() owns the file now (it clears it).
		return
	default:
	}
	if err := saveDesiredIntent(h.dataDir, st); err != nil {
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

// pendingDesiredCfgs loads configs for pendingDesired — tunnels a restore
// tried and failed to bring up. It reads the set, not the file: the file can
// briefly list a tunnel a concurrent Disconnect just dropped from
// activeCfgs, and adopting that as pending would undo the Disconnect.
// Pending tunnels whose config is gone from the tunnel store are dropped.
func (h *Helper) pendingDesiredCfgs() map[string]*domain.WireGuardConfig {
	h.mu.Lock()
	candidates := make([]string, 0, len(h.pendingDesired))
	for name := range h.pendingDesired {
		if _, active := h.activeCfgs[name]; !active {
			candidates = append(candidates, name)
		}
	}
	h.mu.Unlock()
	if len(candidates) == 0 || h.userTunnelStore == nil {
		return nil
	}

	cfgs := make(map[string]*domain.WireGuardConfig, len(candidates))
	var dropped []string
	for _, name := range candidates {
		cfg, err := h.userTunnelStore.Load(name)
		if err != nil {
			slog.Warn("desired-state: config no longer loadable, dropping",
				"tunnel", name, "error", err)
			dropped = append(dropped, name)
			continue
		}
		cfgs[name] = cfg
	}
	if len(dropped) > 0 {
		h.mu.Lock()
		for _, name := range dropped {
			delete(h.pendingDesired, name)
		}
		h.mu.Unlock()
		// Rewrite so the same failures aren't re-logged on every trigger.
		h.persistDesiredState()
	}
	return cfgs
}

// withdrawPendingDesired drops a pending (restore-failed) tunnel that an
// Automation rule now wants off, so a later wake retry won't bring it back.
func (h *Helper) withdrawPendingDesired(name string) {
	h.mu.Lock()
	_, ok := h.pendingDesired[name]
	delete(h.pendingDesired, name)
	h.mu.Unlock()
	if ok {
		slog.Info("automation: rule says off, withdrawing pending restore", "tunnel", name)
		h.persistDesiredState()
	}
}

// connectPendingDesired connects one pending tunnel through the same path as
// a restore. It re-checks under connectMu that the tunnel is still pending: a
// user Disconnect may have withdrawn it, or a manual Connect brought it up,
// while this retry waited.
func (h *Helper) connectPendingDesired(ctx context.Context, cfg *domain.WireGuardConfig) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("reconnect %q cancelled before Connect: %w", cfg.Name, err)
	}
	// Checked before connectMu, as in restore: the network lookup shells out.
	if restoreRuleSaysOff(h, cfg.Name) {
		h.withdrawPendingDesired(cfg.Name)
		return nil
	}
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	h.mu.Lock()
	_, stillPending := h.pendingDesired[cfg.Name]
	h.mu.Unlock()
	if !stillPending {
		return nil
	}
	return restoreConnect(h, cfg)
}

// restoreConnect connects one restored or pending tunnel. It runs the same
// firewall follow-up a manual/automation connect gets — a headless restore
// must not skip DNS protection / kill-switch permits (parity with issue #12)
// — then puts DNS protection back if it was on, and tells the GUI the same
// way automation does so it refreshes and re-applies its firewall settings.
// A package var so tests can exercise restore without a real tunnel.
// Caller MUST hold h.connectMu.
var restoreConnect = func(h *Helper, cfg *domain.WireGuardConfig) error {
	if err := h.doConnectHeld(cfg); err != nil {
		return err
	}
	h.applyPostConnectFirewall(cfg)
	if loadDesiredIntent(h.dataDir).DNSProtection && !h.firewall.IsDNSProtectionEnabled() {
		h.restoreDNSProtection(cfg)
	}
	h.server.Broadcast(ipc.EventAutoConnect, ipc.AutoConnectPayload{TunnelName: cfg.Name})
	return nil
}

// restoreDNSProtection re-enables DNS protection on cfg's interface with its
// DNS servers, mirroring what the GUI's SetDNSProtection(true) does after a
// manual connect. Best-effort: a failure is logged, the tunnel stays up.
func (h *Helper) restoreDNSProtection(cfg *domain.WireGuardConfig) {
	if len(cfg.Interface.DNS) == 0 {
		return
	}
	for _, st := range h.manager.AllStatuses() {
		if st == nil || st.TunnelName != cfg.Name || st.InterfaceName == "" {
			continue
		}
		if err := h.firewall.EnableDNSProtection(st.InterfaceName, cfg.Interface.DNS); err != nil {
			slog.Warn("desired-state: restore DNS protection failed", "tunnel", cfg.Name, "error", err)
		}
		return
	}
}

// restoreRuleSaysOff reports whether an Automation rule wants name OFF on the
// current network. Unknown SSID counts as "no verdict", the same guard the
// startup rule pass uses: a none_match rule would otherwise disconnect a
// tunnel before we know which network we're on. A package var for tests.
var restoreRuleSaysOff = func(h *Helper, name string) bool {
	settings, err := h.loadUserSettings()
	if err != nil {
		return false
	}
	settings.EnsureAutomation()
	auto := settings.Automation
	if auto == nil || len(auto.PerTunnel[name]) == 0 {
		return false
	}
	ctx := h.currentNetworkContext()
	if ctx.SSID == "" {
		return false
	}
	return wifi.Evaluate(auto.PerTunnel[name], ctx) == wifi.StateDisconnect
}

// connectUnderKillSwitch is reconnectFn's connect for a cached tunnel while
// the kill switch blockade is up. A package var so tests can observe the
// choice without a real tunnel. Caller MUST hold h.connectMu.
var connectUnderKillSwitch = func(h *Helper, cfg *domain.WireGuardConfig) error {
	return h.doConnectHeld(cfg)
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

	if !h.restoreOnStart {
		slog.Info("desired-state: fresh helper start (not a crash respawn); clearing",
			"tunnels", names)
		clearDesiredState(h.dataDir)
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

	restored, failed, missing, ruledOff := 0, 0, 0, 0
	intent := loadDesiredIntent(h.dataDir)

	// Same lock order as automation (reevalMu → connectMu): no rule pass
	// can interleave with the restore, and one that ran before it already
	// saw these tunnels down, so restore checks the rules itself below.
	h.reevalMu.Lock()
	defer h.reevalMu.Unlock()
	// Rule verdicts are read before connectMu: the network context shells
	// out (gateway MAC, interface IPs), and a GUI Connect/Disconnect must
	// not wait on that.
	ruleOff := make(map[string]bool, len(names))
	for _, name := range names {
		ruleOff[name] = restoreRuleSaysOff(h, name)
	}
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	// Kill switch first: the user had the blockade up, and the crash
	// recovery above removed it. doConnectHeld handles connecting under it.
	if intent.KillSwitch && !h.firewall.IsKillSwitchEnabled() {
		if err := h.enableKillSwitchForActiveTunnels(); err != nil {
			slog.Error("desired-state: restore kill switch failed", "error", err)
		}
	}

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
			continue
		}
		cfg, err := h.userTunnelStore.Load(name)
		if err != nil {
			missing++
			slog.Warn("desired-state: tunnel config missing, dropping",
				"tunnel", name, "error", err)
			continue
		}
		if ruleOff[name] {
			ruledOff++
			slog.Info("desired-state: automation rule says off on this network, not restoring",
				"tunnel", name)
			continue
		}
		if err := restoreConnect(h, cfg); err != nil {
			failed++
			slog.Warn("desired-state: restore connect failed; keeping entry for reconnect triggers",
				"tunnel", name, "error", err)
			h.mu.Lock()
			if h.pendingDesired == nil {
				h.pendingDesired = make(map[string]struct{})
			}
			h.pendingDesired[name] = struct{}{}
			h.mu.Unlock()
			continue
		}
		restored++
	}

	// Rewrite the file from what should STILL be wanted: active tunnels
	// plus pending (failed) ones, minus tunnels whose configs no longer
	// exist. Needed even when nothing connected, to drop missing configs.
	// Skipped when shutdown began mid-restore — cleanup's
	// clearDesiredState then has the last word.
	select {
	case <-h.done:
		return
	default:
	}
	h.persistDesiredState()
	slog.Info("desired-state restore complete",
		"restored", restored, "failed", failed, "missing_configs", missing,
		"ruled_off", ruledOff, "total", len(names))
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
