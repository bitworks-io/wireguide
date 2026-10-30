# Changelog

All notable changes to WireGuide will be documented in this file.

## Unreleased (bitworks fork)

### Added
- **Per-tunnel handshake health check** - each tunnel can override the global handshake health check (use Settings / on / off) from its detail page. The choice is stored in the tunnel's metadata file and applies without reconnecting.
- **Diagnostics bundle** - `wireguide ctl diag bundle [--out path]` and Settings > Logs > "Export diagnostics..." write a zip for bug reports: the helper log tail (last 5 MB) with the rotated-file list and the launchd stderr log, GUI logs, `config.json`, `history.json`, every tunnel `.conf` with `PrivateKey` and `PresharedKey` replaced by `<redacted>` plus the `.meta.json` files, the resolver state (`scutil --dns` and per-service DNS on macOS, `resolvectl status` on Linux, `netsh interface ip show dns` on Windows), the routing table, the WireGuide firewall rules, the Automation preview, a DNS leak test and versions. Key values found anywhere else in the bundle are scrubbed too, and every command is time-limited and non-fatal. The helper's `Helper.Info` and `Firewall.Status` answers are included as `helper-info.json` and `firewall-status.json` (noted as unavailable with an older helper). A new read-only helper RPC `Diag.Snapshot` (IPC protocol 1.8, additive) supplies the pf anchors on macOS and the nft tables on Linux; with an older helper that section is recorded as unavailable.
- **Inline DNS diagnostics in the config editor** - the editor flags invalid or risky `DNS =` lines as you type (global DNS outside the tunnel's routes, `.local` split domains, split DNS on Windows or without systemd-resolved, missing reverse zones, LAN-only routes with no DNS) with one-click fixes, hover help on the `DNS` key and `~domain` entries, and `DNS =` value completion (gateway and reverse zones derived from AllowedIPs, split-DNS template). Diagnostics never block saving. New-tunnel templates show both DNS modes as commented lines.
- **Shared interface Address warning** - importing or saving a tunnel whose interface `Address` is also used by another saved tunnel now shows a non-blocking warning (also in the editor and in the zip import result). Connecting a tunnel whose Address matches a currently connected tunnel shows it in the conflict dialog, with a "Disconnect X and Connect" shortcut. Nothing is disconnected automatically.
- **Verify** - a manual "Run checks" panel on a connected tunnel (and `wireguide ctl verify <name>`) that checks the last handshake, that each AllowedIPs prefix is routed through the tunnel interface, and that every split-DNS / search domain has the tunnel's resolver registered, plus an optional ping and name lookup. Read-only, runs only on request, every probe capped at 3 s. A prefix that overlaps your LAN is still checked and carries an amber note.
- **Per-domain split-DNS rows and "Try a name"** - the DNS leak test lists each `~domain` with the resolver the system routes it to (from the same check that reports missing domains), and can resolve a name through the system resolver path so supplemental resolvers are honoured. A short note explains that dig/nslookup bypass them on macOS.
- **DNS-mode chips** - the tunnel header and list rows show whether a tunnel replaces system DNS, uses split DNS or only sets search domains; `ctl status` prints `dns=`, and the tray tooltip appends the mode.
- **DNS protection status** - Settings > Advanced shows what DNS protection is actually letting through ("Currently allowing: 1.1.1.1 (home-vpn) on all interfaces"), why it is not applied, or the error that stopped it; on macOS this is read back from pf rather than from the helper's bookkeeping. The tunnel header adds "DNS protected" / "intended, not applied" next to the DNS-mode chip, and a banner appears when protection is on but its rules keep failing to apply. New read-only `Firewall.Status` helper method (IPC 1.10).
- **Pre-connect preview** - a collapsible "What will change when you connect" section above the stats on a disconnected tunnel: whether DNS is replaced system-wide, split to specific domains or only gets search domains, which AllowedIPs are routed, a warning for any range that overlaps your current network (it is still routed, and automation will not auto-connect that tunnel), and "Connecting will FAIL" when the config uses split DNS this platform cannot apply (Windows, Linux without `resolvectl`).
- **Automation status strip** - the Automation editor now shows the network the engine sees and, per tunnel, what the rules decided and why (connect, stay off, on hold, paused by a manual override, blocked by the routing-loop watchdog, or skipped because AllowedIPs overlap the LAN). The same one-liner appears as a chip on the tunnel detail card and tunnel list rows. The helper's `Automation.Preview` reports `blocked` for watchdog-blocked tunnels (IPC protocol 1.6).
- **Precise macOS Location Services state** - the Wi-Fi permission banner and the strip now say whether Location Services is denied, restricted or not yet allowed instead of guessing.
- **Notifications for automatic tunnel changes** - macOS and Linux show a native notification when a tunnel connects or disconnects without a connect or disconnect made in the app (automation, wake, health-check recovery, the CLI), when the helper's loop watchdog disconnects a tunnel, and on helper errors. Changes you make from the window or tray, and the disconnects on quit, never notify. Turn it off with "Notify on automatic tunnel changes" in Settings. If the system notification service is unavailable, macOS falls back to AppleScript notifications. A rule-driven connect or disconnect names the deciding rule (localized from your rules when they have not changed since) and the Wi-Fi network, and each change notifies once whichever of the helper's events and the status update arrives first. Held, paused and skipped decisions never notify. Helper errors with a known cause (DNS protection rules failing to apply, helper not responding) use the same translated text as the in-app banner, and a helper that stops responding now also notifies. A forced "Reset DNS & firewall" counts as your own disconnect.
- **Automation decision events** - the helper now broadcasts `event.automation` (IPC protocol 1.7) for every executed rule-driven connect or disconnect, including failures, and for held, latched and LAN-overlap-skipped decisions when they change for a tunnel. Each event names the deciding rule, the SSID and whether the network had settled. The GUI forwards it as the `automation_event` frontend event; `event.automation_skipped` is unchanged.
- **Per-tunnel rules log** - `automation: rules loaded` is logged once per tunnel whenever that tunnel's rules change.
- **`wireguide://` URL scheme (macOS)** - `connect/<name>`, `disconnect/<name>` and `show` let Shortcuts, Raycast or a shell drive the app (see README for a Shortcuts recipe). Tunnel names are validated and matched exactly against saved tunnels, connect/disconnect always show a confirmation sheet in the window (even when WireGuide is frontmost), and a URL can never import, delete or modify a config. A confirmed connect takes the normal Connect path, including the manual override for automation rules. Windows and Linux are not wired up yet.
- **Helper status and Repair** - Settings > Advanced has a Helper card (version, start mode, socket, process ID, start time, whether the app is attached) backed by a new read-only `Helper.Info` request (IPC 1.9; older helpers fall back to Ping). **Repair helper...** reinstalls the helper on request, after a confirmation and WireGuide's own explanation of the administrator prompt; it is refused while a tunnel is connected, wanted or pending restore, and never touches saved state. The helper-unavailable banner now offers Repair instead of "quit and reopen".
- **Automation: Wi-Fi name lists and connection type** - a Wi-Fi name condition can list several networks ("is any of" / negated "is none of"), and a new connection-type condition matches Wi-Fi, wired or tethered (iPhone/iPad USB, Bluetooth PAN, RNDIS) uplinks. Negated connection-type rules wait for the network to settle like other negated rules. Connection type is detected on macOS and Linux; on Windows it is unknown, so these rules never match there. CLI: `ssid:A|B`, `not-ssid:A|B`, `medium:wired`, `not-medium:wifi`. `Automation.Preview` reports the detected connection type (IPC protocol 1.11).
- **Automation: undo and rule history** - removing a rule in the editor shows "Rule removed - Undo" for 5 seconds. "Restore previous rules…" lists the last five saved states of the rules (time and rule count for the tunnel) and restores one through the normal validated save. Snapshots are taken whenever config.json's rules change, including edits made with `wireguide ctl`, and are kept in `automation-history/` next to config.json. The app also notes when a tunnel's rules were changed outside it.
- **Reset DNS & firewall** - an escape hatch in Settings > Advanced and `wireguide ctl reset-dns [--force] [--kill-switch-off] [--json]` (new `Network.ResetDNS`, IPC 1.12). It removes WireGuide's firewall rules and split-DNS entries, retries any retained DNS recovery immediately and flushes the DNS cache, reporting each step. It is refused while a tunnel is connected, wanted or pending restore (unless forced, which disconnects them as an explicit Off) and while the kill switch is on (unless asked to turn it off). Recovery journals are kept unless their cleanup actually succeeds.
- **Connection change reasons and history start reason** - the helper status now says why each tunnel came up (`last_change_reason`: user, automation, wake, network change, health check, reconnect, recovery) and, for about a minute, why a tunnel went down (`recent_disconnects`, including the routing-loop watchdog). IPC protocol 1.13, additive. Connection history records what started each session and the Wi-Fi network it started on, and shows the helper's own reason for how a session ended (for example an automation rule or the routing-loop watchdog) instead of a generic "Reconnected".
- **Startup recovery notice** - when the helper starts after a previous helper process stopped unexpectedly and cleans up what it left behind, the app shows a dismissible notice, once per helper start, listing the tunnels whose leftover network settings were removed, the tunnels whose DNS changes were restored, and whether leftover WireGuide firewall rules were removed (macOS, where the rules are read back from pf before and after recovery). Reported through an optional `recovery` object on `Helper.Info` (IPC protocol 1.14, additive).

### Changed
- **Helper log rotation** - the helper now writes `/var/log/wireguide-helper.log` itself through a size-based writer (10 MB x 5 files, `.1`-`.5`) instead of leaving launchd to append to it forever; an oversized log from before the upgrade is rotated at the first start. Identical wireguard-go warnings (for example "network is unreachable") are logged once per 60 s with a `suppressed_repeats` count, in the file and in the in-app log viewer. The LaunchDaemon plist's stdout/stderr now go to `/var/log/wireguide-helper.stderr.log` (panics and runtime output only), so the helper is reinstalled once on update, as with any plist change. On Windows, `WIREGUIDE_HELPER_STDERR=1` now writes a rotated `helper-stderr.log` plus `helper-stderr.panic.log` for runtime crashes.
- The DNS protection setting hint now notes that tunnels using split DNS or no DNS keep system DNS and are not affected.
- **Automation toast** - the raw "Wi-Fi: <name>" toast on every network change is gone: the Automation status strip shows the network, and "Automation connected <tunnel>" appears when an automation rule connects a tunnel.
- The Automation status strip stops polling while the window is hidden to the tray and refreshes as soon as it is shown again.
- **macOS login items** - the helper LaunchDaemon and the auto-start LaunchAgent now declare WireGuide as their app (`AssociatedBundleIdentifiers`), so System Settings > Login Items & Extensions attributes them to WireGuide instead of an unidentified developer. An existing auto-start entry is refreshed at launch (only if it still points at this app); the helper plist change causes one reinstall alongside the next update.
- **macOS administrator prompt** - a short dialog now explains why the password is needed (installing or repairing the VPN helper) just before macOS asks for it, in English, Korean, Japanese or Simplified Chinese. Cancel behaves like cancelling the password prompt.

### Fixed
- **Connection history byte totals** - sessions no longer record 0 B (or only the bytes since the last reconnect) when a tunnel briefly reports zeroed counters while connecting or disconnecting, or when a reconnect restarts the counters. A stale snapshot from a tunnel that never opened a session is no longer added to its next session.
- **Handshake health check after sleep** - time spent asleep (or offline, on macOS) no longer counts as a dead handshake. The check pauses for 90 seconds after a wake, measures handshake age from the wake when the last handshake predates it, skips while macOS reports no primary network interface, and no longer starts a per-tunnel reconnect while a wake or network-change reconnect (or an earlier retry for that tunnel) is still in progress, so DNS protection and the kill switch are not suspended by overlapping retries.
- **Tunnels that never handshake** - with the handshake health check on, a connected tunnel that has sent traffic but never completed a handshake (peer down, stale DDNS address) is now reconnected after 180 seconds, then with exponential backoff (up to 48 minutes) until a handshake completes or the tunnel is disconnected. A tunnel that has sent no traffic is left alone, as before. On the WireGuardNT engine this relies on its transmit counter including handshake initiations; if it does not, such tunnels keep the previous behaviour.

### Upgrade notes
- Rule lists that use Wi-Fi name lists or connection type are stored under `per_tunnel_rules_v3`, so 0.6.1 and earlier ignore them entirely instead of misreading part of a list. Because an older version drops them whenever it saves settings, they are also copied to a separate `config.json.automation-v3-backup` that older versions never read, change or remove. If an older version dropped them, Settings offers to restore them for tunnels that have no rules. The existing `.automation-v2-backup` for negated rules is unchanged.

## [0.6.1] - 2026-10-26

### Added
- **Optional Windows kernel engine (#59)** - select the official WireGuardNT backend in Settings. The existing userspace engine remains the default. Switching engines while connected requires confirmation and a reconnect.
- **Linux RPM packages (#47)** - native amd64 and arm64 packages, distribution-appropriate dependencies, and package-format selection in the update checker.
- **Simplified Chinese (#58)** - translated application settings and Windows native interface text.

### Changed
- **Desktop dependencies (#61)** - update Wails and its JavaScript runtime to beta.34, Go to 1.26.10, Node.js to the current 24 LTS patch, and frontend/build dependencies. The Go update fixes a reachable certificate-verification vulnerability; wireguard-go includes the latest handshake and IPv6 length fixes.
- **Linux desktop** - move to GTK4 and WebKitGTK 6.0, adapt connection icons, and restore the main window when the StatusNotifier tray icon is activated.

### Fixed
- **WireGuardNT configuration** - preserve IPv4-mapped IPv6 AllowedIPs and scoped IPv6 endpoint addresses; keep adapter-handle access synchronized and retry configuration snapshots safely.
- **Windows packaging** - bundle the official WireGuardNT runtime and license, and refresh the vendored runtime when its architecture or pinned version changes.

### Upgrade notes
- **Linux now requires GTK4 and WebKitGTK 6.0**, available on Ubuntu 24.04+ and Debian 13+. Older GTK3-only installations must upgrade their distribution before installing this release. The tray uses the session D-Bus StatusNotifierItem interface.
- Existing Windows installations continue to use wireguard-go unless the kernel engine is selected. macOS 12 remains supported; the Go toolchain stays on the 1.26 patch line to retain that baseline.
- macOS applications remain ad-hoc signed. Windows Authenticode signing depends on SignPath availability. Every release publishes SHA256SUMS and an Ed25519 signature for verified in-app updates.

### Verification
- CI covered Windows and macOS tests, production Windows installer and macOS bundle builds, and Linux amd64/arm64 race tests, isolated nftables recovery, native GTK4/Xvfb icon and webview event checks, D-Bus tray activation, DEB/RPM inspection, and Fedora RPM installation.
- Native Windows 11 checks covered both VPN engines with HTTPS, DNS protection and kill-switch blocking/recovery, plus the actual application window, settings persistence through restart, UI-driven connection, and close-to-tray/window restoration without interrupting the VPN. Original user settings and tunnel configurations were restored unchanged.
- Windows ARM64 was cross-built; physical ARM64 Windows, Linux Wayland desktop behavior and a new end-to-end installed-upgrade cycle were not exercised in this release's runtime checks.

## [0.6.0] - 2026-10-21

### Added
- **Verified in-app updates (#36)** — direct-download macOS apps and installer-managed Windows apps can download, verify the Ed25519-signed checksums and artifact version, install, and relaunch. Homebrew installations continue to update through Homebrew; unsupported layouts retain the releases-page fallback.
- **Split DNS** — `~domain` entries route matching names to macOS supplemental resolvers or Linux systemd-resolved. Unsupported configurations fail before network changes instead of silently ignoring the requested DNS behavior.
- **Automation rules** — negated SSID/subnet/gateway-MAC conditions, a network-settle window, and explicit manual On/Off overrides. Extended rules are backed up for downgrade recovery.
- **Connection indicators** — connected VPNs display a green indicator on the macOS Dock and Windows taskbar icons.

### Fixed
- **macOS sleep and helper recovery (#41, #44)** — restore wanted tunnels and protection after an unexpected helper restart, handle wake/network changes, and avoid repeated background elevation. Current helper installations use launchd socket activation without an administrator prompt on ordinary relaunch; installation, upgrades and repairs can still require authorization. Disabled background items direct users to System Settings.
- **GUI shutdown** — remove a native event-delivery deadlock that could prevent macOS updates from quitting and relaunching. Keep the helper control connection alive while idle, restore hidden/minimized windows through a second launch, and respect canceled Windows session-end requests.
- **DNS and firewall protection (#48)** — rebuild per-resolver rules for all active tunnels, preserve sibling traffic and original DNS/search settings, replace Linux nftables rules atomically, and retain independent PF ownership across repair and cleanup. On macOS, evaluate DNS restrictions before kill-switch tunnel-wide permits so enabling both protections cannot bypass the configured resolver list.
- **Endpoint-loop safety (#49)** — forced disconnects now perform helper teardown, remove stale permits and wanted state, and prevent automatic restoration until a successful manual reconnect. Repair endpoint bypass routes safely and preserve Windows interface binding when its socket is recreated.
- **macOS menu and Dock icons (#45, #46)** — use native menu ownership and template rendering, remove the faint menu-bar frame, and preserve the Dock icon's original size and padding when adding its green badge.
- **Profiles and interface** — harden concurrent file operations and imports, preserve per-field edits and errors, clarify protection/update status in English, Korean and Japanese, and fix Windows tunnel recognition in route diagnostics.

### Upgrade notes
- Back up your tunnel configurations before downgrading. Older versions do not understand the extended automation rules; see the README's downgrade recovery instructions.
- Closing the window keeps the app in the tray. Explicit Quit or `wireguide ctl stop` shuts down the helper and tunnels. A clean quit or reboot does not restore an old connection; an unexpected same-boot helper restart can.
- macOS builds remain ad-hoc signed and Windows signing remains subject to SignPath availability. SHA256SUMS and its Ed25519 signature are published for every release.

### Verification
- Windows 11 runtime checks covered VPN lifecycle, protection, automation, pinned-socket port changes and signed in-app updates. macOS 26.4.1 arm64 checks additionally covered actual sleep/wake, Wi-Fi recovery, native PF/DNS packets, helper crashes and direct/Homebrew updates. Detailed scope is recorded in `docs/analysis/macos-native-verification-20261015.md`.
- Other macOS versions, multi-display rendering, overnight standby and every physical-network combination are not established by these runs. The historical macOS 27 hang remains under investigation.

Thanks to the contributors and reporters behind #41, #44–#46 and #50–#53.

## [0.5.2] - 2026-09-15

### Added
- **Reconnect on ping failure (#42)** — optional per-tunnel health checks with up to five IPv4/IPv6 targets, configurable check intervals and consecutive-failure thresholds. Reconnection starts only when every target fails, with a cooldown to avoid repeated reconnect loops. Monitoring is disabled by default.

### Fixed
- **macOS helper recovery (#41)** — hardened helper installation, startup and crash recovery; avoid repeated authorization attempts during recovery, detect unresponsive helpers, and show actionable errors. These changes address concrete recovery defects; the original reporter's exact failure has not been reproduced locally.
- **Reconnect cancellation** — disabling monitoring, changing targets, renaming/deleting a profile or manually disconnecting prevents stale ping retries from reconnecting the tunnel.
- **Monitor lifecycle** — serialize concurrent start/stop operations so a new monitor cannot reuse channels or worker state before the previous shutdown finishes.
- **macOS updates** — Homebrew-compatible macOS/architecture requirements and install steps. In-app updates verify the installed version, then wait for normal app shutdown before relaunching the updated app.
- **Packaging** — Linux desktop/DEB metadata and AppImage build fixes, including rejecting stale output; corrected Windows MSIX architecture metadata and IPv6 interface selection.
- **Error messages** — native validation errors display readable text instead of serialized JSON.

### Upgrade notes
- **Homebrew users upgrading from 0.5.1 or earlier:** quit and reopen WireGuide once after the upgrade to run the new version. Those older clients rely on the cask's removed restart hook; automatic in-app restart is handled by WireGuide starting with 0.5.2.
- Terminal `brew install` / `brew upgrade` no longer force-close or automatically launch WireGuide. Restart a running app after upgrading it.

## [0.5.1] - 2026-08-11

Patch release: the in-app "Update Now" button is now trustworthy on macOS. If you are on 0.5.0 via Homebrew, this is also the first update the button itself should complete cleanly end-to-end.

### Fixed
- **macOS "Update Now" (issue #38)** — the in-app update can no longer report success without actually installing: after `brew upgrade` exits, the installed bundle's version is verified against the release it claimed to install, progress phases ("refreshing" / "installing") are shown in the banner and About panel, and failures surface inline instead of vanishing behind a relaunch. Also survives Homebrew 6's tap-trust gate (`untrusted tap` errors trigger a `brew trust` + one retry) and skips the redundant `brew update` (`HOMEBREW_NO_AUTO_UPDATE=1` — the checker already knows the target version).
- The Homebrew cask itself dropped `auto_updates` (korjwl1/homebrew-tap), so bulk `brew upgrade` no longer skips WireGuide — the root cause of months of silent non-updates.

## [0.5.0] - 2026-08-10

Linux graduates to a supported platform, the CLI learns to start and stop the app, and the Windows helper's IPC surface is locked down to the launching user. Verified on all three OSes before release: a full runtime pass on Windows 11 against a real tunnel (helper IPC, multi-tunnel, kill-switch cycles, CLI lifecycle, tray), the Linux plan in `docs/linux-test-plan.md` on Debian 13 / Raspberry Pi OS ARM64, and the macOS DNS/lifecycle fixes below.

### Added
- **Linux support** — tested and hardened end-to-end on Debian 13 / Raspberry Pi OS ARM64 (Wayland and X11): window decorations restored after tray-restore, gateway/physical-interface detection fingerprints the right network (issue #22), routine RTNETLINK traffic no longer registers as a primary-network change (reconnect decisions compare real default-route snapshots), nftables kill-switch fixes, DEB packaging via nfpm.
- **`wireguide ctl start` / `ctl stop`** — explicit app lifecycle from the CLI. `start` launches the app detached and waits for the helper (long deadline: the macOS admin prompt has no timeout of its own; on macOS it launches its *own* bundle rather than whatever LaunchServices resolves); `stop` quits GUI and helper together and confirms they actually went away. Deliberately the only commands that start anything — `connect`/`status` still refuse rather than boot a VPN stack behind your back.
- **`--json`** on `ctl status` and `ctl list` for scripts and coding agents.
- **CI: 3-OS test matrix** (Linux/macOS/Windows) on every PR; release workflow untouched.

### Security
- **Windows helper pipe scoped to the spawning user (issue #20)** — the named pipe's ACL now grants access to the launching user's SID instead of every interactive user, and each connection's peer SID is verified against it (SYSTEM and a helper spawned without the SID keep working). Verified live on Windows 11 by reading back the pipe's security descriptor.

### Fixed
- **Windows multi-tunnel** — connecting a second tunnel no longer fails on the Wintun adapter name collision; each tunnel gets its own `WireGuide-<id>` adapter, and multi-tunnel status reports per-tunnel interface/duration/traffic instead of zeroed copies.
- **Helper lifetime** — the helper never runs at boot and its lifetime is tied to the GUI: a 60 s startup grace covers a helper whose GUI never attaches (login-autostart with an unanswered UAC prompt no longer leaves an invisible elevated process), and a teardown that leaves no tunnels and no GUI re-arms the shutdown grace window — closing the orphan-helper hole that transient CLI connections opened (a GUI-less `ctl disconnect` of the last tunnel previously left the elevated helper alive until reboot). CLI clients are excluded from connection-lifecycle tracking by design.
- **Kill switch** — rebuilt atomically around every connect/disconnect from actual manager state; a failed connect restores the blockade instead of leaving it half-applied.
- **macOS DNS teardown (issue #34)** — search domains, services added mid-session, and the failed-verify / ForceShutdown paths now all restore DNS.
- **macOS updates (issue #38)** — "Update Now" runs `brew upgrade --greedy` so cask-held updates can't silently no-op.
- **Diagnostics (issue #32)** — ping parsing is locale-agnostic (Korean Windows included), and unreachable hosts report as unreachable instead of a fabricated wall-clock-derived latency.
- **Automation** — rules are validated on save: a malformed CIDR or MAC is rejected with a clear error instead of being written and silently never matching.
- **Idle efficiency** — Wi-Fi polling backs off to 60 s while native change notifications are attached; config-file watching drops from 1 s to 3 s; endpoint-latency logging demoted to debug.

### Removed
- Key generator, CIDR calculator, speed test, mini mode, and the split-tunnel UI stub — dead or abandoned surfaces found in the audit sweep (#35); their bindings and i18n strings went with them.

## [0.4.2] - 2026-07-27

**Urgent fix release for Windows users.** 0.4.1 and earlier shipped with a tray that could permanently lose the main window and an installer that cannot upgrade in place while the app is running. Windows users should update; to get past the installer bug one last time, run `taskkill /F /IM wireguide.exe` from an elevated terminal before launching the 0.4.2 installer. macOS and Linux are unaffected by the tray-window bug (Linux picks up the same Show Window fix), and nothing else changed.

### Fixed
- **Windows tray, issue #30** — left-clicking the tray icon now shows the main window (the platform convention; previously a no-op), and the "Show Window" menu item actually works: it was wired to a macOS-only implementation, so on Windows **a window closed to the tray could never be reopened** — the only recovery was killing the process. The tray menu also showed stale connection state (○ while connected) because menu refills never reached the Win32 popup; the menu now rebuilds through `SetMenu` on every change. macOS behavior is unchanged; Linux gains the same Show Window fix.
- **Windows installer, issue #29** — upgrading by running the installer while WireGuide was running failed with "Error opening file for writing: wireguide.exe" (the GUI and the elevated helper are the same executable, and Windows locks running images; the helper deliberately outlives the GUI, so quitting the tray app wasn't enough). The installer and uninstaller now terminate running instances before touching files. **This fix takes effect when the 0.4.2 installer runs — upgrading *to* 0.4.2 still hits the old installer's bug**, hence the elevated `taskkill` workaround above.

## [0.4.1] - 2026-07-27

### Fixed
- **Automation (GUI), issue #27** — creating or editing rules in the Automation editor was effectively impossible in 0.4.0: the editor's own autosave re-fired the config watcher, and the resulting reload wiped the just-added row before it could be filled in (and could transiently delete a rule being edited). The editor now ignores its own writes (reloading only when the file genuinely changed externally), a blank draft row is no longer autosaved, and a rule that is momentarily incomplete mid-edit keeps its last saved value on disk instead of being deleted. External edits (`wireguide ctl`, another window) still appear live.
- **Automation (GUI)** — per-tunnel rule saves now go through the cross-process-locked settings update instead of a whole-settings overwrite, so a GUI rule edit can no longer clobber a concurrent `wireguide ctl` change to any other setting (and vice versa); condition labels survive the GUI round-trip; a dash- or bare-hex-formatted gateway MAC written by the CLI is no longer treated as a foreign change.
- **Windows (dev):** `go test ./internal/ipc` no longer fails/panics when run unelevated — the tests accept the test binary's own pipe (test builds only; the production SY/BA pipe-owner check is unchanged) (#24).

## [0.4.0] - 2026-07-15

### Added
- **Automation** (issue #12) — per-tunnel `condition → action` rules that connect or disconnect a tunnel based on the network you're on. Conditions: Wi-Fi SSID, subnet (CIDR), or the default-gateway MAC (a precise, medium-agnostic network fingerprint that tells apart networks sharing a subnet); action: connect/disconnect. Rules are ordered by priority (drag-to-reorder, first match wins) and evaluated entirely in the helper via a hybrid trigger (macOS route-monitor subscription; 30 s poll on Windows/Linux). Replaces the legacy per-tunnel Wi-Fi auto-connect / trusted-SSID UI (migrated automatically). Editable in the GUI or via the CLI.
- **Command-line interface** `wireguide ctl` (issue #10) — a third IPC client alongside the GUI (Tailscale-style): `status`, `list`, `connect`, `disconnect`, `import`, `rename`, `delete`, and `automation add/rm/rules` + a read-only decision preview. No per-command sudo, cross-platform, shares the GUI's tunnel store.
- Tunnel-list **sorting** (name / last used / date added, active-on-top) and **compact mode** (issue #16, #17); **drag-resizable** tunnel-list column.

### Fixed
- **update:** the Ed25519 signature is now bound to the hash actually installed (a repo-write attacker could previously pass both checks by swapping SHA256SUMS between check and download); `Install` also enforces `SignatureVerified` in signed-update builds.
- **Windows:** `findInterfaceMTU` buffer overflow + wrong `NlMtu` offset (undefined behaviour on every no-MTU connect; auto-MTU always fell back).
- **Linux:** split-tunnel routes were deleted from the wrong table on the default `Table=auto` path (route leak); DNS search-domain injection; nft kill-switch endpoint-port validation and `oifname` consistency.
- **macOS:** `route -n monitor` subprocess is now supervised (was a silent zombie + stuck monitor on unexpected exit); the tray menu-bar icon uses native click-to-open (fixed the "does nothing on macOS 26" report, issue #18) and follows the menu bar's actual appearance; the connect/Disconnect-race no longer holds `Manager.mu` across slow teardown.
- **storage:** reject case-collisions and Windows reserved names; fsync the parent directory after atomic writes; latency-probe target validation; meta-sidecar lost-update race.
- **Automation (code review, issue #12):** `else`/none_match now matches at its own position so drag-to-reorder priority is uniform (was always held to the end); malformed conditions and unknown actions now fail closed (rule skipped) instead of an unknown action defaulting to connect; a rule-driven connect now runs the same DNS-protection + kill-switch folding as a manual connect (headless automation could previously connect with no protection, or fail entirely under an already-on kill switch), and a rule-driven disconnect strips the tunnel from the kill-switch filter set; macOS no longer overwrites the GUI-reported SSID with an empty root-helper poll (which silently broke SSID rules); Windows gateway-MAC resolves the physical underlay gateway (excluding the WireGuard adapter) so a full tunnel no longer blanks the fingerprint and flaps `mac:` rules; tunnel rename/delete now carry/drop the tunnel's automation rules instead of orphaning them; the rule editor no longer races a debounced save against a tunnel switch. *(Windows gateway change compiles but is unverified on a Windows build.)*
- **config.json:** cross-process read-modify-write is now atomic (file lock) so a `wireguide ctl` edit and a GUI edit can't clobber each other.
- **CLI (issue #10):** `import`/automation edits work on a fresh install (dirs created); `set` exits nonzero when the helper is running but the live apply fails; `delete` refuses to remove a still-connected tunnel whose disconnect failed; `install-skills` writes agent files atomically. The NSIS installer PATH edit no longer interpolates the install path into a PowerShell command (injection), and the macOS cask + Windows installer put `wireguide` on `PATH`.
- **list:** date-added sort now uses a stamped creation time (survives edits) instead of the `.conf` mtime (issue #17).

### Changed
- Latency probe no longer fabricates a `x.x.x.1` gateway target (issue #15); per-tunnel latency target added.

## [0.3.1] - 2026-05-26

### Added
- **Full-tunnel routing-loop protection (Windows + macOS)** — multi-layer defense against the encrypted-UDP-loops-through-tunnel-adapter class of bug (issue #14).
  - Windows: WFP block at `ALE_AUTH_CONNECT_V{4,6}` + `OUTBOUND_TRANSPORT_V{4,6}` layers, iphlpapi-based `/32` bypass host route with `InitializeIpForwardEntry`, `IP_UNICAST_IF` UDP socket binding with `NotifyRouteChange2`-pushed re-pin monitor, runaway-TX watchdog with sustained-asymmetry trip.
  - macOS: `/32` bypass installed before `/1` split routes with fail-fast preflight on missing default gateway, 5 s underlay-detection retry, blackhole fallback on gateway loss inside `reapply` to keep the loop class contained when the upstream gateway briefly disappears, runaway-TX watchdog via `netstat -ibnI`.
- **SignPath Foundation code signing** — CI hooks for SignPath OSS signing of the Windows installer; gated on the foundation's onboarding approval. Releases ship unsigned until then.

### Fixed
- Helper now exits within ~20 s of the GUI dying (was ~70 s) — IPC read deadline trimmed to 10 s now that the GUI's 5 s health-monitor ping cadence is the canonical liveness signal.
- macOS: `RestoreDNS` no longer fires a noisy `netsh`-equivalent against an adapter that's already been detached from the IP stack during disconnect.
- macOS: `getDefaultInterface()` now parses the `netstat -nr` header dynamically; previously the "first lowercase field" heuristic could misidentify `awdl0` (AirDrop) as the default interface on some machines.
- Windows: UAPI listener "may not work" warning downgraded to DEBUG on Windows — the named-pipe bind is expected to fail because the helper runs as an elevated user rather than as `LocalSystem`; status queries route through the in-process `Engine.IpcGet` regardless.

### Changed
- CI release notes generated by `git-cliff` (fuller diffs than the previous auto-generated body).
- CI: explicit NSIS install on Windows runners (the default Windows-latest image no longer carries `makensis` on PATH).
- CI: `Get-FileHash` / `Expand-Archive` in the wintun vendoring step replaced with direct .NET APIs to avoid PowerShell version skew on the runner.
- README: `Install` section moved above `Features`, code-signing dev-process notes trimmed to user-facing status only.

## [0.3.0] - 2026-05-25

### Added
- **Windows kill switch via WFP** — Windows Filtering Platform-based kill switch that survives helper restarts; complements the existing macOS `pf` and Linux `nftables` implementations.
- **Periodic auto-update scheduler** — background check for new releases on a configurable cadence (default 24 h with focus-opportunistic refresh), separate from the existing manual "Check for updates" path.
- **CI release pipeline** — automated darwin (arm64) + Windows (amd64/arm64) builds on tag push, with SHA256SUMS, Ed25519 signature, and `homebrew-tap` cask auto-bump.

### Fixed
- macOS kill switch: `pf` anchor renamed from `com.apple.wireguide` (dot) to `com.apple/wireguide` (slash) so it actually matches the `anchor "com.apple/*"` wildcard in the system `/etc/pf.conf` — previously the rules loaded without ever being evaluated.
- macOS kill switch can now be toggled on without an active tunnel (base block-all set installs cleanly; per-tunnel permits are folded in on subsequent connects).
- Windows disconnect: lingering wintun adapter "defanged" (DNS cleared, metric bumped) before `engine.Close`, so the brief window where Windows still treats the dying adapter as a viable metric-1 path doesn't dump every DNS query onto its dead `8.8.8.8` binding.
- Windows disconnect: dead 12 s DNS-restore call removed; `netsh` output now decoded as the OEM code page so Korean / non-English Windows installs no longer mis-parse error messages.
- Windows: UAPI bypass (status queries served by in-process `Engine.IpcGet` rather than the named pipe that the elevated helper can't bind under the kernel's owner-SID requirement).
- Windows: suicide-reconnect / orphaned `conhost` / dangling route fixes from the WFP kill-switch rework.
- DNS protection regression introduced during the periodic-update-scheduler refactor.
- Numerous race conditions, leak fixes, and audit findings from the cross-platform hardening pass.

### Changed
- Tray and taskbar icons: rounded silhouette via custom genicon (matches the macOS dock icon's visual weight).
- Sidebar dividers, tool pages, and drop affordance polished.
- Settings: maintainer credit added in footer; helper SIGTRAP fix.
- Rebrand: WireGuide red accent + Material-style flat buttons.

## [0.2.0] - 2026-05-05

### Added
- **Wi-Fi auto-connect rules** — per-tunnel SSID-based auto-connect/disconnect; rules fire in the helper so they work even when the GUI is quit
- **Trusted SSID support** — designated SSIDs auto-disconnect all VPN tunnels (home/office network detection)
- **macOS 14+ Location Services integration** — CoreWLAN CGo replaces `networksetup` for SSID detection; app now appears in System Settings → Location Services
- **GUI→Helper SSID forwarding** — on macOS 14+ the helper (root LaunchDaemon) cannot read SSID itself; the GUI polls via CoreWLAN and forwards changes over IPC so auto-connect rules fire correctly
- **Ed25519 signature verification** — auto-update downloads verified against a Ed25519 signature over SHA256SUMS; embedded public key prevents tampered binaries from being installed

### Fixed
- Wi-Fi auto-connect status not updating in GUI/tray after rule fires (`ActiveTunnels` now populated in all status broadcasts)
- `autoConnectedBy` accessed under wrong mutex in `handleRename` (race condition; changed to `wifiMu`)
- Lock ordering violation between `handleRename` and `handleSSIDChange` that could cause deadlock
- Kill switch and DNS protection handlers using `Status().State` instead of `IsConnected()` (broke in multi-tunnel setups where the primary was not the connected tunnel)
- `handleReportSSID` panic on nil `wifiMon` (non-darwin builds and pre-init race)
- `sleep_darwin.go` unsafe.Pointer misuse flagged by `go vet`; replaced with `runtime/cgo.Handle`
- Duplicate SSID appearing in Wi-Fi rules dropdown when current SSID matched a saved rule

### Changed
- Auto-connect logic moved to helper process (was frontend-side) so rules fire independently of GUI lifecycle
- `postConnectRefresh` refactored: `refreshTunnels`+`refreshStatus` kept for manual connect UX; auto-connect path calls only `applyFirewallSettings` (event stream handles status update)
- Dead backward-compat fallback in `subscribeToEvents` removed (active_tunnels now always populated)

## [0.1.9] - 2026-05-05

### Changed
- Removed Wi-Fi rules master toggle; trusted SSIDs are always active when configured

### Fixed
- Various regressions, lifecycle, and performance issues from audit rounds (Round 2, Round 3)
- 30+ fixes from full-codebase review (null guards, lock safety, error propagation)

## [0.1.8] - 2026-04-13

### Changed
- Sidebar navigation: removed Tools tab bar, DNS Leak Test and Route Table are now direct sidebar sub-items
- Settings modal: fixed size regardless of active tab (no more resize when switching to Advanced)
- Settings sidebar active state: tint highlight instead of solid blue (macOS HIG)
- Dropdown controls: custom styled per macOS HIG (28px height, 6px radius, theme-aware chevron)

### Improved
- Route table: sticky column header, legend pinned to bottom, table fills remaining space with scroll
- DNS Leak Test and Route Table now call real backend (previously stub implementations)
- macOS HIG design tokens: added `--border-strong` for input control borders

### Removed
- Network Diagnostics (Ping) tool — not meaningfully useful as a standalone feature
- Unused i18n keys for removed Diagnostics feature

## [0.1.7] - 2026-04-09

### Added
- Multiple simultaneous tunnel support
- Per-tunnel NetworkManager (independent routes, DNS, route monitor per tunnel)
- Per-tunnel health check and reconnection
- Full-tunnel conflict detection (reject two 0.0.0.0/0 configs)
- DNS union across all active tunnels
- No-handshake warning: orange dot in tunnel list, ◐ in tray menu
- Tray menu shows per-tunnel connection + handshake status
- Architecture & design documentation (docs/DESIGN.md)

### Fixed
- Disconnect one tunnel no longer breaks other active tunnels
- Conflict detection: macOS netstat abbreviated CIDRs now parsed correctly
- GUI not reflecting connection state when tunnel connected via system tray
- Bypass route race conditions (lock safety, error propagation)
- Tray icon padding: trimmed transparent pixels for tighter menu bar fit
- Tunnel list unnecessary re-renders on every status tick
- README streamlined: removed defensive tone, screenshots moved to top

### Changed
- Pin Interface toggle added (Settings > Advanced) for dual-network stability
- Bypass routes pinned to upstream interface with -ifscope when enabled

## [0.1.6] - 2026-04-08

### Added
- Settings redesign: split layout with sidebar (General / Advanced / About)
- About tab: app icon, version, GitHub/Issues/License links, update status
- Update popup: modal with release notes ("What's New") and "Skip This Version"
- Helper auto-upgrade: detects version mismatch and reinstalls on app update
- Helper install retry dialog with Quit/Retry options on cancel
- OpenURL Wails binding (restricted to github.com)
- Tests for IsBrewInstall and OpenURL validation (7 new tests)

### Fixed
- Brew install detection: check Caskroom receipt instead of binary path
- Non-brew update: opens GitHub Releases page instead of broken auto-download
- Brew update: runs `brew update` before `brew upgrade` for third-party taps
- Helper Ping response: separate AppVersion field (fixes IPC protocol validation)
- Update popup double-click guard
- localStorage exception handling for skip version
- Detailed admin prompt explaining why password is needed

### Changed
- README/About description: "native macOS" → "cross-platform"

## [0.1.5] - 2026-04-07

### Added
- Health Check toggle in Settings (default: off, recommended with PersistentKeepalive)

### Changed
- Health Check default changed from on to off (consistent with other WG clients)
- README rewritten: removed aggressive tone, verified claims, acknowledged official app works for many users

## [0.1.4] - 2026-04-07

### Security
- Remove script execution (PreUp/PostUp/PreDown/PostDown) — eliminates local privilege escalation via ApproveScripts RPC
- Fix Windows IPC ACL: allow non-admin GUI to connect to helper pipe
- Harden update integrity: asset size validation + Content-Length check

### Fixed
- Kill switch pf rules: use anchor-only approach instead of modifying main ruleset (fixes Tahoe compatibility)
- Kill switch + DNS protection now toggleable while VPN is connected
- Kill switch reconnect deadlock: suspend/resume firewall rules during reconnect
- Log viewer scroll not working
- Tunnel list scroll overflow

### Added
- Handshake-based health check: detects dead tunnels and triggers reconnect after 180s
- Instant sleep/wake detection via NSWorkspace notification (polling fallback kept)
- Typed tunnel error enums (ErrAlreadyConnected, ErrNetwork, etc.)
- DNS post-write verification
- Crash recovery journal with pre-modification DNS snapshot
- Comprehensive unit tests (102 tests, race-clean)
- CHANGELOG.md
- Info-level logs for kill switch and DNS protection events

## [0.1.3] - 2026-04-07

### Fixed
- "Show Window" not working after closing the window (RegisterHook instead of OnWindowEvent)
- Dock icon hide/show when window is closed/reopened
- App icon showing Wails default (white W) instead of WireGuide red icon
- About/Settings dialog showing wrong version — now fetched dynamically from Go

### Added
- GitHub issue templates (bug report, feature request)
- CONTRIBUTING.md and PR template

## [0.1.2] - 2026-04-07

### Fixed
- Dock icon not hiding when window is closed
- Tunnel list not updating after rename

## [0.1.1] - 2026-04-06

### Fixed
- Daemon socket directory permissions (0700 → 0755)
- LaunchDaemon install flow rewrite (app first-launch, not cask postflight)

### Added
- Version display in Settings

## [0.1.0] - 2026-04-05

### Added
- Initial release
- WireGuard tunnel management (import, create, edit, export .conf files)
- Config editor with CodeMirror 6 syntax highlighting and autocompletion
- System tray with connection status badge
- Kill switch via macOS pf
- DNS protection (force DNS through VPN tunnel only)
- Auto-reconnect with exponential backoff
- Sleep/wake recovery
- Route monitor for gateway changes
- Conflict detection (Tailscale, other WG interfaces)
- Network diagnostics (ping, DNS leak test, route table)
- Auto-update (GitHub Releases + Homebrew)
- Real-time RX/TX speed graph
- i18n (English, Korean, Japanese)
- Dark / Light / System theme
