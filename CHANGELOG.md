# Changelog

All notable changes to WireGuide will be documented in this file.

## Unreleased (bitworks fork)

### Added
- **Diagnostics bundle** — `wireguide ctl diag bundle [--out path]` and Settings → Logging → "Export diagnostics…" (native save dialog) write a zip: helper log tail (5 MB) + rotated-file list, GUI logs if any, `config.json`, tunnel `.conf`s with `PrivateKey`/`PresharedKey` redacted (commented-out keys too; key values are also scrubbed from every other file), `.meta.json`, `history.json`, `scutil --dns`, `networksetup -getdnsservers` per service, both WireGuide pf anchors, `netstat -nr`, the Automation preview, a DNS leak test and versions. New read-only helper RPC `Diag.Snapshot` (IPC protocol 1.3, additive) supplies the pf anchors; an older helper just leaves that section out. A test scans the produced zip for the test config's keys.
- **Helper log rotation** — the helper writes `/var/log/wireguide-helper.log` itself through a size-based writer (10 MB x 5 files, `.1`-`.5`, O_APPEND, 0644). An oversized log from before the upgrade is rotated at the first start. Repeated identical wireguard-go warnings (e.g. "network is unreachable") log once per 60 s with a `suppressed_repeats` count (trailing summaries also reach the LogViewer). The LaunchDaemon plist's StandardOut/ErrorPath now point at `/var/log/wireguide-helper.stderr.log` (panics only); the in-app LogViewer is fed over IPC and is unaffected.
- **`wireguide://` URL scheme** — `connect/<name>`, `disconnect/<name>` and `show` (see README for Shortcuts recipes). Names are validated with `storage.ValidateTunnelName`, connect/disconnect show a confirmation sheet unless the app is frontmost, and nothing can import/delete/modify configs. `automation/pause` is deferred: it needs a helper-side latch.
- **Split-DNS inline help in the config editor** — the `DNS =` line is linted as you type (lint gutter + hover): errors for malformed `~domain` entries or split DNS without a server IP; warnings when a resolver outside AllowedIPs would replace system DNS on every interface, for `~x.local`, for split DNS on Windows, and when two tunnels share an `Address`; hints for LAN-only tunnels without DNS and for missing reverse zones (with a quick-fix). Hover on `DNS` / `~domain` explains global vs split vs none, that NXDOMAIN does not fall back to local DNS, and that `dig` bypasses split DNS (use `dscacheutil`). Completion after `DNS =` offers `~`, the AllowedIPs gateway, reverse zones and a split template. The new-tunnel template shows both DNS modes. Linting never blocks Save/Connect (`config.Lint` is separate from `config.Validate`).
- **Verify** — a "Verify" panel on the tunnel detail page and `wireguide ctl verify <name> [--json] [--resolve host] [--ping host]` check the handshake, a route per AllowedIPs (or "skipped — overlaps your LAN"), that the split-DNS resolver is registered for every `~domain`, and optionally ping a host and resolve a name through the system resolver. Manual only; every probe times out within 3 s.
- **DNS mode everywhere** — a chip on the tunnel card and list rows (`Global · replaces system DNS`, `Split · <domains>`, search domains only, or none), the DNS Leak Test lists each split domain with its resolver and has a "Try a name" field, and `ctl status` prints `dns=global|split(...)|search|none`.
- **Duplicate-Address warning** — saving or importing (including zip import) a tunnel whose `Address` is already used by another tunnel shows a non-blocking warning, and connecting it while the other is up offers "Disconnect X and Connect".
- **Split DNS (`~domain`)** — `DNS = 192.168.1.1, ~corp.lan` sends queries for `corp.lan` (and any other `~` domain) to the tunnel's servers while system DNS stays exactly as it is. On macOS the tunnel's servers are installed as a supplemental resolver in the SystemConfiguration dynamic store (`com.wireguide.<utunN>.match` / `.search` keys, no `networksetup`, no DNS snapshot, no reapply loop); keys are removed on disconnect, rollback and shutdown and swept at helper start. On Linux it uses `resolvectl` only (`~` routing domains, `default-route no`); Windows does not support it yet and connects without DNS handling. The config validator accepts `~name`, rejects malformed entries, requires at least one server IP, and caps 32 domains. The DNS leak test no longer reports split mode as a leak and checks that a resolver exists for each `~` domain. Tunnel details now show DNS servers, search domains and split-DNS domains.
- **Automation "why" strip** — the Automation editor header shows the network the engine sees (SSID, "no Wi-Fi", or "Wi-Fi name unknown" with a Location Services hint), whether it has settled (countdown while "is not" rules are on hold) and this tunnel's live verdict: connect/disconnect with the deciding rule, on hold, paused after a manual connect/disconnect (resumes when the network changes) or not connecting because AllowedIPs overlap your LAN. The same one-liner appears as a chip on the tunnel detail card and under each tunnel in the list. Polls the helper's read-only `Automation.Preview` every 2 s while the window is visible on macOS, every 30 s elsewhere.
- **Native notifications for automatic changes** — a notification when a tunnel connects or disconnects without a connect/disconnect made in this app (Automation rules, `wireguide ctl`, wake), when automation connects a tunnel (names it), and on critical helper errors. Never fires for your own window/tray actions. New Settings toggle "Notify on automatic tunnel changes" (default on). Uses the Wails notifications service (authorization requested on first use) and falls back to `osascript` on macOS; no-op on Windows for now. English, Korean and Japanese.
- **Helper & firewall visibility (helper release; one admin prompt at upgrade, IPC protocol 1.3)** — per-tunnel status gains `dns_mode`, `dns_servers`, `dns_protected` and `routes_skipped` (macOS LAN-overlap skips are now recorded, routes installed are unchanged); a read-only `Firewall.Status` RPC reports wanted vs actual DNS protection / kill switch (macOS reads both pf anchors back); Settings shows "Currently allowing: …" under DNS Protection, the hero card shows "DNS protected" / "intended, not applied" and "N routes skipped (overlap your LAN)", and the Routes tab marks skipped ranges. A banner appears when DNS protection keeps failing to apply, and an info banner when helper startup recovery restored DNS or flushed stale firewall rules (`Helper.Info` + `event.recovery`).
- **Reset DNS & firewall to system defaults** — `Network.ResetDNS` (Settings > Advanced and `wireguide ctl reset-dns [--force]`) flushes both WireGuide pf anchors, removes split-DNS dynamic-store keys, restores DNS from the pre-VPN recovery journal and flushes the DNS cache; it refuses while a tunnel is connected unless forced (which disconnects first). A "what will change when you connect" expander on the tunnel page previews DNS and route effects from the config.
- **Helper card and explain-before-prompt** — Settings > Advanced shows the helper version, start mode (launchd socket / legacy), socket, pid, start time and activation reason, with a "Repair helper…" button (the only prompting action). A native dialog now explains why the password is needed (once per app update) before every administrator prompt; the "quit and reopen" hint became a Repair action; both LaunchDaemon and LaunchAgent plists carry `AssociatedBundleIdentifiers`.
- **Automation events, change reasons, wake-aware health, connection type and SSID lists (IPC protocol 1.4, additive)** — `event.automation` reports every executed rule connect/disconnect (and held / latched / skipped-for-LAN-overlap only when that changes); notifications name the rule and SSID. Each tunnel carries a `last_change_reason` (user, automation, wake, network change, health check, reconnect, recovery) and recent disconnects; History records the start/end reason and SSID. The handshake health check waits 90 s after wake (measuring handshake age from the wake), is skipped while offline, and now also reconnects tunnels that never complete a handshake, checked from connect time with exponential backoff (3 → 6 → 12 → 24 → 48 min between attempts) until a handshake or a user disconnect; a per-tunnel override (inherit / on / off, stored in `.meta.json`) sits on the tunnel page. New conditions: SSID lists ("any of" / "none of") and connection type (Wi-Fi / wired / tethered), with the same settle/hold rules as "is not"; an unknown connection type never matches and is re-checked shortly. CLI forms `ssid:A|B`, `medium:wired`, `not-…`. The Location Services state is shown precisely in the banner and why-strip. Rules editing gains an undo toast, pre/post-change backups (newest 5, edits coalesced) with restore, and a "changed outside the app" toast. **Downgrade note:** an older helper fails validation for `medium` rules and for SSID rules that use only the list, and skips them; evaluation then falls through to later rules (for example a "none match → connect"), so an older helper can take a different or even the opposite action.
- Toast "Automation connected X" when automation connects a tunnel; the raw "Wi-Fi: X" toast on every SSID change is gone. About links come from the build's repository constant (fork builds target bitworks-io/wireguide) and About shows when update checks keep failing.

### Changed
- The "PRODUCTION BUILD WITHOUT SIGNING KEY" message is a single WARN at process start instead of an ERROR.
- Health-check hint now says the trigger can also fire after sleep/wake or on idle tunnels without PersistentKeepalive. The tunnel detail pane shows "Select a tunnel" instead of "No tunnels configured" when tunnels exist but none is selected.

### Fixed
- **Automation no longer stays "on hold — waiting for the network to settle" after rules are saved** — the helper now re-evaluates when the automation block of `config.json` changes (polled every 2 s; other settings are ignored), so the settle timer is armed for rules added while it was running. The settle fingerprint uses only the primary interface's subnets (virtual bridges such as `bridge100`/`vmenet` no longer restart the 15 s window), and the read-only Automation preview heals a stale settle tracker by triggering one evaluation (at most every 5 s).
- **History rows with 0 B rx/tx** — a tunnel the helper lists as active while connecting or disconnecting reports 0/0 counters, and a reconnect restarts them from zero; the per-tick cache overwrote the real totals with those readings one tick before the session closed (49 of 76 sessions in one history were affected). Session totals now accumulate across zeroed or reset readings, and app-quit close merges the live status with the cache.
- **Wi-Fi roam blips no longer bounce automation-owned tunnels** — the legacy wake/interface-change reconnect used to tear down an arbitrary tunnel before deciding anything, causing a ~20 s outage for tunnels with automation rules. The helper now leaves connected tunnels that have automation rules or a manual connect/disconnect latch untouched and only rebuilds plain tunnels.
- **DNS permits respect LAN-overlap route skips** — a DNS server inside an AllowedIPs range that the macOS route installer skipped (it overlaps the local network) is no longer pinned to the tunnel interface, so another tunnel's DNS block cannot blackhole it.
- **Login item picks up `AssociatedBundleIdentifiers` on upgrade (macOS)** — with Launch at login on, the app refreshes an existing `~/Library/LaunchAgents/com.wireguide.gui.plist` to the current template at startup (user-level, no prompt; only when the login item already launches this app bundle, so it is never retargeted, and a removed login item is never recreated), so upgraded installs no longer need Launch at login toggled off and on.
- **Stale SSID no longer trusted after the app dies** — the gateway MAC is stamped lazily when it was not yet known at report time, so a helper without a GUI drops the reported SSID once the gateway changes.
- **A leftover helper cannot outlive the removed app (macOS)** — the LaunchDaemon plist now carries `--app-bundle=<installing .app>`; if that bundle is missing on two checks 2 s apart at helper start, the helper deletes its plist, binary and socket, runs `launchctl bootout`, and exits without serving. The helper runs crash recovery (pf anchors, DNS journal) before removing itself, the path is symlink-resolved so Homebrew launches match, and paths XML cannot represent omit the flag. Existing installs get the new plist via the normal one-time reinstall (one admin prompt). Moving the app elsewhere triggers the same cleanup; the next launch reinstalls.
- **Crash recovery no longer wipes the user's own DNS** — the recovery journal records `dns_mode` (`global`/`split`), and `networksetup` DNS/search domains are reset to defaults only for tunnels that overrode system DNS. Split-DNS and DNS-less tunnels are left alone. Tunnel detail view reads the right (lower-case) model fields, so the DNS, AllowedIPs and public key rows render again.

### Changed (macOS helper start)
- **No administrator prompt at boot or on app relaunch** — the LaunchDaemon now owns the helper's socket (`/var/run/com.wireguide.helper.sock`, launchd socket activation). The helper still never runs at boot; launchd starts it when the app (or `ctl`) connects, so reopening the app after a quit or an idle exit no longer asks for a password. The prompt now appears only to install or repair (first install, app update, broken job).
- **The first launch after upgrading asks for the admin password once** (the plist changed); a still-running pre-upgrade helper is shut down gracefully first.
- **Helper is dormant until the app attaches** — Wi-Fi/subnet automation (including the startup re-evaluation) does nothing until a GUI connects, and a helper started without a GUI exits after 15 s (an active tunnel keeps it alive).
- **CLI** — `Helper.Ping` reports `gui_attached` (IPC protocol 1.2). `ctl start/stop/status` and the other commands treat a helper with no app attached as "app not running"; `ctl stop` confirms with "no app and no tunnels" instead of waiting for the socket to go silent.
- Quitting the app stops its helper health monitor first, so a health tick can no longer restart the helper right after Quit.
- Security: any process running as your user can now start the root helper without a password (it still serves only your uid and exposes the same RPC surface as an open app). `brew uninstall --zap` removes the daemon, its socket and the pf token.

### Fixed
- **macOS DNS protection no longer outlives its tunnels** — the helper now owns DNS protection as wanted state and reconciles the firewall against the tunnels that are actually connected (on connect, disconnect, automation, reconnect suspend/resume, and a tunnel-set watchdog in the event loop). Previously the `block ... port 53` pf rule survived disconnects, so system DNS stayed dead until quit or reboot.
- **DNS protection no longer blackholes split tunnels** — resolvers reached over the physical network (e.g. 1.1.1.1 with a LAN-only AllowedIPs) get an any-interface permit, resolvers inside AllowedIPs or behind a default-route tunnel are pinned to the tunnel, split-DNS (`~domain`) tunnels never trigger protection, and `0.0.0.0/1` + `128.0.0.0/1` full tunnels are recognised. Loopback resolvers on port 53 are always exempt, and search domains in `DNS =` no longer cause errors.
- **Stale pf state cleared on every helper start** — both WireGuide pf anchors are flushed unconditionally at startup, not only when a state file exists.
- **pf is reference counted** — WireGuide enables pf with `pfctl -E`, persists the token (with boot time) and releases it with `pfctl -X`; it never runs `pfctl -e` or `pfctl -d`, so other pf users (Internet Sharing, other VPNs) are no longer switched off. `/etc/pf.conf` is reloaded only when the active ruleset lacks `anchor "com.apple/*"`.
- **Single firewall model on macOS** — kill switch and DNS rules render from one model, so toggling the kill switch can no longer resurrect stale DNS rules.
- **Reconnect monitor** — the firewall is resumed on every exit path of a reconnect attempt (including panic), rebuilt from the currently connected tunnels instead of the alphabetically first one, and stays fail-closed with the kill switch when no tunnel is up.
- **Legacy disconnect** — tunnels that did tear down lose their kill-switch permits even when another tunnel's teardown failed; automation disconnects now take the connect lock.
- **Linux** — repeated DNS-protection enables replace the nftables DNS table instead of appending to it.
- **Linux DNS permits** — the nftables backend now applies the full permit set (pinned `oifname` for tunnel-routed resolvers, no interface match for split-tunnel resolvers) and removes a stale `wireguide_dns` table at helper start.
- **Failed firewall reconciles are retried** — a failed apply is no longer recorded as handled; the event-loop safety net retries with backoff. macOS pf applies roll back the two anchors together and restore the model on failure.
- **pf token robustness** — pf is re-enabled if it was stopped externally, a dead token no longer wedges disable/cleanup, tokens are keyed to `kern.bootsessionuuid`, and pf query output no longer includes pfctl's stderr notices.
- **Updates** — fork builds open the fork's release page (never upstream's Homebrew cask) and `-bitworks.N` revisions are ordered; the helper also restores DNS on a timed-out SIGTERM shutdown.
- **Helper shutdown** — SIGTERM/SIGINT run the normal graceful shutdown, bounded to 3 s; the macOS install script waits up to 15 s for the old helper to unload.
- **Automation no longer fights the reconnect monitor** — the legacy sleep/wake/interface-change reconnect only restores tunnels that are down, counts `ErrAlreadyConnected` as success (no more endless retry loop with two tunnels), leaves rule-governed tunnels and manually disconnected tunnels to automation/the user, waits up to 10 s for a default route, and ends its retry when nothing is left to restore; the retry is also cancelled when the last tunnel disconnects.
- **LAN-overlap guard** — a tunnel whose AllowedIPs contain a local physical-interface address (e.g. the home LAN) is no longer brought up by automation or the legacy reconnect, and macOS route installation skips such a range with a warning instead of routing the LAN into the tunnel.

### Added
- **Negated automation conditions** — `ssid`, `subnet` and `network` rules gain an "is not" mode (`negate` in `config.json`, an is/is-not selector in the editor, `not-ssid:`/`not-subnet:`/`not-mac:` in `ctl automation add`). A negated rule matches only when its value is known and different; when unknown (blank SSID while roaming on Wi-Fi, network changed less than ~15 s ago, no default route) evaluation holds instead of falling through. A blank SSID on a non-Wi-Fi primary interface (Ethernet, USB tethering) is a known "no SSID". Non-negated rules and existing configs are unchanged. Downgrade note: an older binary reads a negated rule as its positive form (the opposite action), so remove negated rules before downgrading.
- **Manual override latch** — an explicit connect/disconnect from the GUI, tray or CLI pauses automation for that tunnel until the network settles on a different identity, so a still-true rule no longer undoes a manual disconnect within milliseconds.
- `ctl automation` shows the primary interface, settle state, and `held`/`latched` decisions.

### Changed
- Update checks now target `bitworks-io/wireguide`; version is `0.5.2-bitworks.5`.

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
