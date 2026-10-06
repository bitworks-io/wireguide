# Manual Test Checklist

Things that can't be reasonably automated and must be verified by hand
before considering the related feature done. Items here are added when
shipped without end-to-end verification — clear them out as you walk
through each one.

## Phase 4 — Automation rules (helper-side, issue #12)

Rule evaluation lives in `internal/helper/wifi_rules.go`
(`reevaluateAutomation`); the rule model + engine live in
`internal/wifi/automation.go` (`Evaluate`); rule data lives in
`Settings.Automation` (`internal/storage/settings.go`). Legacy
`Settings.WifiRules` is migrated once on first read. The helper evaluates
rules itself, so these tests verify behavior **both with the GUI running
and after Cmd+Q'ing the GUI**.

Rules can be authored in the GUI (tunnel detail → **Automation**) or from
the CLI (`wireguide ctl automation add/rm/rules`). The read-only preview
`wireguide ctl automation` prints the current network context (SSID,
gateway MAC, physical IPs) and each tunnel's decision — use it to check
expectations without reading logs.

Semantics reminder: rules are evaluated top to bottom and the first
matching rule wins, by position; `else` is an unconditional match at its
own position (a fallback when last). Order = priority, and a rule can
connect OR disconnect regardless of how the tunnel was brought up.
Negated ("is not") rules only match on a known, different value and hold
(stop, no fall-through) when unknown; see the negation section below.

### Connect on a network (SSID)
- [ ] Add `connect` when `ssid:<current-wifi>` for a tunnel; disconnect
      it manually; rejoin/stay on that SSID. **Expected**: helper log
      `automation: rule connect ... reason=ssid-change`, tunnel up within
      ~6s. Confirm with `ctl automation` (decision=connect).
- [ ] Repeat with the GUI fully quit (Cmd+Q, verify via
      `pgrep -f WireGuide.app`). The rule must still fire — only the
      helper log shows it; `ctl status` confirms.

### Disconnect on a specific network (gateway MAC)
- [ ] On the target network, capture its gateway MAC (`ctl automation`
      shows `gateway-mac=`), add `disconnect` when `mac:<that-MAC>`.
- [ ] Connect the tunnel; **Expected**: within a few seconds the
      route-change trigger fires `automation: rule disconnect
      reason=network-change` and the tunnel goes down. Verify the MAC
      match is separator/case-insensitive (dash/upper-case forms match).

### Subnet condition + Ethernet
- [ ] Add `disconnect` when `subnet:<your-current-CIDR>`; connect the
      tunnel on that network (Ethernet is fine — no SSID needed).
      **Expected**: it disconnects. On macOS this fires via the route
      monitor instantly; on Windows/Linux within the 30s poll.

### Priority / conflict
- [ ] Add two rules that both match now with opposite actions (e.g.
      `disconnect ssid:X` and `connect else`, or two matching concrete
      conditions). **Expected**: the top rule wins. Reorder (GUI drag, or
      `rm` + `add`) and confirm the result flips.

### Rule edits without restart
- [ ] Edit rules (GUI or `ctl automation add`) while connected to a
      network. **Expected**: the change takes effect on the next trigger
      (SSID change / route change / 30s poll) — the helper rereads
      config.json each evaluation, no restart.

### Negative cases
- [ ] A tunnel with NO rules is never auto-touched (connect it manually;
      it stays up across network changes).
- [ ] A malformed MAC/CIDR rule never matches (and the GUI flags it red);
      it doesn't crash or affect other rules.
- [ ] Wi-Fi off / on Ethernet with only SSID rules — those rules simply
      don't match (SSID is empty); nothing happens.

### Negated conditions ("is not")
Setup: tunnel `T` with rules `disconnect when ssid=<Site>` then
`connect when ssid is not <Site>` (CLI: `add T disconnect ssid:<Site>`,
`add T connect not-ssid:<Site>`). `ctl automation` shows `settled` /
`settling, Ns left` and per-tunnel `decision=` (`held`, `latched`).
- [ ] On `<Site>`: tunnel goes down (positive rule, no settle delay).
- [ ] Join another Wi-Fi. **Expected**: nothing for ~15 s
      (`decision=held`, "settling"), then `automation: rule connect
      reason=settled` and the tunnel comes up.
- [ ] Roam between two access points of `<Site>` (SSID goes blank for a
      few seconds). **Expected**: no connect/disconnect flap.
- [ ] Kill the GUI on macOS while on Wi-Fi (no SSID reports).
      **Expected**: the last reported SSID is still used (decisions follow
      it) until the gateway changes; then the SSID becomes unknown and
      negated SSID rules hold (`decision=held`), tunnel left as is.
- [ ] Plug in Ethernet / USB tethering (primary interface not Wi-Fi) and
      wait 15 s. **Expected**: blank SSID counts as "not `<Site>`", so the
      connect rule fires (`ctl automation` shows `wifi=false`).
- [ ] Manual disconnect on a network where the connect rule holds.
      **Expected**: it stays down (`decision=latched`) through blips and
      re-evaluations; after you settle on a different network the latch
      clears and rules apply again. Same for a manual connect on a
      network where a disconnect rule would fire.
- [ ] Two tunnels up (one with rules), sleep/wake or change the primary
      interface. **Expected**: no `already connected` retry loop; the
      rule-governed tunnel is handled by automation (`reason=reconnect`),
      not the legacy reconnect.
- [ ] Tunnel whose AllowedIPs contain your own LAN (e.g. the home
      `192.168.x.0/24` while at home): automation/reconnect refuse to
      bring it up (Info log); a manual connect logs "AllowedIPs overlaps
      local network" and skips that route, LAN keeps working.
- [ ] `ctl automation add T connect not-else` is rejected; the GUI hides
      the is/is-not selector for "otherwise".
