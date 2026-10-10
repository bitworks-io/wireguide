<script>
  // Per-tunnel Automation rule editor (issue #12). Each rule is an
  // ordered condition→action: on a matching network the tunnel is
  // connected or disconnected. Connect and disconnect conditions are set
  // independently (just add rules with the action you want). Persisted to
  // Settings.automation.per_tunnel_rules[tunnelName]; the whole settings
  // object is re-fetched and spread on save so other screens' edits (and
  // other tunnels' rules) are never clobbered.
  import { afterUpdate, onMount, onDestroy } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import Icon from './Icon.svelte';
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';
  import SSIDPermissionBanner from './SSIDPermissionBanner.svelte';
  import { automationPreview, automationCheckedAt, AUTOMATION_POLL_MS, refreshAutomationPreview } from '../stores/automation.js';
  import { networkLines, verdictFor, verdictText, verdictTone } from './automationLine.js';
  import { removeAt, restoreAt, UNDO_MS } from './automationSafety.js';
  import { locationAuth } from '../stores/automation.js';
  import { noteOwnSave, setRulesBaseline } from '../stores/automationWatch.js';
  import {
    MEDIUMS, DEFAULT_MEDIUM, macInvalid, macCanon, commitDraft, rowFromDisk, blankRow,
    cleanedRule, rulesDiffer,
  } from './automationRules.js';

  export let TunnelService;
  export let tunnelName = '';
  export let open = false;

  let rules = [];

  // Live "why" strip: what network the engine sees and what it decided for
  // THIS tunnel. Fed by the shared poller (App.svelte); opening the editor
  // also refreshes immediately so it never opens on a stale reading.
  $: whyNet = networkLines($t, $automationPreview, $locationAuth);
  $: whyVerdict = verdictFor($automationPreview, tunnelName);
  $: whyLine = whyVerdict ? verdictText($t, whyVerdict) : '';
  $: whySlowPoll = AUTOMATION_POLL_MS > 5000;
  $: if (open) refreshAutomationPreview();
  // Local-only row identity for the {#each} key; never persisted
  // (persistSet() rebuilds plain objects). Monotonic and never reset, so
  // keys stay unique across loads. Note this does NOT preserve DOM across
  // a genuine reload (load() mints fresh ids) — focus survival comes from
  // diskDiffers suppressing self-write reloads, not from the keying.
  let ruleId = 0;
  let loadedFor = '';
  let knownSSIDs = [];
  let currentSSID = '';
  let currentSubnets = [];      // autocomplete suggestions for the subnet field
  let currentGatewayMAC = '';   // autocomplete suggestion for the MAC field
  let saveError = '';
  // loadGen tags each async load so a slow in-flight load(A) can't clobber
  // the rules after the user has already switched to load(B) (issue #12).
  let loadGen = 0;

  // Reload whenever the modal opens for a (possibly different) tunnel.
  $: if (open && tunnelName && loadedFor !== tunnelName) {
    load(tunnelName);
  }

  async function load(name) {
    // Claim the load BEFORE the first await: the reactive statement keys
    // on loadedFor, and awaiting first would leave a window where any
    // state change re-runs it and double-invokes load for the same name.
    loadedFor = name;
    clearUndo();
    showBackups = false;
    const gen = ++loadGen;
    // Persist any pending edit for the tunnel we're leaving BEFORE we
    // overwrite `rules`, so switching tunnels never drops the last change.
    await flush();
    saveError = '';
    try {
      const s = await TunnelService.GetSettings();
      if (gen !== loadGen) return; // a newer load superseded this one
      const per = s?.automation?.per_tunnel_rules || {};
      // Deep-copy so edits don't mutate the fetched object before save.
      rules = (per[name] || []).map(r => {
        const row = rowFromDisk(r, ++ruleId);
        // Seed the last-committed form so an existing rule that turns
        // incomplete mid-edit keeps its on-disk value (see persistSet).
        row._committed = cleanedRule(row);
        return row;
      });
    } catch (e) {
      if (gen === loadGen) rules = [];
      console.error('automation load:', e);
    }
    try {
      const r = await TunnelService.GetKnownSSIDs();
      if (gen !== loadGen) return;
      knownSSIDs = r?.known || [];
      currentSSID = r?.current || '';
    } catch (_) {}
    try {
      const subs = (await TunnelService.GetCurrentSubnets()) || [];
      if (gen !== loadGen) return;
      currentSubnets = subs;
    } catch (_) { if (gen === loadGen) currentSubnets = []; }
    try {
      const mac = (await TunnelService.GetCurrentNetwork())?.gateway_mac || '';
      if (gen !== loadGen) return;
      currentGatewayMAC = mac;
    } catch (_) { if (gen === loadGen) currentGatewayMAC = ''; }
  }

  const MAX_RULES = 50;
  function addRule() {
    if (rules.length >= MAX_RULES) return;
    // No save() here: a blank draft is not a configuration change — it
    // becomes persistable on the first input that completes it. Saving
    // now would also manufacture a self-write config_changed echo.
    rules = [...rules, blankRow(++ruleId)];
  }

  // "Rule removed — Undo" for UNDO_MS: keeps the removed row and its index
  // so Undo puts it back where it was. A newer removal replaces the toast
  // (one level: the user's deletion is deliberate, this is a convenience).
  let undoItem = null; // { row, index }
  let undoTimer = null;
  function clearUndo() {
    if (undoTimer) { clearTimeout(undoTimer); undoTimer = null; }
    undoItem = null;
  }
  function removeRule(i) {
    const r = removeAt(rules, i);
    if (r.removed === null) return;
    rules = r.list;
    save();
    clearUndo();
    undoItem = { row: r.removed, index: r.index };
    undoTimer = setTimeout(clearUndo, UNDO_MS);
  }
  function undoRemove() {
    if (!undoItem) return;
    rules = restoreAt(rules, undoItem.row, undoItem.index);
    clearUndo();
    save();
  }

  // "Restore previous rules…": snapshots written by the GUI on every
  // successful save. Restoring goes through the validated save path.
  let showBackups = false;
  let backups = [];
  let backupError = '';
  async function openBackups() {
    showBackups = !showBackups;
    backupError = '';
    if (!showBackups) return;
    await flush();
    try {
      backups = (await TunnelService.ListAutomationBackups(tunnelName)) || [];
    } catch (e) {
      backups = [];
      backupError = errText(e);
    }
  }
  async function restoreBackup(b) {
    backupError = '';
    const name = tunnelName;
    try {
      await flush();
      // Register the write first so its config_changed echo is never
      // reported as an outside edit.
      noteOwnSave(name, (await TunnelService.AutomationBackupRules(b.name, name)) || []);
      await TunnelService.RestoreAutomationBackup(b.name, name);
      setRulesBaseline(await TunnelService.GetSettings());
      showBackups = false;
      loadedFor = ''; // re-run the reactive load for this tunnel
    } catch (e) {
      backupError = errText(e);
    }
  }

  // Lightweight format validation for user feedback. The engine is
  // already safe against garbage (a bad CIDR / MAC simply never matches,
  // never panics, never reaches a shell), but without this a malformed
  // value would save and silently never fire — so mark it invalid so the
  // user can fix it. Empty is "incomplete", not "invalid".
  // A MAC is valid in any common style — colon, dash, or no separator —
  // as long as it reduces to exactly 12 hex digits. The engine compares
  // canonically (separator/case-insensitive), and we normalise on commit
  // (macInvalid/macCanon live in automationRules.js).
  function onMacChange(rule) {
    rule.when.gateway_mac = macCanon(rule.when.gateway_mac);
    rules = rules;
    save();
  }
  // Switching to "connection type" needs a concrete medium, or the select
  // would show one value while cleanedRule() treats the row as incomplete.
  function onTypeChange(rule) {
    if (rule.when.type === 'medium' && !MEDIUMS.includes(rule.when.medium)) rule.when.medium = DEFAULT_MEDIUM;
    rules = rules;
    save();
  }

  // SSID tags: typing a comma or pressing Enter commits the name as a tag;
  // the remaining draft text still counts (see cleanedRule).
  function onSSIDInput(rule) {
    if ((rule.when.ssid || '').includes(',')) { commitDraft(rule.when, false); rules = rules; }
    save();
  }
  function onSSIDKeydown(e, rule) {
    // Never commit a half-composed IME (Hangul/Kana) name; WebKit may
    // report that Enter as keyCode 229 without isComposing.
    if (e.isComposing || e.keyCode === 229) return;
    if (e.key === 'Enter') {
      e.preventDefault();
      commitDraft(rule.when, true);
      rules = rules;
      save();
    } else if (e.key === 'Backspace' && !rule.when.ssid && rule.when.ssids.length) {
      rule.when.ssids = rule.when.ssids.slice(0, -1);
      rules = rules;
      save();
    }
  }
  function onSSIDChange(rule) {
    commitDraft(rule.when, true);
    rules = rules;
    save();
  }
  function removeSSID(rule, j) {
    rule.when.ssids = rule.when.ssids.filter((_, idx) => idx !== j);
    rules = rules;
    save();
  }

  function cidrInvalid(v) {
    const s = (v || '').trim();
    if (s === '') return false;
    const m = s.match(/^([^/]+)\/(\d{1,3})$/);
    if (!m) return true;
    const prefix = Number(m[2]);
    const ip = m[1];
    if (ip.includes(':')) return prefix < 0 || prefix > 128; // IPv6 — trust the notation
    const octets = ip.split('.');
    if (octets.length !== 4) return true;
    if (octets.some(o => o === '' || !/^\d+$/.test(o) || Number(o) > 255)) return true;
    return prefix < 0 || prefix > 32;
  }

  // Drag-to-reorder with LIVE reordering: as the cursor passes over
  // another row the list re-sorts in real time (the standard sortable-
  // list feel), the dragged row is dimmed, and the browser's drag image
  // is the whole row. Rule order IS priority — the engine applies the
  // first matching rule (top wins) — so this both reorders and re-prioritises.
  let dragIndex = null;
  function onDragStart(e, i) {
    dragIndex = i;
    e.dataTransfer.effectAllowed = 'move';
    try { e.dataTransfer.setData('text/plain', String(i)); } catch (_) {}
    // Ghost = the full row (drag starts from the handle, so inputs stay usable).
    const row = e.currentTarget.closest('.am-rule');
    if (row) {
      try { e.dataTransfer.setDragImage(row, 24, row.offsetHeight / 2); } catch (_) {}
    }
  }
  function onRowDragOver(e, i) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (dragIndex === null || dragIndex === i) return;
    // Move the dragged item to this row's position, live.
    const arr = [...rules];
    const [moved] = arr.splice(dragIndex, 1);
    arr.splice(i, 0, moved);
    rules = arr;
    dragIndex = i;
  }
  function onDragEnd() {
    if (dragIndex !== null) { dragIndex = null; save(); }
  }

  // Scroll affordance: show a fade at the top/bottom of the rule list
  // only when there's hidden content in that direction, so it's obvious
  // the list scrolls. Recomputed after every render and on scroll.
  let rulesEl;
  let canScrollUp = false;
  let canScrollDown = false;
  function updateScroll() {
    if (!rulesEl) return;
    canScrollUp = rulesEl.scrollTop > 2;
    canScrollDown = rulesEl.scrollTop + rulesEl.clientHeight < rulesEl.scrollHeight - 2;
  }
  afterUpdate(updateScroll);

  // cleanedRule returns the normalized persisted form of a row, or null
  // while the row's condition is incomplete. persistSet() is what goes to
  // disk: the latest complete form of every row (cached on r._committed).
  // A row that turns incomplete mid-edit therefore keeps its last on-disk
  // value instead of being transiently deleted (and lost on a crash); a
  // never-completed draft contributes nothing. Rows leave the persisted
  // set only via removeRule() or by abandoning a draft.
  // (cleanedRule lives in automationRules.js.)
  function persistSet() {
    const out = [];
    for (const r of rules) {
      const c = cleanedRule(r);
      if (c) r._committed = c;
      if (r._committed) out.push(r._committed);
    }
    return out;
  }

  // Debounced, snapshot-based save. The pending snapshot binds the rules
  // to the tunnel they were edited for AT SCHEDULE TIME — the old code read
  // `tunnelName` and the live `rules` when the 300ms timer fired, so closing
  // one tunnel and opening another within the debounce window could persist
  // the wrong tunnel's rules under the new name (issue #12). saveChain
  // serialises overlapping saves so a fast burst can't interleave writes.
  let saveTimer = null;
  let pending = null;             // { name, rules } snapshot to persist
  let saveChain = Promise.resolve();

  function save() {
    pending = { name: tunnelName, rules: persistSet() };
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(runSave, 300);
  }
  function runSave() {
    saveTimer = null;
    const snap = pending;
    pending = null;
    if (!snap) return;
    saveChain = saveChain.then(() => persist(snap));
  }
  async function persist(snap) {
    saveError = '';
    try {
      // Scoped, cross-process-atomic update of just this tunnel's rules.
      // The old GetSettings → whole-object SaveSettings pair had a lost-
      // update race: a CLI SettingsStore.Update landing between the two
      // IPC calls was clobbered by our stale snapshot of every setting.
      // An empty set removes the tunnel's entry (same semantics as before).
      // Advance the external-change baseline first so the config_changed
      // echo of this very write is never reported as an outside edit.
      noteOwnSave(snap.name, snap.rules);
      await TunnelService.SaveAutomationRules(snap.name, snap.rules);
    } catch (e) {
      TunnelService.GetSettings().then(setRulesBaseline).catch(() => {});
      saveError = errText(e);
      console.error('automation save:', e);
    }
  }
  // flush persists any debounced edit immediately and waits for all
  // in-flight/queued saves — used before switching tunnels and on close so
  // the last edit is never lost.
  async function flush() {
    if (saveTimer) { clearTimeout(saveTimer); runSave(); }
    await saveChain;
  }

  async function close() {
    await flush();
    clearUndo();
    showBackups = false;
    open = false;
    loadedFor = '';
  }

  // Live-reflect an external edit to config.json (e.g. `wireguide ctl
  // automation ...`, or another window) while the editor is open — the
  // file is the single source of truth for COMPLETE rules, so a genuine
  // external change reloads rather than sitting on a stale in-memory copy
  // that our next save would write back over.
  //
  // But the watcher also fires for this editor's OWN persist(): draft rows
  // (incomplete condition) exist only in the UI — persistSet() keeps them
  // off disk — so a blind reload here erased the row the user was about to
  // fill in, ~1 s after adding it (issue #27). The saveTimer guard alone
  // can't prevent that: the 300 ms debounce has long cleared by the time
  // the ≤1 s mtime poll delivers the event. So reload only when disk
  // actually disagrees with what we'd persist right now — a self-write
  // compares equal and is ignored; a real external edit differs and reloads.
  //
  // normRule puts a disk rule and a persistSet() rule through the SAME
  // normalization (load()'s type fallback, MAC canonicalization), so e.g.
  // a dash-separated MAC written by `wireguide ctl` never reads as a
  // difference from our colon form and forces a spurious reload.
  // (normRule / rulesDiffer live in automationRules.js.)
  function diskDiffers(disk) {
    return rulesDiffer(disk, persistSet());
  }
  let cfgChangedUnsub = null;
  onMount(() => {
    cfgChangedUnsub = Events.On('config_changed', async () => {
      // Capture the tunnel so a switch mid-await can't compare or load
      // across tunnels; busy() bundles every reason to leave the user's
      // local state alone (closed, switched, typing, save queued, or a
      // live drag reorder that hasn't been saved yet).
      const name = tunnelName;
      const busy = () =>
        !open || tunnelName !== name || saveTimer !== null || pending || dragIndex !== null;
      if (!name || busy()) return;
      try {
        await saveChain; // let an in-flight persist settle before comparing
        const s = await TunnelService.GetSettings();
        if (busy()) return; // state moved while we awaited
        const disk = (s?.automation?.per_tunnel_rules || {})[name] || [];
        if (!diskDiffers(disk)) return;
      } catch (e) {
        // Can't tell what's on disk — keep the user's in-progress state
        // rather than risk wiping it with a reload that would also fail.
        console.error('automation config_changed check:', e);
        return;
      }
      load(name);
    });
  });
  onDestroy(() => {
    if (cfgChangedUnsub) cfgChangedUnsub();
    clearUndo();
  });
</script>

{#if open}
  <div class="am-backdrop" on:click={close}>
    <div class="am-dialog" on:click|stopPropagation role="dialog" aria-modal="true" aria-label={$t('automation.title')}>
      <div class="am-header">
        <div class="am-icon"><Icon name="wifi" size={18} strokeWidth={2} /></div>
        <div class="am-header-text">
          <h3>{$t('automation.title')}</h3>
          <p class="am-sub">{tunnelName}</p>
        </div>
        <button class="am-close" on:click={close} aria-label="Close"><Icon name="x" size={16} strokeWidth={2} /></button>
      </div>
      {#if $automationPreview?.available}
        <div class="am-why" role="status" aria-live="polite" aria-label={$t('automation.why.title')}>
          <div class="am-why-net">
            <span>{whyNet.network}</span>
            {#if whyNet.settle}<span class="am-why-sep">·</span><span>{whyNet.settle}</span>{/if}
            {#if whySlowPoll && $automationCheckedAt}
              <span class="am-why-sep">·</span><span>{$t('automation.why.checked_at', { time: new Date($automationCheckedAt).toLocaleTimeString() })}</span>
            {/if}
          </div>
          {#if whyVerdict}
            <div class="am-why-verdict am-why-{verdictTone(whyVerdict)}">{whyLine || $t('automation.why.v_no_match')}</div>
          {/if}
        </div>
      {/if}
      <p class="am-hint">{$t('automation.hint')}</p>

      <SSIDPermissionBanner {TunnelService} />

      <div class="am-rules-wrap">
        <div class="am-fade am-fade-top" class:show={canScrollUp}>
          <span class="am-chevron am-chevron-up"><Icon name="chevron-down" size={15} strokeWidth={2.5} /></span>
        </div>
        <div class="am-rules" bind:this={rulesEl} on:scroll={updateScroll}>
        {#if rules.length === 0}
          <div class="am-empty">{$t('automation.empty')}</div>
        {:else}
          {#each rules as rule, i (rule._id)}
            <div class="am-rule" class:am-dragging={dragIndex === i}
              on:dragover={(e) => onRowDragOver(e, i)}
              on:dragend={onDragEnd}>
              <span class="am-handle" draggable="true" title={$t('automation.drag_hint')}
                on:dragstart={(e) => onDragStart(e, i)}>⋮⋮</span>
              <span class="am-priority">{i + 1}</span>
              <select class="am-do" bind:value={rule.do} on:change={save} aria-label={$t('automation.action')}>
                <option value="connect">{$t('automation.connect')}</option>
                <option value="disconnect">{$t('automation.disconnect')}</option>
              </select>
              <span class="am-when">{$t('automation.when')}</span>
              <select class="am-type" bind:value={rule.when.type} on:change={() => onTypeChange(rule)} aria-label={$t('automation.condition')}>
                <option value="network">{$t('automation.cond_network')}</option>
                <option value="subnet">{$t('automation.cond_subnet')}</option>
                <option value="ssid">{$t('automation.cond_ssid')}</option>
                <option value="medium">{$t('automation.cond_medium')}</option>
                <option value="none_match">{$t('automation.cond_none')}</option>
              </select>
              {#if rule.when.type !== 'none_match'}
                <select class="am-neg" bind:value={rule.when.negate} on:change={save} aria-label={$t('automation.negate')}
                  title={rule.when.negate ? $t('automation.negated_hint') : ''}>
                  <option value={false}>{$t('automation.is')}</option>
                  <option value={true}>{$t('automation.is_not')}</option>
                </select>
              {/if}
              {#if rule.when.type === 'network'}
                <input
                  class="am-val" class:am-invalid={macInvalid(rule.when.gateway_mac)}
                  list="am-mac-list"
                  placeholder={currentGatewayMAC || $t('automation.mac_placeholder')}
                  title={macInvalid(rule.when.gateway_mac) ? $t('automation.mac_invalid') : ''}
                  bind:value={rule.when.gateway_mac}
                  on:input={save} on:change={() => onMacChange(rule)} />
              {:else if rule.when.type === 'subnet'}
                <input
                  class="am-val" class:am-invalid={cidrInvalid(rule.when.subnet)}
                  list="am-subnet-list"
                  placeholder={currentSubnets[0] || '192.168.0.0/24'}
                  title={cidrInvalid(rule.when.subnet) ? $t('automation.subnet_invalid') : ''}
                  bind:value={rule.when.subnet}
                  on:input={save} on:change={save} />
              {:else if rule.when.type === 'ssid'}
                <div class="am-val am-tags" title={$t('automation.ssid_tags_hint')}>
                  {#each rule.when.ssids as tag, j}
                    <span class="am-tag">{tag}<button class="am-tag-x" type="button"
                      on:click={() => removeSSID(rule, j)}
                      aria-label={$t('automation.remove_ssid', { ssid: tag })}><Icon name="x" size={9} strokeWidth={2.5} /></button></span>
                  {/each}
                  <input
                    class="am-tag-input"
                    list="am-ssid-list"
                    placeholder={rule.when.ssids.length ? $t('automation.ssid_add_placeholder') : (currentSSID || $t('automation.ssid_placeholder'))}
                    aria-label={$t('automation.ssid_tags_hint')}
                    bind:value={rule.when.ssid}
                    on:input={() => onSSIDInput(rule)}
                    on:keydown={(e) => onSSIDKeydown(e, rule)}
                    on:change={() => onSSIDChange(rule)} />
                </div>
              {:else if rule.when.type === 'medium'}
                <select class="am-val am-medium" bind:value={rule.when.medium} on:change={save} aria-label={$t('automation.cond_medium')}>
                  {#each MEDIUMS as m}<option value={m}>{$t(`automation.medium_${m}`)}</option>{/each}
                </select>
              {:else}
                <span class="am-val am-val-none">{$t('automation.cond_none_desc')}</span>
              {/if}
              <button class="am-remove" on:click={() => removeRule(i)} aria-label="remove rule"><Icon name="x" size={12} strokeWidth={2} /></button>
            </div>
          {/each}
        {/if}
        </div>
        <div class="am-fade am-fade-bottom" class:show={canScrollDown}>
          <span class="am-chevron"><Icon name="chevron-down" size={15} strokeWidth={2.5} /></span>
        </div>
      </div>

      <datalist id="am-ssid-list">
        {#each knownSSIDs as s}<option value={s}></option>{/each}
      </datalist>
      <datalist id="am-subnet-list">
        {#each currentSubnets as sn}<option value={sn}></option>{/each}
      </datalist>
      <datalist id="am-mac-list">
        {#if currentGatewayMAC}<option value={currentGatewayMAC}></option>{/if}
      </datalist>

      {#if saveError}<div class="am-error">{saveError}</div>{/if}

      {#if undoItem}
        <div class="am-undo" role="status">
          <span>{$t('automation.safety.removed')}</span>
          <button type="button" class="am-undo-btn" on:click={undoRemove}>{$t('automation.safety.undo')}</button>
        </div>
      {/if}

      {#if showBackups}
        <div class="am-backups">
          {#if backupError}<div class="am-error">{backupError}</div>{/if}
          {#if backups.length === 0}
            <div class="am-backups-empty">{$t('automation.safety.no_backups')}</div>
          {:else}
            {#each backups as b}
              <div class="am-backup-row">
                <span>{new Date(b.time).toLocaleString()} · {$t('automation.safety.rule_count', { n: b.rule_count })}</span>
                <button type="button" class="am-undo-btn" on:click={() => restoreBackup(b)}>{$t('automation.safety.restore')}</button>
              </div>
            {/each}
          {/if}
        </div>
      {/if}

      <div class="am-footer">
        <button class="am-add" on:click={addRule} disabled={rules.length >= MAX_RULES}>
          <Icon name="plus" size={13} strokeWidth={2.25} /> {$t('automation.add_rule')}
        </button>
        <button class="am-restore" type="button" on:click={openBackups}>{$t('automation.safety.restore_open')}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .am-undo, .am-backup-row {
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    padding: 6px 10px; border-radius: 8px; margin: 6px 0 0;
    background: var(--bg-card); border: 0.5px solid var(--border);
    font: 400 12px/16px var(--font-sans); color: var(--text-primary);
  }
  .am-undo-btn {
    background: transparent; border: 0; color: var(--accent); cursor: pointer;
    font: 600 12px/16px var(--font-sans); padding: 2px 6px; border-radius: 6px;
  }
  .am-undo-btn:hover { background: var(--bg-hover); }
  .am-backups { margin-top: 6px; max-height: 140px; overflow-y: auto; flex-shrink: 0; }
  .am-backups-empty { font: 400 12px/16px var(--font-sans); color: var(--text-muted); padding: 6px 2px; }
  .am-footer { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
  .am-restore {
    background: transparent; border: 0; color: var(--text-secondary); cursor: pointer;
    font: 400 12px/16px var(--font-sans); padding: 4px 8px; border-radius: 6px; margin-left: auto;
  }
  .am-restore:hover { background: var(--bg-hover); color: var(--text-primary); }
  .am-why {
    margin: 0 0 10px;
    padding: 8px 10px;
    border-radius: 8px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    font: 400 12px/16px var(--font-sans);
    color: var(--text-secondary);
  }
  .am-why-net { display: flex; flex-wrap: wrap; gap: 0 6px; }
  .am-why-sep { color: var(--text-muted); }
  .am-why-verdict { margin-top: 3px; font-weight: 500; color: var(--text-primary); }
  .am-why-warn { color: var(--orange, #FF9500); }

  .am-backdrop {
    position: fixed; inset: 0; z-index: 1000;
    background: color-mix(in srgb, #000 45%, transparent);
    display: flex; align-items: center; justify-content: center;
    padding: 24px;
  }
  .am-dialog {
    /* Fixed size — the dialog never grows/shrinks with the rule count.
       Rules scroll inside .am-rules; a few rules just leave empty space. */
    width: 100%; max-width: 560px; height: 540px; max-height: 88vh;
    display: flex; flex-direction: column;
    background: var(--bg-elevated, var(--bg-secondary));
    border: 1px solid var(--border);
    border-radius: 14px; padding: 20px;
    box-shadow: 0 16px 48px rgba(0,0,0,0.35);
  }
  .am-header { display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
  .am-icon {
    width: 36px; height: 36px; border-radius: 9px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    background: color-mix(in srgb, var(--accent) 15%, transparent);
    color: var(--accent);
  }
  .am-header-text { flex: 1; min-width: 0; }
  .am-header-text h3 { margin: 0; font: 600 15px/1.2 var(--font-sans); color: var(--text-primary); }
  .am-sub { margin: 2px 0 0; font: 400 12px/1.2 var(--font-mono); color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .am-close { background: transparent; border: 0; color: var(--text-muted); cursor: pointer; padding: 4px; border-radius: 6px; }
  .am-close:hover { background: var(--bg-hover); color: var(--text-primary); }
  .am-hint { margin: 12px 0; font: 400 12px/1.5 var(--font-sans); color: var(--text-secondary); flex-shrink: 0; }
  /* The one scrolling region: fills the space between the fixed header
     and the fixed add-button, so the dialog stays a constant size. The
     wrap hosts the top/bottom scroll-affordance fades. */
  .am-rules-wrap { flex: 1; min-height: 0; position: relative; display: flex; }
  .am-rules { flex: 1; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; margin: 4px 0; padding-right: 4px; }
  .am-fade {
    position: absolute; left: 0; right: 4px; height: 52px; pointer-events: none;
    opacity: 0; z-index: 2;
    display: flex; justify-content: center;
  }
  @media (prefers-reduced-motion: no-preference) {
    .am-fade { transition: opacity 140ms ease; }
    .am-chevron { animation: am-bob 1.4s ease-in-out infinite; }
  }
  .am-fade.show { opacity: 1; }
  /* Stronger, taller gradient — stays near-solid at the edge so hidden
     rows are clearly cut off, not just barely tinted. */
  .am-fade-top {
    top: 0; align-items: flex-start; padding-top: 2px;
    background: linear-gradient(to bottom,
      var(--bg-elevated, var(--bg-secondary)) 0%,
      color-mix(in srgb, var(--bg-elevated, var(--bg-secondary)) 88%, transparent) 45%,
      transparent 100%);
  }
  .am-fade-bottom {
    bottom: 0; align-items: flex-end; padding-bottom: 2px;
    background: linear-gradient(to top,
      var(--bg-elevated, var(--bg-secondary)) 0%,
      color-mix(in srgb, var(--bg-elevated, var(--bg-secondary)) 88%, transparent) 45%,
      transparent 100%);
  }
  .am-chevron { color: var(--accent); display: inline-flex; }
  .am-chevron-up { transform: rotate(180deg); }
  @keyframes am-bob {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(3px); }
  }
  .am-chevron-up { animation: am-bob-up 1.4s ease-in-out infinite; }
  @keyframes am-bob-up {
    0%, 100% { transform: rotate(180deg) translateY(0); }
    50% { transform: rotate(180deg) translateY(3px); }
  }
  .am-empty { padding: 16px; text-align: center; font: 400 12px var(--font-sans); color: var(--text-muted); border: 1px dashed var(--border); border-radius: 8px; }
  .am-rule {
    display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
    padding: 6px; border: 1px solid transparent; border-radius: 9px;
  }
  .am-rule.am-dragging { opacity: 0.35; }
  @media (prefers-reduced-motion: no-preference) {
    .am-rule { transition: opacity 120ms ease; }
  }
  .am-handle {
    cursor: grab; color: var(--text-muted); font: 700 12px/1 var(--font-sans);
    letter-spacing: -2px; padding: 0 2px; user-select: none; flex-shrink: 0;
  }
  .am-handle:active { cursor: grabbing; }
  .am-priority {
    flex-shrink: 0; width: 18px; height: 18px; border-radius: 50%;
    display: inline-flex; align-items: center; justify-content: center;
    font: 600 10px var(--font-sans); color: var(--text-secondary);
    background: color-mix(in srgb, var(--text-muted) 18%, transparent);
  }
  .am-rule select, .am-rule input {
    font: 400 12px var(--font-sans); color: var(--text-primary);
    background: var(--bg-primary); border: 1px solid var(--border);
    border-radius: 7px; padding: 5px 7px;
  }
  .am-do { font-weight: 600; }
  .am-neg { font-weight: 600; }
  .am-when { font: 400 11px var(--font-sans); color: var(--text-muted); }
  .am-val { flex: 1; min-width: 120px; }
  .am-val-none { color: var(--text-muted); border: 0 !important; background: transparent !important; }
  .am-tags {
    display: flex; flex-wrap: wrap; align-items: center; gap: 4px;
    background: var(--bg-primary); border: 1px solid var(--border);
    border-radius: 7px; padding: 3px 4px;
  }
  .am-tags:focus-within { border-color: var(--accent); }
  .am-tag {
    display: inline-flex; align-items: center; gap: 2px;
    font: 500 11px var(--font-sans); color: var(--text-primary);
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    border-radius: 5px; padding: 2px 3px 2px 6px; max-width: 100%;
    overflow-wrap: anywhere;
  }
  .am-tag-x {
    display: inline-flex; background: transparent; border: 0; padding: 2px;
    color: var(--text-muted); cursor: pointer; border-radius: 4px;
  }
  .am-tag-x:hover { color: var(--text-primary); background: color-mix(in srgb, var(--text-muted) 20%, transparent); }
  .am-rule .am-tags input.am-tag-input {
    flex: 1; min-width: 80px; border: 0; background: transparent; padding: 2px 3px; outline: none;
  }
  .am-rule input.am-invalid {
    border-color: var(--error-text, #ff453a);
    background: color-mix(in srgb, var(--error-text, #ff453a) 8%, var(--bg-primary));
  }
  .am-remove { background: transparent; border: 0; color: var(--text-muted); cursor: pointer; padding: 4px; border-radius: 6px; flex-shrink: 0; }
  .am-remove:hover { background: color-mix(in srgb, var(--red, #ff3b30) 18%, transparent); color: var(--red, #ff3b30); }
  .am-add {
    display: inline-flex; align-self: flex-start; align-items: center; gap: 6px;
    margin-top: 12px; flex-shrink: 0;
    font: 500 12px var(--font-sans); color: var(--accent);
    background: transparent; border: 1px dashed color-mix(in srgb, var(--accent) 45%, transparent);
    border-radius: 8px; padding: 7px 12px; cursor: pointer;
  }
  .am-add:hover:not(:disabled) { background: color-mix(in srgb, var(--accent) 10%, transparent); }
  .am-add:disabled { opacity: 0.45; cursor: not-allowed; }
  .am-error { margin-top: 8px; font: 400 12px var(--font-sans); color: var(--error-text, #ff453a); flex-shrink: 0; }
</style>
