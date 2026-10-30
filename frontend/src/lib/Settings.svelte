<script>
 import { modal, backdrop } from './modal.js';
  import { onDestroy, onMount } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import { t, setLanguage, getLanguage, detectLanguage } from '../i18n/index.js';
  import { applyTheme } from '../stores/theme.js';
  import { connectionStatus, tunnels } from '../stores/tunnels.js';
  import { compactList } from '../stores/ui.js';
  import Icon from './Icon.svelte';
  import ErrorNotice from './ErrorNotice.svelte';
  import { loadSettings, patchSettings, settingsErrors, settingRetryValue } from '../stores/settings.js';
  import { errText } from './errors.js';
  import { firewallDnsLine } from './dns-protection.js';
  import { createEventScope } from './event-scope.js';
  import { startModeKey, isRepairBusy } from './helper-info.js';
  import { rulesFor } from './automationRules.js';
  import { noteOwnSave } from '../stores/automationWatch.js';
  import { stepLabel, stepDetail, refusalNeeds, resetSucceeded } from './reset-dns.js';

  export let TunnelService;
  export let onClose = () => {};
  export let updateInfo = null;
  export let onInstall = null;
  // Tab to open on (the helper-unavailable banner deep-links to 'advanced').
  export let initialTab = 'general';

  const settingsEvents = createEventScope((...args) => Events.On(...args));
  let aboutUpdating = false;
  let aboutShowVpnWarn = false;
  // updateState mirrors UpdateState DTO from GetUpdateState. Used by the
  // About tab to show last-checked timestamp + brew detection + an
  // explicit "Check now" button (the launch-only check we used to do
  // could leave About showing "up to date" for days after a release).
  let updateState = null;
  let aboutChecking = false;
  let aboutCheckResult = '';

  // Diagnostics export (native save dialog on the Go side). The result is
  // shown inline: the app toast renders underneath this modal.
  let exportBusy = false;
  let exportSaved = '';
  let exportError = '';
  async function exportDiagnostics() {
    if (exportBusy) return;
    exportBusy = true;
    exportSaved = '';
    exportError = '';
    try {
      const path = await TunnelService.ExportDiagnostics();
      if (path) exportSaved = $t('settings.export_diagnostics_done', { path });
    } catch (e) {
      exportError = errText(e);
    } finally {
      exportBusy = false;
    }
  }
  // nowTick drives formatLastChecked re-evaluation. Without this, opening
  // Settings and leaving it on the About tab for 10 minutes would still
  // show "just now". Updated every 60 s by an interval started in
  // onMount and torn down in onDestroy.
  let nowTick = Date.now();
  let nowTimer = null;

  async function refreshUpdateState() {
    try { updateState = await TunnelService.GetUpdateState(); } catch (_) {}
  }

  // Last *attempted* manual check, including failures — used to throttle
  // rapid-click. Distinct from updateState.last_check_unix which only
  // tracks *successful* checks (the scheduler's contract).
  let lastManualCheckMs = 0;
  const MANUAL_CHECK_MIN_INTERVAL_MS = 5000;

  async function aboutCheckNow() {
    if (aboutChecking) return;
    // Rate-limit guard. Without this, holding-down "Check now" sends a
    // request per response-time interval (~few hundred ms) and burns the
    // 60-req/hour anonymous GitHub quota for everyone behind the same
    // public IP. The 5 s floor lines up with what a frustrated human can
    // tolerate; a programmatic caller will hit it harmlessly.
    const now = Date.now();
    if (now - lastManualCheckMs < MANUAL_CHECK_MIN_INTERVAL_MS) {
      return;
    }
    lastManualCheckMs = now;
    aboutChecking = true;
    aboutCheckResult = '';
    try {
      const info = await TunnelService.CheckForUpdate();
      await refreshUpdateState();
      if (info?.available) {
        // New version found: the green "up to date" pill flips to the
        // "Update" pill automatically (driven by `updateInfo`), so the
        // pill itself is the success indicator — no extra result line.
        // updateInfo is always declared (export let updateInfo = null);
        // assigning here mutates the prop so the parent's binding sees it.
        updateInfo = info;
      }
      // Up-to-date result is *not* mirrored to aboutCheckResult on
      // purpose: the pill already says "최신 버전입니다", and adding a
      // second identical message below the row causes the UI to shift
      // every time the user clicks "Check now". The "Last checked"
      // timestamp flipping to "just now" is the silent feedback that
      // the click actually did something.
    } catch (e) {
      aboutCheckResult = $t('update.check_failed') + ': ' + (e?.message || e);
    } finally {
      aboutChecking = false;
    }
  }

  // `_tick` parameter forces Svelte to re-run this whenever nowTick
  // changes (every 60 s). Without it, Svelte couldn't tell the result
  // depends on time and would cache the first evaluation forever.
  function formatLastChecked(unix, _tick) {
    if (!unix) {
      // First-launch placeholder: when auto-check is on and the scheduler
      // hasn't fired its first tick yet (30–120 s after startup), show
      // a "scheduled" hint instead of the misleading "Never checked".
      // Dev builds never schedule, so they still get "Never checked".
      if (updateState?.auto_enabled && !updateState?.is_dev_build) {
        return $t('update.first_check_scheduled');
      }
      return $t('update.never_checked');
    }
    const diff = Math.max(0, Date.now() / 1000 - unix);
    let time;
    if (diff < 60) {
      time = $t('update.time_just_now');
    } else if (diff < 3600) {
      time = $t('update.time_minutes_ago', { n: Math.floor(diff / 60) });
    } else if (diff < 86400) {
      time = $t('update.time_hours_ago', { n: Math.floor(diff / 3600) });
    } else {
      time = $t('update.time_days_ago', { n: Math.floor(diff / 86400) });
    }
    return $t('update.last_checked', { time });
  }


  function aboutRequestUpdate() {
    if ($connectionStatus?.state === 'connected') {
      aboutShowVpnWarn = true;
    } else {
      doAboutUpdate();
    }
  }

  async function doAboutUpdate() {
    aboutShowVpnWarn = false;
    aboutUpdating = true;
    aboutCheckResult = '';
    try {
      if (onInstall) await onInstall();
    } catch (e) {
      // Inline, next to the button that failed — the toast alone renders
      // under this modal.
      aboutCheckResult = $t('update.install_failed') + ': ' + (e?.message || e);
    } finally {
      aboutUpdating = false;
    }
  }

  let activeTab = initialTab;
  let settings = {
    language: getLanguage(),
    theme: 'system',
    auto_start: false,
    kill_switch: false,
    dns_protection: false,
    health_check: false,
    pin_interface: false,
    log_level: 'info',
    tunnel_backend: 'userspace',
    tray_icon_style: 'color',
    auto_update_check: true,
    notify_auto_changes: true,
    compact_list: false,
  };
  let loaded = false;
  let loadError = "";
  let pendingPatch = {};
  let busyFields = {};
  // Engine picked while at least one tunnel is connected. Nothing is
  // persisted until the confirmation dialog is accepted.
  let pendingBackend = null;
  // A disconnect invalidates the confirmation's premise; do not leave a
  // stale pending choice that the user could apply to a later connection.
  $: if ($connectionStatus?.state !== 'connected') pendingBackend = null;
  let appVersion = '';
  // This build's GitHub repository (Go: update.RepoURL) for the About links.
  let repoURL = '';
  function openRepo(path) {
    if (repoURL) TunnelService.OpenURL(repoURL.replace(/\/+$/, '') + path);
  }
  let automationBackup = null;

  async function refreshAutomationBackup() {
    try { automationBackup = await TunnelService.GetAutomationBackupStatus(); }
    catch (e) { console.error('load automation backup status:', e); }
  }

  // Tier-3 rule lists (Wi-Fi name lists, connection type) that an older
  // version dropped from the settings file. Restoring only fills tunnels
  // that currently have no rules.
  let restoringV3 = false;
  let restoreV3Error = '';
  async function restoreV3Backup() {
    restoringV3 = true;
    restoreV3Error = '';
    try {
      const names = (await TunnelService.RestoreAutomationV3Backup()) || [];
      // Mark the restored lists as this app's own write so the rule
      // history's outside-change notice does not report them.
      if (names.length) {
        const s = await TunnelService.GetSettings();
        for (const name of names) noteOwnSave(name, rulesFor(s, name));
      }
    }
    catch (e) { restoreV3Error = errText(e); }
    finally {
      restoringV3 = false;
      await refreshAutomationBackup();
    }
  }

  async function load() {
    try {
      const s = await loadSettings(TunnelService);
      if (s) {
        settings.language = s.language || 'auto';
        settings.theme = s.theme || 'system';
        settings.auto_start = s.auto_start ?? false;
        settings.kill_switch = s.kill_switch ?? false;
        settings.dns_protection = s.dns_protection ?? false;
        settings.health_check = s.health_check ?? false;
        settings.pin_interface = s.pin_interface ?? false;
        settings.log_level = s.log_level || 'info';
        settings.tunnel_backend = s.tunnel_backend || 'userspace';
        settings.tray_icon_style = s.tray_icon_style || 'color';
        settings.compact_list = s.compact_list ?? false;
        // Legacy settings.json predates this field — *bool null on
        // the Go side becomes undefined here; default to true to match
        // Settings.AutoUpdateCheckEnabled() semantics.
        settings.auto_update_check = (s.auto_update_check === false) ? false : true;
        settings.notify_auto_changes = s.notify_auto_changes !== false;
      }
      loaded = true;
      loadError = '';
    } catch (e) {
      loaded = false;
      loadError = errText(e);
    }
    await refreshAutomationBackup();
  }
  load();

  async function save() {
    if (!loaded || Object.keys(pendingPatch).length === 0) return;
    const patch = pendingPatch;
    pendingPatch = {};
    try { await patchSettings(TunnelService, patch); }
    catch (_) { /* Shared error state remains visible until this field succeeds. */ }
    finally { await refreshAutomationBackup(); }
  }

  function queuePatch(patch) {
    if (!loaded) return;
    pendingPatch = { ...pendingPatch, ...patch };
    scheduleSave();
  }

  async function applyField(key, value) {
    if (!loaded || busyFields[key]) return;
    settings[key] = value;
    busyFields = { ...busyFields, [key]: true };
    try { await patchSettings(TunnelService, { [key]: value }); }
    catch (_) {
      // A failed live apply can still have persisted intent. Re-read this
      // field instead of guessing with !value or overwriting another edit.
      try { settings[key] = (await loadSettings(TunnelService))[key]; } catch (_) {}
    } finally { busyFields = { ...busyFields, [key]: false }; }
    // A failed apply broadcasts no settings_changed; re-read the truth.
    if (key === 'dns_protection' || key === 'kill_switch') refreshFirewall();
  }

  // ---- DNS protection truth (Advanced tab) ----
  // Firewall.Status reads pf back on macOS, so it is fetched on demand —
  // when the Advanced tab opens and after a protection setting changes —
  // never on a timer. Unavailable (older helper, helper down) shows nothing.
  let fwStatus = { available: false };
  let fwSeq = 0;
  async function refreshFirewall() {
    const seq = ++fwSeq;
    let next = { available: false };
    try { next = (await TunnelService.GetFirewallStatus()) || { available: false }; } catch (_) {}
    if (seq === fwSeq) fwStatus = next;
  }
  $: dnsLine = firewallDnsLine($t, fwStatus, settings.dns_protection, ($connectionStatus?.active_tunnels || []).length > 0);
  let lastTab = '';
  $: if (activeTab !== lastTab) {
    lastTab = activeTab;
    if (activeTab === 'advanced') refreshFirewall();
  }

  let saveTimer = null;
  function scheduleSave(event) {
    if (event?.target?.id === 'auto-update') pendingPatch.auto_update_check = settings.auto_update_check;
    if (!loaded) return;
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      saveTimer = null;
      save();
    }, 300);
  }

  function onThemeChange(e) {
    settings.theme = e.target.value;
    applyTheme(settings.theme);
    queuePatch({ theme: settings.theme });
  }

  function onLanguageChange(e) {
    settings.language = e.target.value;
    const resolved = settings.language === 'auto' ? detectLanguage() : settings.language;
    setLanguage(resolved);
    queuePatch({ language: settings.language });
  }

  function onCompactListChange(e) {
    settings.compact_list = e.target.checked;
    // Update the shared store so the tunnel list re-renders immediately,
    // then persist.
    compactList.set(settings.compact_list);
    queuePatch({ compact_list: settings.compact_list });
  }

  function onNotifyAutoChange(e) {
    settings.notify_auto_changes = e.target.checked;
    queuePatch({ notify_auto_changes: settings.notify_auto_changes });
  }

  function onAutoStartChange(e) {
    settings.auto_start = e.target.checked;
    queuePatch({ auto_start: settings.auto_start });
  }

  function onLogLevelChange(e) { applyField('log_level', e.target.value); }
  function onTunnelBackendChange(e) {
    const next = e.target.value;
    if ($connectionStatus?.state === 'connected' && next !== settings.tunnel_backend) {
      pendingBackend = next;
      // Keep the select on the persisted value until the user confirms.
      e.target.value = settings.tunnel_backend;
      return;
    }
    applyField('tunnel_backend', next);
  }

  function confirmBackendChange() {
    const next = pendingBackend;
    pendingBackend = null;
    if (next) applyField('tunnel_backend', next);
  }

  function cancelBackendChange() {
    pendingBackend = null;
  }
  function onKillSwitchChange(e) { applyField('kill_switch', e.target.checked); }
  function onDnsProtectionChange(e) { applyField('dns_protection', e.target.checked); }
  function onPinInterfaceChange(e) { applyField('pin_interface', e.target.checked); }
  function onHealthCheckChange(e) { applyField('health_check', e.target.checked); }

  // Reflect settings applied by another client (the CLI) live, so the
  // toggle doesn't sit stale while the helper actually changed state.
  let settingsChangedUnsub = null;
  function onSettingsChanged(event) {
    const p = event?.data || {};
    if (p.kill_switch != null) settings.kill_switch = p.kill_switch;
    if (p.dns_protection != null) settings.dns_protection = p.dns_protection;
    if ((p.dns_protection != null || p.kill_switch != null) && activeTab === 'advanced') refreshFirewall();
    if (p.health_check != null) settings.health_check = p.health_check;
    if (p.pin_interface != null) settings.pin_interface = p.pin_interface;
    if (p.log_level != null) settings.log_level = p.log_level;
    if (p.tunnel_backend != null) {
      settings.tunnel_backend = p.tunnel_backend;
      if (pendingBackend === p.tunnel_backend) pendingBackend = null;
    }
    settings = settings; // trigger reactivity
  }

  onDestroy(() => {
    window.removeEventListener('keydown', onKeyDown);
    settingsEvents.dispose();
    if (settingsChangedUnsub) settingsChangedUnsub();
    if (saveTimer) {
      clearTimeout(saveTimer);
      save();
    }
    if (nowTimer) clearInterval(nowTimer);
  });

  function tabKeydown(event) {
    const tabs = ['general', 'advanced', 'about'];
    const direction = ['ArrowDown', 'ArrowRight'].includes(event.key) ? 1 : ['ArrowUp', 'ArrowLeft'].includes(event.key) ? -1 : 0;
    if (!direction && !['Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    activeTab = event.key === 'Home' ? tabs[0] : event.key === 'End' ? tabs.at(-1) : tabs[(tabs.indexOf(activeTab) + direction + tabs.length) % tabs.length];
    event.currentTarget.parentElement.querySelectorAll('[role="tab"]')[tabs.indexOf(activeTab)].focus();
  }

  function close() {
    if (saveTimer) {
      clearTimeout(saveTimer);
      saveTimer = null;
      save();
    }
    onClose();
  }

  function onKeyDown(e) {
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
    }
  }

  // ---- Helper card and Repair (Advanced) ----
  let helperInfo = { available: false };
  async function refreshHelperInfo() {
    try { helperInfo = (await TunnelService.GetHelperInfo()) || { available: false }; }
    catch (_) { helperInfo = { available: false }; }
  }
  function helperModeLabel(mode) {
    const key = startModeKey(mode);
    return key ? $t('settings.helper_mode_' + key) : (mode || '—');
  }
  function helperReasonLabel(mode) {
    const key = startModeKey(mode);
    return key ? $t('settings.helper_reason_' + key) : '—';
  }
  function helperStarted(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleString();
  }
  $: if (activeTab === 'advanced') refreshHelperInfo();

  // Repair helper: the only action on this screen that prompts for a password.
  // The confirm sheet comes first; WireGuide's own dialog then explains the
  // prompt before the system asks.
  let repairStage = ''; // '' | 'confirm' | 'running'
  let repairError = '';
  let repairDone = false;
  function askRepair() {
    repairError = '';
    repairDone = false;
    repairStage = 'confirm';
  }
  function cancelRepair() {
    if (repairStage === 'confirm') repairStage = '';
  }
  async function doRepair() {
    repairStage = 'running';
    repairError = '';
    try {
      await TunnelService.RepairHelper();
      repairDone = true;
      await refreshHelperInfo();
    } catch (e) {
      const msg = errText(e);
      repairError = isRepairBusy(msg) ? $t('settings.helper_repair_busy') : msg;
    }
    repairStage = '';
  }

  // ---- Reset DNS & firewall (Advanced) ----
  // Escape hatch: the helper removes WireGuide's firewall rules and split DNS,
  // retries any retained DNS recovery and flushes the DNS cache. It refuses
  // while tunnels are up or the kill switch is on unless the user opts in.
  let resetStage = ''; // '' | 'confirm' | 'running'
  let resetForce = false;
  let resetKsOff = false;
  let resetShowForce = false;
  let resetShowKsOff = false;
  let resetRefusal = null; // refused response from the helper
  let resetResult = null;
  let resetError = '';
  async function askReset() {
    resetError = '';
    resetResult = null;
    resetRefusal = null;
    resetForce = false;
    resetKsOff = false;
    resetShowKsOff = !!settings.kill_switch;
    resetShowForce = false;
    try {
      const list = (await TunnelService.ListTunnels()) || [];
      resetShowForce = list.some((x) => x.is_connected);
    } catch (_) {}
    resetStage = 'confirm';
  }
  function cancelReset() {
    if (resetStage === 'confirm') resetStage = '';
  }
  async function doReset() {
    resetStage = 'running';
    resetError = '';
    try {
      const resp = await TunnelService.ResetDNS(resetForce, resetKsOff);
      if (resp?.refused) {
        // The helper also sees wanted and pending-restore tunnels: show the
        // option it asked for and keep the sheet open.
        const need = refusalNeeds(resp);
        resetShowForce = resetShowForce || need.force;
        resetShowKsOff = resetShowKsOff || need.killSwitchOff;
        resetRefusal = resp;
        resetStage = 'confirm';
        return;
      }
      resetResult = resp;
    } catch (e) {
      resetError = errText(e);
    }
    resetStage = '';
  }

  // Register the listener synchronously and tear it down via
  // onDestroy. An `onMount(async ...)` callback returns a Promise,
  // not a cleanup function, so the cleanup we used to put after the
  // `await` was silently dropped — every Settings open leaked another
  // window-level keydown listener that called save() on stale state.
  onMount(() => {
    window.addEventListener('keydown', onKeyDown);
    settingsChangedUnsub = Events.On('settings_changed', onSettingsChanged);
    // A restarted or repaired helper changes pid/start time: refresh the card.
    settingsEvents.on('helper', () => { if (activeTab === 'advanced') return refreshHelperInfo(); });
    settingsEvents.on('helper_reset', () => { if (activeTab === 'advanced') return refreshHelperInfo(); });
    // 60 s tick so the "Last checked Nm ago" line keeps current while
    // the Settings modal is open. Cleanup is in onDestroy above.
    nowTimer = setInterval(() => { nowTick = Date.now(); }, 60000);
    (async () => {
      try { appVersion = await TunnelService.GetVersion(); } catch (_) {}
      try { repoURL = await TunnelService.GetRepoURL(); } catch (_) {}
      await refreshUpdateState();
    })();
  });
</script>

<div class="modal-backdrop" use:backdrop={close}>
  <div class="modal" use:modal={close} tabindex="-1" role="dialog" aria-modal="true" aria-labelledby="settings-title">
    <h3 id="settings-title">{$t('settings.title')}</h3>

    {#if loadError}<ErrorNotice message={$t('settings.load_failed') + ' ' + loadError} onRetry={load}/>{/if}
    {#each Object.entries($settingsErrors) as [key, failure] (key)}<ErrorNotice message={$t('settings.save_failed') + ' ' + failure} busy={!loaded || busyFields[key]} onRetry={() => applyField(key, settingRetryValue(key))}/>{/each}
    <fieldset disabled={!loaded} class="settings-fields">
    <div class="settings-layout">
      <div class="settings-sidebar" role="tablist" aria-orientation="vertical" aria-label={$t('settings.title')}>
        <button role="tab" tabindex={activeTab === 'general' ? 0 : -1} on:keydown={tabKeydown} aria-selected={activeTab === 'general'} class:active={activeTab === 'general'} on:click={() => activeTab = 'general'}>
          <Icon name="settings" size={14} strokeWidth={1.75} />
          <span>{$t('settings.general')}</span>
        </button>
        <button role="tab" tabindex={activeTab === 'advanced' ? 0 : -1} on:keydown={tabKeydown} aria-selected={activeTab === 'advanced'} class:active={activeTab === 'advanced'} on:click={() => activeTab = 'advanced'}>
          <Icon name="wrench" size={14} strokeWidth={1.75} />
          <span>{$t('settings.advanced')}</span>
        </button>
        <button role="tab" tabindex={activeTab === 'about' ? 0 : -1} on:keydown={tabKeydown} aria-selected={activeTab === 'about'} class:active={activeTab === 'about'} on:click={() => activeTab = 'about'}>
          <Icon name="info" size={14} strokeWidth={1.75} />
          <span>{$t('settings.about')}</span>
        </button>
      </div>

      <div class="settings-content" role="tabpanel">
        {#if automationBackup?.error || automationBackup?.different || automationBackup?.recovery_copies > 0}
          <div class="settings-section" role="status">
            <p class="setting-desc">{$t(automationBackup.error ? 'settings.automation_backup_error' : 'settings.automation_backup_recovery')}</p>
            {#if automationBackup.error}<p class="setting-desc">{automationBackup.error}</p>{/if}
          </div>
        {/if}
        {#if automationBackup?.v3?.error || automationBackup?.v3?.recoverable?.length > 0 || restoreV3Error}
          <div class="settings-section" role="status">
            {#if automationBackup?.v3?.error}
              <p class="setting-desc">{$t('settings.automation_backup_error')}</p>
              <p class="setting-desc">{automationBackup.v3.error}</p>
            {:else if automationBackup?.v3?.recoverable?.length > 0}
              <p class="setting-desc">{$t('settings.automation_v3_recoverable', { names: automationBackup.v3.recoverable.join(', ') })}</p>
              <button type="button" class="check-btn" disabled={restoringV3} on:click={restoreV3Backup}>{$t('settings.automation_v3_restore')}</button>
            {/if}
            {#if restoreV3Error}<ErrorNotice message={$t('settings.automation_v3_restore_failed') + ' ' + restoreV3Error} busy={restoringV3} onRetry={restoreV3Backup}/>{/if}
          </div>
        {/if}
        {#if activeTab === 'general'}
          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_appearance')}</h4>
            <div class="settings-card">
              <div class="setting-row">
                <label class="setting-label" for="theme-select">{$t('settings.theme')}</label>
                <select id="theme-select" value={settings.theme} on:change={onThemeChange}>
                  <option value="dark">{$t('settings.theme_dark')}</option>
                  <option value="light">{$t('settings.theme_light')}</option>
                  <option value="system">{$t('settings.theme_system')}</option>
                </select>
              </div>
              <div class="setting-row">
                <label class="setting-label" for="lang-select">{$t('settings.language')}</label>
                <select id="lang-select" value={settings.language} on:change={onLanguageChange}>
                  <option value="auto">{$t('settings.lang_auto')}</option>
                  <option value="en">English</option>
                  <option value="ko">한국어</option>
                  <option value="ja">日本語</option>
                  <option value="zh">简体中文</option>
                </select>
              </div>
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="compact-list">{$t('settings.compact_list')}</label>
                  <p class="setting-desc">{$t('settings.compact_list_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="compact-list" type="checkbox" checked={settings.compact_list} on:change={onCompactListChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_startup')}</h4>
            <div class="settings-card">
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="auto-start">{$t('settings.auto_start')}</label>
                  <p class="setting-desc">{$t('settings.auto_start_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="auto-start" type="checkbox" checked={settings.auto_start} on:change={onAutoStartChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_notifications')}</h4>
            <div class="settings-card">
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="notify-auto">{$t('settings.notify_auto_changes')}</label>
                  <p class="setting-desc">{$t('settings.notify_auto_changes_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="notify-auto" type="checkbox" checked={settings.notify_auto_changes} on:change={onNotifyAutoChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_updates')}</h4>
            <div class="settings-card">
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="auto-update">{$t('settings.auto_update_check')}</label>
                  <p class="setting-desc">{$t('settings.auto_update_check_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="auto-update" type="checkbox" bind:checked={settings.auto_update_check} on:change={scheduleSave} />
                  <span class="toggle-track"></span>
                </label>
              </div>
            </div>
          </div>

        {:else if activeTab === 'advanced'}
          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_security')}</h4>
            <div class="settings-card">
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="kill-switch">{$t('settings.kill_switch')}</label>
                  <p class="setting-desc">{$t('settings.kill_switch_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="kill-switch" disabled={busyFields.kill_switch} type="checkbox"
                    checked={settings.kill_switch}
                    on:change={onKillSwitchChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="dns-protection">{$t('settings.dns_protection')}</label>
                  <p class="setting-desc">{$t('settings.dns_protection_hint')}</p>
                  {#if dnsLine}
                    <p class="setting-live setting-live-{dnsLine.tone}" aria-live="polite">{dnsLine.text}</p>
                  {/if}
                </div>
                <label class="toggle">
                  <input id="dns-protection" disabled={busyFields.dns_protection} type="checkbox"
                    checked={settings.dns_protection}
                    on:change={onDnsProtectionChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_connection')}</h4>
            <div class="settings-card">
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="health-check">{$t('settings.health_check')}</label>
                  <p class="setting-desc">{$t('settings.health_check_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="health-check" disabled={busyFields.health_check} type="checkbox"
                    checked={settings.health_check}
                    on:change={onHealthCheckChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="pin-interface">{$t('settings.pin_interface')}</label>
                  <p class="setting-desc">{$t('settings.pin_interface_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="pin-interface" disabled={busyFields.pin_interface} type="checkbox"
                    checked={settings.pin_interface}
                    on:change={onPinInterfaceChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
              {#if /Windows/i.test(navigator.userAgent)}
                <div class="setting-row">
                  <div class="setting-info">
                    <label class="setting-label" for="tunnel-backend">{$t('settings.tunnel_backend')}</label>
                    <p class="setting-desc">{$t('settings.tunnel_backend_hint')}</p>
                  </div>
                  <select id="tunnel-backend" disabled={busyFields.tunnel_backend} value={settings.tunnel_backend} on:change={onTunnelBackendChange}>
                    <option value="userspace">{$t('settings.tunnel_backend_userspace')}</option>
                    <option value="kernel">{$t('settings.tunnel_backend_kernel')}</option>
                  </select>
                </div>
              {/if}
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_helper')}</h4>
            <div class="settings-card">
              {#if helperInfo.available}
                <div class="setting-row"><span class="setting-label">{$t('settings.helper_version')}</span><span class="info-val">{helperInfo.app_version || '—'}</span></div>
                {#if helperInfo.start_mode}
                  <div class="setting-row"><span class="setting-label">{$t('settings.helper_mode')}</span><span class="info-val">{helperModeLabel(helperInfo.start_mode)}</span></div>
                  <div class="setting-row"><span class="setting-label">{$t('settings.helper_reason')}</span><span class="info-val">{helperReasonLabel(helperInfo.start_mode)}</span></div>
                  <div class="setting-row"><span class="setting-label">{$t('settings.helper_socket')}</span><span class="info-val mono">{helperInfo.socket_path || '—'}</span></div>
                  <div class="setting-row"><span class="setting-label">{$t('settings.helper_started')}</span><span class="info-val">{helperStarted(helperInfo.started_at)}</span></div>
                {:else}
                  <div class="setting-row"><p class="setting-desc">{$t('settings.helper_old')}</p></div>
                {/if}
                <div class="setting-row"><span class="setting-label">{$t('settings.helper_pid')}</span><span class="info-val">{helperInfo.pid || '—'}</span></div>
                <div class="setting-row"><span class="setting-label">{$t('settings.helper_attached')}</span><span class="info-val">{helperInfo.gui_attached ? $t('settings.helper_attached_yes') : $t('settings.helper_attached_no')}</span></div>
              {:else}
                <div class="setting-row"><p class="setting-desc">{$t('settings.helper_unavailable')}</p></div>
              {/if}
              <div class="setting-row">
                <div class="setting-info">
                  <p class="setting-desc">{$t('settings.helper_repair_hint')}</p>
                  {#if repairDone}<p class="setting-live-ok">{$t('settings.helper_repair_done')}</p>{/if}
                  {#if repairError}<ErrorNotice message={repairError} />{/if}
                </div>
                <button class="warn-btn warn-proceed" disabled={repairStage !== ''} on:click={askRepair}>
                  {repairStage === 'running' ? $t('settings.helper_repairing') : $t('settings.helper_repair')}
                </button>
              </div>
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_reset')}</h4>
            <div class="settings-card">
              <div class="setting-row">
                <div class="setting-info">
                  <p class="setting-desc">{$t('settings.reset_dns_hint')}</p>
                  {#if resetError}<ErrorNotice message={resetError} />{/if}
                </div>
                <button class="warn-btn warn-proceed" disabled={resetStage !== ''} on:click={askReset}>
                  {resetStage === 'running' ? $t('settings.reset_dns_running') : $t('settings.reset_dns')}
                </button>
              </div>
              {#if resetResult}
                <div class="setting-row reset-result">
                  <div class="setting-info">
                    <p class={resetSucceeded(resetResult) ? 'setting-live-ok' : 'setting-desc'}>
                      {resetSucceeded(resetResult) ? $t('settings.reset_dns_done') : $t('settings.reset_dns_partial')}
                    </p>
                    <ul class="reset-steps">
                      {#each resetResult.steps || [] as step}
                        <li class:failed={!step.ok}>
                          <span class="reset-mark" aria-hidden="true">{step.ok ? '✓' : '✕'}</span>
                          <span class="reset-step-name">{stepLabel($t, step.name)}</span>
                          <span class="reset-step-detail">{stepDetail($t, step)}</span>
                        </li>
                      {/each}
                    </ul>
                  </div>
                </div>
              {/if}
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_logging')}</h4>
            <div class="settings-card">
              <div class="setting-row">
                <label class="setting-label" for="log-level">{$t('settings.log_level')}</label>
                <select id="log-level" disabled={busyFields.log_level} value={settings.log_level} on:change={onLogLevelChange}>
                  <option value="debug">{$t('settings.log_level_debug')}</option>
                  <option value="info">{$t('settings.log_level_info')}</option>
                  <option value="warn">{$t('settings.log_level_warn')}</option>
                  <option value="error">{$t('settings.log_level_error')}</option>
                </select>
              </div>
              <div class="setting-row">
                <div class="setting-info">
                  <span class="setting-label">{$t('settings.export_diagnostics')}</span>
                  <p class="setting-desc">{$t('settings.export_diagnostics_hint')}</p>
                  {#if exportSaved}<p class="setting-desc" role="status">{exportSaved}</p>{/if}
                </div>
                <button type="button" class="check-btn" on:click={exportDiagnostics} disabled={exportBusy}>
                  {exportBusy ? $t('settings.export_diagnostics_busy') : $t('settings.export_diagnostics')}
                </button>
              </div>
              {#if exportError}<ErrorNotice message={$t('settings.export_diagnostics_failed') + ': ' + exportError} busy={exportBusy} onRetry={exportDiagnostics}/>{/if}
            </div>
          </div>

        {:else if activeTab === 'about'}
          <div class="about-tab">
            <div class="about-hero">
              <img src="/wireguide.svg" alt="WireGuide" class="about-logo" />
              <div class="about-hero-text">
                <h2 class="about-name">WireGuide</h2>
                <p class="about-tagline-text">{$t('settings.about_tagline')}</p>
                <div class="about-pills">
                  <span class="pill pill-version">{appVersion ? `v${appVersion}` : 'v—'}</span>
                  {#if updateInfo?.available}
                    <button class="pill pill-update" on:click={aboutRequestUpdate} disabled={aboutUpdating}>
                      <span class="pill-dot"></span>
                      {aboutUpdating ? $t('update.updating') : $t('update.update_now')}
                    </button>
                  {:else if updateState?.last_check_unix && updateState.last_seen_version === appVersion && !aboutChecking && !aboutCheckResult}
                    <span class="pill pill-ok">
                      <Icon name="check" size={11} strokeWidth={2.5} />
                      {$t('settings.up_to_date')}
                    </span>
                  {/if}
                </div>
                <div class="about-check-row">
                  <button class="check-btn" on:click={aboutCheckNow} disabled={aboutChecking}>
                    {aboutChecking ? $t('update.checking') : $t('update.check_now')}
                  </button>
                  <span class="check-meta">{formatLastChecked(updateState?.last_check_unix, nowTick)}</span>
                </div>
                {#if updateState?.is_dev_build}
                  <!-- Explains why "Never checked" sticks even on a healthy install:
                       dev builds intentionally skip the auto-check loop so local
                       iteration doesn't burn the GitHub API quota. Manual button
                       still works, hence the "use the button" framing. -->
                  <div class="check-hint">{$t('update.dev_build_hint')}</div>
                {:else if updateState && !updateState.auto_enabled}
                  <div class="check-hint">{$t('update.auto_off_hint')}</div>
                {/if}
                {#if aboutCheckResult}
                  <div class="check-result">{aboutCheckResult}</div>
                {/if}
              </div>
            </div>

            <p class="about-desc-paragraph">{$t('settings.about_desc')}</p>

            {#if aboutShowVpnWarn}
              <div class="about-vpn-warn">
                <Icon name="triangle-alert" size={16} strokeWidth={2} />
                <div class="vpn-warn-body">
                  <p>{$t('update.vpn_warning')}</p>
                  <div class="vpn-warn-actions">
                    <button class="warn-btn warn-proceed" on:click={doAboutUpdate}>{$t('update.proceed')}</button>
                    <button class="warn-btn warn-cancel" on:click={() => aboutShowVpnWarn = false}>{$t('update.cancel')}</button>
                  </div>
                </div>
              </div>
            {/if}

            <div class="about-links">
              <button class="link-btn" disabled={!repoURL} on:click={() => openRepo('')}>GitHub</button>
              <button class="link-btn" disabled={!repoURL} on:click={() => openRepo('/releases')}>{$t('settings.about_releases')}</button>
              <button class="link-btn" disabled={!repoURL} on:click={() => openRepo('/issues')}>{$t('settings.about_issues')}</button>
              <button class="link-btn" disabled={!repoURL} on:click={() => openRepo('/blob/main/LICENSE')}>{$t('settings.about_license')}</button>
            </div>

          </div>
        {/if}
      </div>
    </div>

    </fieldset>
    <div class="modal-footer">
      <div class="footer-info">
        <span class="footer-credit-label">{$t('settings.about_made_by')}</span>
        <button class="footer-link" on:click={() => TunnelService.OpenURL('https://github.com/korjwl1')}>@korjwl1</button>
        <span class="footer-sep">·</span>
        <span class="footer-credit-text">{$t('settings.about_footer_copyright')}</span>
      </div>
      <button type="button" class="btn-close" on:click={close}>{$t('settings.close')}</button>
    </div>
  </div>

  {#if repairStage === 'confirm'}
    <div class="confirm-backdrop" use:backdrop={cancelRepair}>
      <div class="confirm-dialog" use:modal={cancelRepair} role="dialog" aria-modal="true" aria-labelledby="repair-confirm-title" tabindex="-1">
        <div class="dialog-header">
          <div class="dialog-icon-tile">
            <Icon name="triangle-alert" size={18} strokeWidth={2} />
          </div>
          <div class="dialog-header-text">
            <h3 id="repair-confirm-title">{$t('settings.helper_repair_title')}</h3>
          </div>
        </div>
        <p class="dialog-message">{$t('settings.helper_repair_confirm')}</p>
        <div class="confirm-footer">
          <button class="dialog-btn dialog-btn-ghost" on:click={cancelRepair}>{$t('confirm.no')}</button>
          <button class="dialog-btn dialog-btn-primary" on:click={doRepair}>{$t('settings.helper_repair_go')}</button>
        </div>
      </div>
    </div>
  {/if}

  {#if resetStage !== ''}
    <div class="confirm-backdrop" use:backdrop={cancelReset}>
      <div class="confirm-dialog" use:modal={cancelReset} role="dialog" aria-modal="true" aria-labelledby="reset-confirm-title" tabindex="-1">
        <div class="dialog-header">
          <div class="dialog-icon-tile">
            <Icon name="triangle-alert" size={18} strokeWidth={2} />
          </div>
          <div class="dialog-header-text">
            <h3 id="reset-confirm-title">{$t('settings.reset_dns_title')}</h3>
          </div>
        </div>
        <p class="dialog-message">{$t('settings.reset_dns_intro')}</p>
        <ul class="reset-list">
          <li>{$t('settings.reset_dns_item_firewall')}</li>
          <li>{$t('settings.reset_dns_item_split')}</li>
          <li>{$t('settings.reset_dns_item_recovery')}</li>
          <li>{$t('settings.reset_dns_item_cache')}</li>
        </ul>
        {#if resetRefusal}
          <p class="dialog-message reset-refusal" role="alert">
            {resetRefusal.reason === 'kill_switch_on'
              ? $t('settings.reset_dns_refused_ks')
              : $t('settings.reset_dns_refused_tunnels', { tunnels: (resetRefusal.connected_tunnels || []).join(', ') })}
          </p>
        {/if}
        {#if resetShowForce}
          <label class="reset-option">
            <input type="checkbox" bind:checked={resetForce} disabled={resetStage === 'running'} />
            <span>{$t('settings.reset_dns_force')}</span>
          </label>
        {/if}
        {#if resetShowKsOff}
          <label class="reset-option">
            <input type="checkbox" bind:checked={resetKsOff} disabled={resetStage === 'running'} />
            <span>{$t('settings.reset_dns_ks_off')}</span>
          </label>
        {/if}
        <div class="confirm-footer">
          <button class="dialog-btn dialog-btn-ghost" disabled={resetStage === 'running'} on:click={cancelReset}>{$t('confirm.no')}</button>
          <button class="dialog-btn dialog-btn-primary" disabled={resetStage === 'running'} on:click={doReset}>
            {resetStage === 'running' ? $t('settings.reset_dns_running') : $t('settings.reset_dns_go')}
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if pendingBackend}
    <div class="confirm-backdrop" use:backdrop={cancelBackendChange}>
      <div class="confirm-dialog" use:modal={cancelBackendChange} role="dialog" aria-modal="true" aria-labelledby="backend-confirm-title" tabindex="-1">
        <div class="dialog-header">
          <div class="dialog-icon-tile">
            <Icon name="triangle-alert" size={18} strokeWidth={2} />
          </div>
          <div class="dialog-header-text">
            <h3 id="backend-confirm-title">{$t('settings.tunnel_backend_confirm_title')}</h3>
          </div>
        </div>
        <p class="dialog-message">{$t('settings.tunnel_backend_confirm_message', { engine: $t(pendingBackend === 'kernel' ? 'settings.tunnel_backend_kernel' : 'settings.tunnel_backend_userspace') })}</p>
        <div class="confirm-footer">
          <button class="dialog-btn dialog-btn-ghost" on:click={cancelBackendChange}>{$t('confirm.no')}</button>
          <button class="dialog-btn dialog-btn-primary" on:click={confirmBackendChange}>
            {$t('settings.tunnel_backend_switch')}
          </button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .settings-fields { border: 0; padding: 0; margin: 0; min-width: 0; display: flex; flex-direction: column; flex: 1; min-height: 0; }
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg, rgba(0,0,0,0.45));
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 200;
  }
  .modal {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: 14px;
    padding: 20px 22px 14px;
    width: 720px;
    height: 520px;
    display: flex;
    flex-direction: column;
    box-shadow: var(--shadow-lg);
    overflow: hidden;
    box-sizing: border-box;
  }
  h3 {
    margin: 0 0 14px;
    font: 700 16px/22px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-primary);
    letter-spacing: -0.01em;
    flex-shrink: 0;
  }

  /* Split layout — fixed height with internal scroll */
  .settings-layout {
    display: flex;
    gap: 16px;
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }

  /* Sidebar — sits on the same modal surface as the content area.
     No background panel, no border. Visual hierarchy comes from
     the active tab item's own fill + content-area structure
     (Linear / Notion / macOS System Settings pattern). */
  .settings-sidebar {
    display: flex;
    flex-direction: column;
    gap: 2px;
    width: 148px;
    flex-shrink: 0;
    padding: 0 6px 0 0;
    overflow-y: auto;
  }
  .settings-sidebar button {
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 8px 10px;
    background: none;
    border: none;
    border-radius: 8px;
    color: var(--text-secondary);
    font: 500 13px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
    text-align: left;
    min-height: 34px;
    width: 100%;
    letter-spacing: -0.005em;
  }
  .settings-sidebar button :global(.icon) {
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .settings-sidebar button:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .settings-sidebar button:hover :global(.icon) {
    color: var(--text-primary);
  }
  /* Active state: neutral gray fill + bold primary text + accent ICON.
     macOS HIG sidebar pattern — only the icon carries brand color,
     the row itself stays calm so the user's eye lands on content,
     not the active nav row. */
  .settings-sidebar button.active {
    background: var(--bg-active);
    color: var(--text-primary);
    font-weight: 600;
  }
  .settings-sidebar button.active :global(.icon) {
    color: var(--accent);
  }
  .settings-sidebar button:focus,
  .settings-sidebar button:focus-visible {
    outline: none;
  }
  @media (prefers-reduced-motion: no-preference) {
    .settings-sidebar button {
      transition: background-color 140ms ease, color 140ms ease;
    }
  }

  /* Content area — independent scroll */
  .settings-content {
    flex: 1;
    min-width: 0;
    overflow-y: auto;
    padding-right: 4px;
  }
  .settings-content::-webkit-scrollbar { width: 8px; }
  .settings-content::-webkit-scrollbar-track { background: transparent; }
  .settings-content::-webkit-scrollbar-thumb {
    background-color: color-mix(in srgb, var(--text-muted) 40%, transparent);
    border-radius: 4px;
    border: 2px solid transparent;
    background-clip: content-box;
  }
  .settings-content::-webkit-scrollbar-thumb:hover {
    background-color: var(--text-muted);
  }

  /* ---- Section + Card layout (M3 / iOS Settings style) ---- */
  .settings-section {
    margin-bottom: var(--space-4, 12px);
  }
  .section-title {
    margin: 0 0 6px var(--space-1, 4px);
    font: 500 10px/13px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .settings-card {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }

  /* Setting rows inside cards — spacing alone separates (no hairlines).
     The card surface itself is the grouping cue (Linear / Notion pattern). */
  .setting-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 11px 14px;
    gap: var(--space-3);
  }
  .setting-row + .setting-row {
    padding-top: 3px;
  }
  .setting-row--toggle {
    align-items: flex-start;
    padding: 12px 14px;
  }
  .setting-row--toggle + .setting-row--toggle {
    padding-top: 4px;
  }
  .setting-info {
    flex: 1;
    min-width: 0;
  }
  .setting-label {
    display: block;
    font: 400 13px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-primary);
    cursor: pointer;
  }
  .info-val {
    font: 400 12px/16px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
    text-align: right;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .info-val.mono { font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace); font-size: 11px; }
  .reset-list {
    margin: 0 0 12px;
    padding-left: 18px;
    font: 400 12px/17px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
  }
  .reset-refusal { color: var(--orange, #ff9f0a); }
  .reset-option {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    margin: 0 0 10px;
    font: 400 12px/17px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-primary);
    cursor: pointer;
  }
  .reset-steps {
    list-style: none;
    margin: 6px 0 0;
    padding: 0;
    font: 400 11px/16px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
  }
  .reset-steps li { display: flex; gap: 6px; flex-wrap: wrap; }
  .reset-steps li.failed { color: var(--red, #ff453a); }
  .reset-mark { width: 12px; flex: none; }
  .reset-step-name { font-weight: 600; }
  .reset-step-detail { min-width: 0; overflow-wrap: anywhere; }
  .setting-live-ok {
    margin: 6px 0 0;
    font: 400 11px/15px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--green, #30d158);
  }
  .setting-desc {
    margin: 3px 0 0;
    padding: 0;
    font: 400 11px/15px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-muted);
    letter-spacing: 0.01em;
  }
  .setting-live {
    margin: 4px 0 0;
    font: 500 11px/15px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    overflow-wrap: anywhere;
  }
  .setting-live-ok { color: var(--green); }
  .setting-live-muted { color: var(--text-secondary); }
  .setting-live-error { color: var(--red); }

  /* ---- Toggle switch (34×20px, 200ms slide) ---- */
  .toggle {
    position: relative;
    display: inline-block;
    width: 34px;
    height: 20px;
    flex-shrink: 0;
    cursor: pointer;
    margin-top: 1px;
  }
  .toggle input {
    opacity: 0;
    width: 0;
    height: 0;
    position: absolute;
  }
  .toggle-track {
    position: absolute;
    inset: 0;
    background: color-mix(in srgb, var(--text-muted) 35%, var(--bg-input));
    border-radius: 10px;
    border: 0.5px solid color-mix(in srgb, var(--border) 60%, transparent);
  }
  .toggle-track::before {
    content: '';
    position: absolute;
    width: 16px;
    height: 16px;
    left: 2px;
    top: 2px;
    background: #fff;
    border-radius: 50%;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.25);
  }
  @media (prefers-reduced-motion: no-preference) {
    .toggle-track {
      transition: background-color 200ms ease, border-color 200ms ease;
    }
    .toggle-track::before {
      transition: transform 200ms ease;
    }
  }
  .toggle input:checked + .toggle-track {
    background: var(--green);
    border-color: var(--green);
  }
  .toggle input:checked + .toggle-track::before {
    transform: translateX(14px);
  }
  .toggle input:focus-visible + .toggle-track {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  select {
    -webkit-appearance: none;
    appearance: none;
    height: 28px;
    padding: 0 28px 0 12px;
    background-color: var(--bg-input);
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%233C3C43' stroke-opacity='.56' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 9px center;
    border: 1px solid rgba(60, 60, 67, 0.5);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 13px;
    font-family: var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
  }
  :global([data-theme="dark"]) select {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%23FFFFFF' stroke-opacity='.55' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
    border-color: rgba(84, 84, 88, 0.72);
  }
  select:hover {
    background-color: var(--bg-hover);
  }
  select:focus,
  select:focus-visible {
    outline: none;
    box-shadow: none;
  }
  input[type="checkbox"] {
    width: 16px;
    height: 16px;
    accent-color: var(--green, #34C759);
    min-width: 16px;
  }
  input[type="checkbox"]:focus,
  input[type="checkbox"]:focus-visible {
    outline: none;
    box-shadow: none;
  }

  /* ========== About tab — redesigned ========== */
  .about-tab {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .about-hero {
    display: flex;
    align-items: center;
    gap: 18px;
    padding: 4px 0 4px;
  }
  .about-logo {
    width: 64px;
    height: 64px;
    flex-shrink: 0;
    filter: drop-shadow(0 4px 12px color-mix(in srgb, var(--accent) 28%, transparent));
  }
  .about-hero-text {
    flex: 1;
    min-width: 0;
  }
  .about-name {
    margin: 0;
    font: 700 22px/28px var(--font-sans);
    color: var(--text-primary);
    letter-spacing: -0.02em;
  }
  .about-tagline-text {
    margin: 2px 0 10px;
    font: 500 13px/18px var(--font-sans);
    color: var(--text-secondary);
    letter-spacing: -0.005em;
  }
  .about-pills {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font: 600 11px/14px var(--font-sans);
    padding: 4px 10px;
    border-radius: 999px;
    letter-spacing: 0.02em;
  }
  .pill-version {
    color: var(--text-secondary);
    background: color-mix(in srgb, var(--text-muted) 18%, transparent);
    font-feature-settings: "tnum";
  }
  .pill-ok {
    color: var(--green);
    background: color-mix(in srgb, var(--green) 16%, transparent);
  }
  .pill-update {
    color: #fff;
    background: var(--accent);
    border: 0;
    cursor: pointer;
    box-shadow: 0 1px 3px color-mix(in srgb, var(--accent) 26%, transparent),
                0 1px 2px rgba(0,0,0,0.08);
  }
  @media (prefers-reduced-motion: no-preference) {
    .pill-update { transition: background-color 140ms ease, transform 140ms ease, box-shadow 140ms ease; }
  }
  .pill-update:hover:not(:disabled) {
    background: color-mix(in srgb, #fff 8%, var(--accent));
    transform: translateY(-1px);
  }
  .pill-update:disabled { opacity: 0.65; cursor: wait; }

  .about-check-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 8px;
  }
  .check-btn {
    height: 24px;
    padding: 0 10px;
    font: 500 11px/14px var(--font-sans);
    color: var(--text-primary);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
  }
  .check-btn:hover:not(:disabled) { background: var(--bg-hover); }
  .check-btn:disabled { opacity: 0.6; cursor: wait; }
  .check-meta {
    font: 400 11px/14px var(--font-sans);
    color: var(--text-secondary);
    font-feature-settings: "tnum";
  }
  .check-result {
    margin-top: 6px;
    font: 400 11px/15px var(--font-sans);
    color: var(--text-secondary);
  }
  .check-hint {
    margin-top: 6px;
    font: 400 11px/15px var(--font-sans);
    color: var(--text-muted, var(--text-secondary));
    font-style: italic;
  }
  .pill-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #fff;
  }

  .about-desc-paragraph {
    margin: 18px 0 16px;
    font: 13px/20px var(--font-sans);
    color: var(--text-secondary);
    letter-spacing: -0.005em;
  }

  /* VPN warn inline alert card */
  .about-vpn-warn {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    background: color-mix(in srgb, var(--orange, #FF9500) 10%, var(--bg-card));
    border: 0.5px solid color-mix(in srgb, var(--orange, #FF9500) 35%, var(--border));
    border-radius: 10px;
    padding: 12px 14px;
    margin-bottom: 14px;
    color: var(--orange, #FF9500);
  }
  .vpn-warn-body {
    flex: 1;
    min-width: 0;
  }
  .about-vpn-warn p {
    margin: 0 0 8px;
    font: 12px/16px var(--font-sans);
    color: var(--text-primary);
  }
  .vpn-warn-actions {
    display: flex;
    gap: 8px;
  }
  .warn-btn {
    height: 26px;
    padding: 0 12px;
    border: 0;
    border-radius: 7px;
    font: 600 11px/14px var(--font-sans);
    cursor: pointer;
  }
  .warn-proceed {
    background: var(--orange, #FF9500);
    color: #fff;
  }
  .warn-cancel {
    background: transparent;
    color: var(--text-secondary);
  }
  .warn-cancel:hover { background: var(--bg-hover); }

  /* Simple text-link row (original style — restored). */
  .about-links {
    display: flex;
    flex-wrap: wrap;
    gap: 18px;
    margin-bottom: 18px;
  }
  .link-btn {
    font: 500 12px/16px var(--font-sans);
    color: var(--accent);
    background: none;
    border: 0;
    padding: 0;
    cursor: pointer;
    letter-spacing: -0.005em;
  }
  .link-btn:hover { text-decoration: underline; }
  .link-btn:disabled { opacity: 0.5; cursor: wait; text-decoration: none; }
  .link-btn:focus, .link-btn:focus-visible { outline: none; }


  /* ========== Modal footer — credits row + close button on one line ==========
     The credit info shows in every tab now (not just About) — persistent
     identity reminder. justify-content: space-between pins the credit
     block to the left and the close button to the right. */
  .modal-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    margin-top: 14px;
    padding-top: 4px;
    flex-shrink: 0;
  }
  .footer-info {
    display: flex;
    align-items: baseline;
    gap: 5px;
    flex-wrap: wrap;
    min-width: 0;
    font: 11px/15px var(--font-sans);
    color: var(--text-muted);
    letter-spacing: 0.01em;
  }
  .footer-credit-label,
  .footer-credit-text { color: var(--text-muted); }
  .footer-sep { opacity: 0.55; }
  .footer-link {
    background: none;
    border: 0;
    padding: 0;
    cursor: pointer;
    font: inherit;
    color: var(--accent);
    letter-spacing: -0.005em;
  }
  .footer-link:hover { text-decoration: underline; }
  .footer-link:focus, .footer-link:focus-visible { outline: none; }
  .btn-close {
    min-width: 84px;
    height: 32px;
    padding: 0 18px;
    background: var(--accent);
    color: #fff;
    border: 0;
    border-radius: 10px;
    font: 600 13px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    letter-spacing: -0.005em;
    cursor: pointer;
    box-shadow:
      0 1px 3px color-mix(in srgb, var(--accent) 26%, transparent),
      0 1px 2px rgba(0,0,0,0.08);
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn-close {
      transition: background-color 140ms ease, box-shadow 140ms ease, transform 140ms ease;
    }
  }
  .btn-close:hover {
    background: color-mix(in srgb, #fff 8%, var(--accent));
    transform: translateY(-1px);
    box-shadow:
      0 4px 10px color-mix(in srgb, var(--accent) 30%, transparent),
      0 1px 2px rgba(0,0,0,0.10);
  }
  .btn-close:active { background: color-mix(in srgb, #000 8%, var(--accent)); transform: translateY(0); }
  .btn-close:focus,
  .btn-close:focus-visible {
    outline: none;
  }

  @media (prefers-reduced-motion: no-preference) {
    .settings-sidebar button {
      transition: background-color 120ms cubic-bezier(0.2, 0, 0.1, 1),
                  color 120ms cubic-bezier(0.2, 0, 0.1, 1);
    }
    .btn-close {
      transition: filter 120ms cubic-bezier(0.2, 0, 0.1, 1);
    }
  }

  /* Engine switch confirmation — sits above the Settings modal (z-index 200). */
  .confirm-backdrop {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg, rgba(0,0,0,0.45));
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 400;
  }
  .confirm-dialog {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: 14px;
    padding: 22px 26px 18px;
    width: 480px;
    max-width: calc(100vw - 40px);
    box-sizing: border-box;
    box-shadow: var(--shadow-lg);
  }
  .dialog-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 10px;
  }
  .dialog-icon-tile {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    border-radius: 10px;
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    color: var(--accent);
    flex-shrink: 0;
  }
  .dialog-header-text { flex: 1; min-width: 0; }
  .confirm-dialog h3 {
    margin: 0;
    color: var(--text-primary);
    font: 700 15px/20px var(--font-sans);
    letter-spacing: -0.01em;
  }
  .dialog-message {
    margin: 0 0 18px;
    font: 13px/19px var(--font-sans);
    color: var(--text-secondary);
  }
  .confirm-footer {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    margin-top: 14px;
  }
  .dialog-btn {
    height: 32px;
    min-width: 76px;
    padding: 0 16px;
    border: 0;
    border-radius: 9px;
    font: 600 13px/18px var(--font-sans);
    letter-spacing: -0.005em;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .dialog-btn-ghost {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    color: var(--text-primary);
  }
  .dialog-btn-ghost:hover { background: var(--bg-hover); }
  .dialog-btn-primary {
    background: var(--accent);
    color: #fff;
    box-shadow:
      0 1px 3px color-mix(in srgb, var(--accent) 26%, transparent),
      0 1px 2px rgba(0,0,0,0.08);
  }
  .dialog-btn-primary:hover { background: color-mix(in srgb, #fff 8%, var(--accent)); }
  .dialog-btn-primary:active { background: color-mix(in srgb, #000 8%, var(--accent)); }
</style>
