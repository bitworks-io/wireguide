<script>
  // Per-tunnel override of the global handshake health check (Settings).
  // Stored in the tunnel's .meta.json sidecar; "inherit" follows Settings.
  import { onMount, onDestroy } from 'svelte';
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';

  export let TunnelService;
  export let tunnelName;
  let value = 'inherit';
  let loading = true;
  let saving = false;
  let error = '';
  let disposed = false;

  onMount(async () => {
    try {
      const v = await TunnelService.GetTunnelHealthCheck(tunnelName);
      if (!disposed) value = v || 'inherit';
    } catch (e) {
      if (!disposed) error = errText(e);
    } finally {
      if (!disposed) loading = false;
    }
  });
  onDestroy(() => { disposed = true; });

  async function save(next) {
    const prev = value;
    value = next;
    saving = true;
    error = '';
    try {
      await TunnelService.SetTunnelHealthCheck(tunnelName, next);
    } catch (e) {
      // The sidecar still holds the old value: show it, not the rejected one.
      if (!disposed) {
        value = prev;
        error = errText(e);
      }
    } finally {
      if (!disposed) saving = false;
    }
  }
</script>

<div class="hc-override">
  <label for="hc-override-select">{$t('tunnel.health_check_override')}</label>
  <select id="hc-override-select" value={value} disabled={loading || saving}
    on:change={(e) => save(e.currentTarget.value)}
    aria-describedby="hc-override-hint">
    <option value="inherit">{$t('tunnel.health_check_inherit')}</option>
    <option value="on">{$t('tunnel.health_check_on')}</option>
    <option value="off">{$t('tunnel.health_check_off')}</option>
  </select>
  <p id="hc-override-hint" class="hint">{$t('tunnel.health_check_override_hint')}</p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</div>

<style>
  .hc-override { margin-top: 16px; display: grid; grid-template-columns: 1fr auto; align-items: center; gap: 6px 12px; }
  label { font-size: 13px; font-weight: 600; color: var(--text-primary); }
  select { padding: 6px 8px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg-card); color: var(--text-primary); font: inherit; font-size: 12px; }
  select:disabled { opacity: 0.6; }
  select:focus-visible { outline: 2px solid var(--red); outline-offset: 2px; }
  .hint { grid-column: 1 / -1; font-size: 12px; line-height: 1.5; color: var(--text-secondary); margin: 0; }
  .error { grid-column: 1 / -1; color: var(--red); font-size: 12px; overflow-wrap: anywhere; margin: 0; }
</style>
