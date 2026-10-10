<script>
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';

  export let TunnelService;
  export let tunnelName = '';
  // Suggested placeholder for the resolve field (e.g. nas.<first ~domain>).
  export let resolveHint = '';

  let pingHost = '';
  let resolveName = '';
  let rows = null;
  let running = false;
  let error = '';
  let ranFor = '';

  // Results belong to one tunnel; drop them when the selection changes.
  $: if (tunnelName !== ranFor) {
    rows = null;
    error = '';
    ranFor = tunnelName;
  }

  // Manual only: this is the sole entry point and it is a button click.
  async function run() {
    if (running) return;
    running = true;
    error = '';
    const name = tunnelName;
    try {
      const res = await TunnelService.Verify(name, pingHost.trim(), resolveName.trim());
      if (name === tunnelName) rows = res || [];
    } catch (e) {
      if (name === tunnelName) error = errText(e);
    }
    running = false;
  }

  function onKey(e) {
    if (e.key === 'Enter') run();
  }
</script>

<div class="info-section verify">
  <h3 class="section-label">{$t('verify.title')}</h3>
  <div class="info-card verify-card">
    <div class="verify-inputs">
      <label class="field">
        <span class="field-label">{$t('verify.ping_label')}</span>
        <input type="text" spellcheck="false" autocomplete="off"
          placeholder={$t('verify.ping_placeholder')}
          bind:value={pingHost} on:keydown={onKey} />
      </label>
      <label class="field">
        <span class="field-label">{$t('verify.resolve_label')}</span>
        <input type="text" spellcheck="false" autocomplete="off"
          placeholder={resolveHint || $t('verify.resolve_placeholder')}
          bind:value={resolveName} on:keydown={onKey} />
      </label>
    </div>
    <div class="verify-actions">
      <button class="btn-run" on:click={run} disabled={running}>
        {running ? $t('verify.running') : $t('verify.run')}
      </button>
      <span class="verify-note">{$t('verify.note')}</span>
    </div>

    {#if error}
      <div class="verify-error">{error}</div>
    {/if}

    {#if rows}
      <ul class="rows">
        {#each rows as r}
          <li class="row">
            <span class="dot {r.status}" role="img" aria-label={$t('verify.status_' + r.status)}></span>
            <div class="row-body">
              <div class="row-head">
                <span class="row-check">{$t('verify.check_' + r.check)}</span>
                <span class="row-detail">{r.detail_key ? $t('verify.detail_' + r.detail_key, r.detail_params || {}) : r.detail}</span>
              </div>
              {#if r.status !== 'green' && (r.hint_key || r.hint)}
                <div class="row-hint">{r.hint_key ? $t('verify.hint_' + r.hint_key) : r.hint}</div>
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </div>
</div>

<style>
  .info-section { margin-bottom: 16px; }
  .section-label {
    margin: 0 0 8px 4px;
    font: 500 10px/13px var(--font-sans);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .info-card {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 12px;
    padding: 12px 14px;
  }
  .verify-inputs {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: 12px;
  }
  .field { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .field-label { font: 400 11px/14px var(--font-sans); color: var(--text-secondary); }
  input {
    height: 26px;
    padding: 0 8px;
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-primary, transparent);
    color: var(--text-primary);
    font: 12px/16px var(--font-mono);
    min-width: 0;
  }
  input:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
  .verify-actions {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 10px;
  }
  .btn-run {
    height: 26px;
    padding: 0 14px;
    background: var(--accent);
    border: 0;
    border-radius: var(--radius-sm);
    color: var(--text-inverse);
    cursor: pointer;
    font: var(--text-headline);
    flex-shrink: 0;
  }
  .btn-run:hover:not(:disabled) { filter: brightness(1.08); }
  .btn-run:active:not(:disabled) { filter: brightness(0.94); }
  .btn-run:disabled { opacity: 0.6; cursor: progress; }
  .verify-note { font: 400 11px/14px var(--font-sans); color: var(--text-muted); }
  .verify-error {
    margin-top: 10px;
    padding: 6px 10px;
    background: var(--error-bg);
    border-radius: var(--radius-sm);
    color: var(--error-text);
    font: var(--text-body);
  }
  .rows { list-style: none; margin: 12px 0 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .row { display: flex; gap: 10px; align-items: flex-start; }
  .dot { width: 8px; height: 8px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }
  .dot.green { background: var(--green); }
  .dot.amber { background: var(--orange, #FF9500); }
  .dot.red { background: var(--red); }
  .row-body { min-width: 0; flex: 1; }
  .row-head { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; font: 13px/18px var(--font-sans); }
  .row-check { color: var(--text-primary); font-weight: 600; }
  .row-detail { color: var(--text-secondary); font-family: var(--font-mono); font-size: 11px; overflow-wrap: anywhere; }
  .row-hint { font: 400 11px/15px var(--font-sans); color: var(--text-muted); margin-top: 2px; }
</style>
