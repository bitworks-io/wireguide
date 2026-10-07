import { writable } from 'svelte/store';

// Live automation decision (Wails: GetAutomationPreview). One poller feeds
// the Automation editor strip and the chips on the tunnel list / hero card.
export const automationPreview = writable(null);
// Wall-clock time of the last successful poll, shown as "checked HH:MM:SS"
// where polling is slow (Windows/Linux).
export const automationCheckedAt = writable(0);

const IS_MAC = typeof navigator !== 'undefined' && /Mac/i.test(navigator.platform || navigator.userAgent || '');
// 2 s on macOS while the window is visible (a settle countdown / manual
// latch should feel live); 30 s elsewhere.
export const AUTOMATION_POLL_MS = IS_MAC ? 2000 : 30000;

let timer = null;
let service = null;
let lastJSON = '';
let inflight = false;

export async function refreshAutomationPreview() {
  if (!service || inflight) return;
  inflight = true;
  try {
    const p = await service.GetAutomationPreview();
    const json = JSON.stringify(p);
    // Only notify subscribers on a real change; a 2 s poll of an idle
    // network would otherwise re-render every chip each tick.
    if (json !== lastJSON) {
      lastJSON = json;
      automationPreview.set(p);
    }
    automationCheckedAt.set(Date.now());
  } catch (_) {
    // Older helper / transient IPC failure: hide the strip rather than
    // show stale state.
    if (lastJSON !== '') {
      lastJSON = '';
      automationPreview.set(null);
    }
  } finally {
    inflight = false;
  }
}

function schedule() {
  if (timer) clearInterval(timer);
  timer = setInterval(() => {
    if (document.visibilityState === 'visible') refreshAutomationPreview();
  }, AUTOMATION_POLL_MS);
}

function onVisibility() {
  if (document.visibilityState === 'visible') refreshAutomationPreview();
}

export function startAutomationPolling(TunnelService) {
  stopAutomationPolling();
  service = TunnelService;
  refreshAutomationPreview();
  schedule();
  document.addEventListener('visibilitychange', onVisibility);
}

export function stopAutomationPolling() {
  if (timer) clearInterval(timer);
  timer = null;
  document.removeEventListener('visibilitychange', onVisibility);
  service = null;
  lastJSON = '';
}
