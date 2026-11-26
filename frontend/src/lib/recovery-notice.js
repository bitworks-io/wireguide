// Startup-recovery notice: after the helper cleaned up what a previous helper
// process left behind (tunnels, DNS, firewall rules), the app says so once
// per helper start. Pure helpers, kept out of App.svelte so they are testable.

// localStorage key holding the started_at of the helper start already shown.
export const RECOVERY_SEEN_KEY = 'wireguide.recoveryNoticeSeen';

// The notice to show for a GetHelperInfo() result, or null: nothing was
// cleaned up, the helper is too old to say, or this helper start (keyed by
// started_at) was already announced.
export function recoveryNotice(info, seenStartedAt) {
  const r = info?.recovery;
  if (!info?.available || !r || !info.started_at) return null;
  if (info.started_at === seenStartedAt) return null;
  const tunnels = Array.isArray(r.tunnels_recovered) ? r.tunnels_recovered : [];
  const dns = Array.isArray(r.dns_restored) ? r.dns_restored : [];
  const firewall = r.firewall_flushed === true;
  if (!tunnels.length && !dns.length && !firewall) return null;
  return { startedAt: info.started_at, tunnels, dns, firewall };
}

// The notice's lines, translated with tr(key, params).
export function recoveryLines(tr, notice) {
  if (!notice) return [];
  const lines = [];
  if (notice.tunnels.length) lines.push(tr('app.recovery_tunnels', { names: notice.tunnels.join(', ') }));
  if (notice.dns.length) lines.push(tr('app.recovery_dns', { names: notice.dns.join(', ') }));
  if (notice.firewall) lines.push(tr('app.recovery_firewall'));
  return lines;
}

// Storage access never throws: private windows and blocked storage only
// mean the notice may show again.
export function readSeen(storage) {
  try { return storage?.getItem(RECOVERY_SEEN_KEY) || ''; } catch (_) { return ''; }
}

export function writeSeen(storage, startedAt) {
  try { storage?.setItem(RECOVERY_SEEN_KEY, startedAt); } catch (_) { /* best effort */ }
}
