// Pure helpers for DNS protection truth: the tunnel header's protection chip,
// the Settings DNS Protection sub-line (from Firewall.Status) and the
// critical banner's coded rows. Strings only go through the translator `tr`
// ($t), so every locale uses i18n keys.

// protectionState: '' (nothing to say), 'protected' (the applied firewall
// rules pin this tunnel's resolvers) or 'intended' (protection is wanted and
// this tunnel replaces system DNS, but the rules are not pinning it). An
// older helper omits dns_mode and dns_protected together, so a missing
// dns_mode means "unknown", never "not applied". Split, search-only and
// DNS-less tunnels are never pinned, so they get no chip.
export function protectionState(status, wanted) {
  if (!status || status.state !== 'connected' || !status.dns_mode) return '';
  if (status.dns_protected) return 'protected';
  if (wanted && status.dns_mode === 'global') return 'intended';
  return '';
}

// formatPermit: "1.1.1.1 (home-vpn) on all interfaces" / "... on utun4".
export function formatPermit(tr, p) {
  const who = p.tunnel ? `${p.server} (${p.tunnel})` : p.server;
  return p.interface
    ? tr('settings.dns_permit_iface', { who, iface: p.interface })
    : tr('settings.dns_permit_any', { who });
}

// firewallDnsLine decides the Settings DNS Protection sub-line from
// GetFirewallStatus ({available, status}), the wanted setting and whether any
// tunnel is connected. Returns null (say nothing: unknown or not wanted) or
// { tone: 'ok' | 'muted' | 'error', text }.
export function firewallDnsLine(tr, fw, wanted, connected = true) {
  if (!fw || !fw.available || !fw.status) return null;
  const s = fw.status;
  if (s.suspended) {
    return wanted ? { tone: 'muted', text: tr('settings.dns_protection_suspended') } : null;
  }
  if (wanted && s.dns_reconcile_error) {
    return { tone: 'error', text: tr('settings.dns_protection_error', { error: s.dns_reconcile_error }) };
  }
  const permits = s.permits || [];
  if (s.dns_protection_active && permits.length > 0) {
    const list = permits.map((p) => formatPermit(tr, p)).join('; ');
    return { tone: 'ok', text: tr('settings.dns_protection_allowing', { list }) };
  }
  if (s.dns_protection_active) {
    return { tone: 'ok', text: tr('settings.dns_protection_blocking') };
  }
  if (wanted) {
    // With no tunnel up there is nothing to protect yet; "not applied" is a
    // statement about a connected tunnel.
    return { tone: 'muted', text: tr(connected ? 'settings.dns_protection_inactive' : 'settings.dns_protection_idle') };
  }
  return null;
}

// Critical-banner codes the GUI words itself (CriticalErrorPayload.code).
// Anything else shows the helper's untranslated where/detail.
const CRITICAL_CODES = ['dns_protection_failing'];

export function isKnownCritical(code) {
  return CRITICAL_CODES.includes(code);
}

// criticalRow returns { where, detail } for one banner entry.
export function criticalRow(tr, e) {
  if (isKnownCritical(e.code)) {
    return { where: tr('critical.' + e.code + '_where'), detail: tr('critical.' + e.code) };
  }
  return { where: e.where, detail: e.detail };
}
