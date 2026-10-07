// Pure helpers for the "DNS truth" surfaces: the hero-card protection chip,
// skipped-route notes, the Settings DNS Protection sub-line and the
// pre-connect "what will change" preview. Strings are never built here; every
// result is an i18n key plus params so the components translate them. `tr` is
// the translator function ($t) where a helper has to compose text.

// protectionState: '' (nothing to say), 'protected' (the helper's firewall
// permit set covers this tunnel's resolvers) or 'intended' (protection is
// wanted, this tunnel replaces system DNS, but the firewall is not pinning
// it). Only meaningful while connected, and only against a helper that reports
// dns_mode: an older helper omits dns_protected too, so a missing dns_mode
// means "unknown", never "not applied". Split, search-only and DNS-less
// tunnels are never meant to be pinned, so they get no chip.
export function protectionState(status, wanted) {
  if (!status || status.state !== 'connected' || !status.dns_mode) return '';
  if (status.dns_protected) return 'protected';
  if (wanted && status.dns_mode === 'global') return 'intended';
  return '';
}

// skippedRouteRows lists every AllowedIPs range the macOS LAN-overlap guard
// left out, across the primary status and the per-tunnel entries.
export function skippedRouteRows(status) {
  const rows = [];
  const seen = new Set();
  const add = (s) => {
    if (!s) return;
    for (const cidr of s.routes_skipped || []) {
      const key = `${s.tunnel_name}|${cidr}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({ tunnel: s.tunnel_name, cidr });
    }
  };
  add(status);
  for (const s of status?.tunnels || []) add(s);
  return rows;
}

export function skippedRoutesLabel(tr, n) {
  return tr(n === 1 ? 'tunnel.routes_skipped_one' : 'tunnel.routes_skipped_other', { n });
}

// formatPermit renders one permit: "1.1.1.1 (Office) on all interfaces".
export function formatPermit(tr, p) {
  const who = p.tunnel ? `${p.server} (${p.tunnel})` : p.server;
  return p.interface
    ? tr('settings.dns_permit_iface', { who, iface: p.interface })
    : tr('settings.dns_permit_any', { who });
}

// firewallDnsLine decides the Settings DNS Protection sub-line from the
// Firewall.Status result ({available, status}), the wanted setting and whether
// any tunnel is connected.
// Returns null (show nothing) or { tone: 'ok'|'muted'|'error', text }.
export function firewallDnsLine(tr, fw, wanted, connected = true) {
  if (!fw || !fw.available || !fw.status) return null;
  const s = fw.status;
  if (wanted && s.dns_reconcile_error) {
    return { tone: 'error', text: tr('settings.dns_protection_error', { error: s.dns_reconcile_error }) };
  }
  if (s.dns_protection_active && (s.permits || []).length > 0) {
    const list = s.permits.map((p) => formatPermit(tr, p)).join('; ');
    return { tone: 'ok', text: tr('settings.dns_protection_allowing', { list }) };
  }
  if (s.dns_protection_active) {
    return { tone: 'ok', text: tr('settings.dns_protection_blocking') };
  }
  if (wanted) {
    // With no tunnel up there is simply nothing to protect yet; "not applied"
    // is only a statement about a connected tunnel.
    return { tone: 'muted', text: tr(connected ? 'settings.dns_protection_inactive' : 'settings.dns_protection_idle') };
  }
  return null;
}

function parseDns(list) {
  const out = { servers: [], search: [], match: [] };
  for (const raw of list || []) {
    const tok = String(raw).trim();
    if (!tok) continue;
    if (tok.startsWith('~')) {
      const d = tok.slice(1).trim();
      if (d && d !== '.' && !d.startsWith('~')) out.match.push(d);
    } else if (tok.includes(':') || /^[0-9.]+$/.test(tok)) out.servers.push(tok);
    else out.search.push(tok);
  }
  return out;
}

function isFullTunnel(ranges) {
  const has = (c) => ranges.includes(c);
  return has('0.0.0.0/0') || has('::/0') ||
    (has('0.0.0.0/1') && has('128.0.0.0/1')) || (has('::/1') && has('8000::/1'));
}

// connectPreview describes, from the config alone, what connecting will do.
// detail is GetTunnelDetail's config ({interface:{dns}, peers:[{allowed_ips}]});
// overlaps are the ranges the macOS connect path will not route (computed by
// the backend with the same rule as AddRoutes; [] on other platforms).
// Returns [{ key, params }].
export function connectPreview(detail, overlaps, splitSupported = true) {
  if (!detail) return [];
  const out = [];
  const dns = parseDns(detail.interface?.dns);
  if (dns.match.length > 0 && !splitSupported) {
    out.push({ key: 'preview.dns_split_unsupported', params: { domains: dns.match.join(', ') } });
  } else if (dns.match.length > 0) {
    out.push({ key: 'preview.dns_split', params: { servers: dns.servers.join(', '), domains: dns.match.join(', ') } });
  } else if (dns.servers.length > 0) {
    out.push({ key: 'preview.dns_global', params: { servers: dns.servers.join(', ') } });
  } else if (dns.search.length > 0) {
    out.push({ key: 'preview.dns_search', params: { domains: dns.search.join(', ') } });
  } else {
    out.push({ key: 'preview.dns_none', params: {} });
  }
  const skipped = new Set(overlaps || []);
  const ranges = [];
  for (const p of detail.peers || []) for (const r of p.allowed_ips || []) ranges.push(String(r).trim());
  if (isFullTunnel(ranges)) {
    out.push({ key: 'preview.routes_full', params: {} });
  } else if (ranges.length > 0) {
    const routed = ranges.filter((r) => !skipped.has(r));
    if (routed.length > 0) out.push({ key: 'preview.routes_split', params: { ranges: routed.join(', ') } });
  }
  if (skipped.size > 0) {
    out.push({ key: 'preview.routes_skipped', params: { ranges: [...skipped].join(', ') } });
  }
  return out;
}
