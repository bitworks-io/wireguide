// Pure logic for the pre-connect "What will change when you connect" preview.
// It describes, from the stored config alone, what Connect will do. Strings
// are never built here: each line is { key, params, tone } and the caller
// renders it through i18n (preview.*).

import { parseDnsEntries } from './dns-mode.js';

function isFullTunnel(ranges) {
  const has = (c) => ranges.includes(c);
  return has('0.0.0.0/0') || has('::/0') ||
    (has('0.0.0.0/1') && has('128.0.0.0/1')) || (has('::/1') && has('8000::/1'));
}

// connectPreview(detail, overlaps, opts) -> [{ key, params, tone }].
//   detail   GetTunnelDetail's config ({interface:{dns,table}, peers:[{allowed_ips}]}).
//   overlaps GetLANOverlaps' [{range, network}]: ranges that overlap the
//            current LAN. They are still routed into the tunnel.
//   opts     { splitSupported: SplitDNSSupported() (default true),
//              platform: navigator.platform (macOS gets the system-wide DNS wording) }
// tone is 'info', 'warn' or 'error' ("Connecting will FAIL").
export function connectPreview(detail, overlaps, opts = {}) {
  if (!detail) return [];
  const splitSupported = opts.splitSupported !== false;
  const isMac = /Mac/i.test(opts.platform || '');
  const out = [];

  const dns = parseDnsEntries(detail.interface?.dns);
  const servers = dns.servers.join(', ');
  if (dns.match.length > 0 && !splitSupported) {
    out.push({ key: 'preview.dns_split_unsupported', params: { domains: dns.match.map((d) => '~' + d).join(', ') }, tone: 'error' });
  } else if (dns.match.length > 0) {
    out.push({ key: 'preview.dns_split', params: { servers, domains: dns.match.map((d) => '~' + d).join(', ') }, tone: 'info' });
  } else if (dns.servers.length > 0) {
    out.push({ key: isMac ? 'preview.dns_global_mac' : 'preview.dns_global', params: { servers }, tone: 'info' });
  } else if (dns.search.length > 0) {
    out.push({ key: 'preview.dns_search', params: { domains: dns.search.join(', ') }, tone: 'info' });
  } else {
    out.push({ key: 'preview.dns_none', params: {}, tone: 'info' });
  }

  const ranges = [];
  for (const p of detail.peers || []) for (const r of p.allowed_ips || []) {
    const v = String(r).trim();
    if (v) ranges.push(v);
  }
  if (String(detail.interface?.table || '').trim().toLowerCase() === 'off') {
    out.push({ key: 'preview.routes_none', params: {}, tone: 'info' });
    return out;
  }
  if (isFullTunnel(ranges)) {
    out.push({ key: 'preview.routes_full', params: {}, tone: 'info' });
  } else if (ranges.length > 0) {
    out.push({ key: 'preview.routes_split', params: { ranges: ranges.join(', ') }, tone: 'info' });
  }
  for (const o of overlaps || []) {
    out.push({ key: 'preview.routes_overlap', params: { range: o.range, network: o.network }, tone: 'warn' });
  }
  return out;
}
