import { test } from 'vitest';
import assert from 'node:assert/strict';
import {
  protectionState, skippedRouteRows, skippedRoutesLabel, formatPermit, firewallDnsLine, connectPreview,
} from './dnsTruth.js';

const tr = (key, params = {}) => {
  const p = Object.entries(params).map(([k, v]) => `${k}=${v}`).join(',');
  return p ? `${key}|${p}` : key;
};

test('protection state: protected, intended, nothing', () => {
  const up = { state: 'connected', dns_mode: 'global' };
  assert.equal(protectionState({ ...up, dns_protected: true }, true), 'protected');
  assert.equal(protectionState(up, true), 'intended');
  assert.equal(protectionState(up, false), '');
  assert.equal(protectionState({ state: 'disconnected' }, true), '');
  assert.equal(protectionState(null, true), '');
});

test('protection state: split/none/search tunnels are never "intended"', () => {
  for (const dns_mode of ['split', 'none', 'search']) {
    assert.equal(protectionState({ state: 'connected', dns_mode }, true), '', dns_mode);
  }
});

test('protection state: an older helper (no dns_mode) shows nothing', () => {
  assert.equal(protectionState({ state: 'connected' }, true), '');
  assert.equal(protectionState({ state: 'connected', dns_protected: true }, true), '');
});

test('skipped rows come from the primary and per-tunnel statuses without duplicates', () => {
  const st = {
    state: 'connected', tunnel_name: 'a', routes_skipped: ['192.168.1.0/24'],
    tunnels: [
      { tunnel_name: 'a', routes_skipped: ['192.168.1.0/24'] },
      { tunnel_name: 'b', routes_skipped: ['10.0.0.0/24', '10.0.1.0/24'] },
    ],
  };
  const rows = skippedRouteRows(st);
  assert.deepEqual(rows.map((r) => `${r.tunnel}:${r.cidr}`), ['a:192.168.1.0/24', 'b:10.0.0.0/24', 'b:10.0.1.0/24']);
  assert.deepEqual(skippedRouteRows({ state: 'connected', tunnel_name: 'a' }), []);
  assert.equal(skippedRoutesLabel(tr, 1), 'tunnel.routes_skipped_one|n=1');
  assert.equal(skippedRoutesLabel(tr, 3), 'tunnel.routes_skipped_other|n=3');
});

test('permit formatting names the tunnel and the interface scope', () => {
  assert.equal(formatPermit(tr, { interface: '', server: '1.1.1.1', tunnel: 'Office' }),
    'settings.dns_permit_any|who=1.1.1.1 (Office)');
  assert.equal(formatPermit(tr, { interface: 'utun4', server: '10.0.0.1' }),
    'settings.dns_permit_iface|who=10.0.0.1,iface=utun4');
});

test('firewall DNS sub-line', () => {
  const live = { available: true, status: { dns_protection_active: true, permits: [{ interface: '', server: '1.1.1.1', tunnel: 'W' }] } };
  assert.match(firewallDnsLine(tr, live, true).text, /^settings\.dns_protection_allowing\|list=settings\.dns_permit_any/);
  assert.equal(firewallDnsLine(tr, live, true).tone, 'ok');

  const idle = { available: true, status: { dns_protection_active: false, permits: [] } };
  assert.deepEqual(firewallDnsLine(tr, idle, true), { tone: 'muted', text: 'settings.dns_protection_inactive' });
  assert.equal(firewallDnsLine(tr, idle, false), null);
  assert.deepEqual(firewallDnsLine(tr, idle, true, false), { tone: 'muted', text: 'settings.dns_protection_idle' });

  const failing = { available: true, status: { dns_protection_active: false, last_reconcile_error: 'pfctl boom', dns_reconcile_error: 'pfctl boom' } };
  assert.deepEqual(firewallDnsLine(tr, failing, true), { tone: 'error', text: 'settings.dns_protection_error|error=pfctl boom' });

  // A kill-switch-only failure must not be blamed on DNS protection.
  const ksOnly = { available: true, status: { dns_protection_active: true, permits: [], last_reconcile_error: 'ks boom' } };
  assert.deepEqual(firewallDnsLine(tr, ksOnly, true), { tone: 'ok', text: 'settings.dns_protection_blocking' });

  assert.equal(firewallDnsLine(tr, { available: false }, true), null);
  assert.equal(firewallDnsLine(tr, null, true), null);
});

test('connect preview: global, split, none and LAN overlaps', () => {
  const full = { interface: { dns: ['1.1.1.1'] }, peers: [{ allowed_ips: ['0.0.0.0/0', '::/0'] }] };
  assert.deepEqual(connectPreview(full, []), [
    { key: 'preview.dns_global', params: { servers: '1.1.1.1' } },
    { key: 'preview.routes_full', params: {} },
  ]);

  const split = { interface: { dns: ['192.168.1.1', '~intranet.example'] }, peers: [{ allowed_ips: ['192.168.1.0/24', '10.9.0.0/24'] }] };
  assert.deepEqual(connectPreview(split, ['192.168.1.0/24']), [
    { key: 'preview.dns_split', params: { servers: '192.168.1.1', domains: 'intranet.example' } },
    { key: 'preview.routes_split', params: { ranges: '10.9.0.0/24' } },
    { key: 'preview.routes_skipped', params: { ranges: '192.168.1.0/24' } },
  ]);

  const bare = { interface: { dns: [] }, peers: [{ allowed_ips: ['10.0.0.0/8'] }] };
  assert.equal(connectPreview(bare, [])[0].key, 'preview.dns_none');
  assert.deepEqual(connectPreview(null, []), []);
  assert.equal(connectPreview({ interface: { dns: ['corp.lan'] }, peers: [] }, [])[0].key, 'preview.dns_search');
});

test('connect preview: split DNS unsupported platform', () => {
  const split = { interface: { dns: ['10.0.0.1', '~corp.lan'] }, peers: [{ allowed_ips: ['10.0.0.0/8'] }] };
  assert.equal(connectPreview(split, [], false)[0].key, 'preview.dns_split_unsupported');
  assert.equal(connectPreview(split, [], true)[0].key, 'preview.dns_split');
});
