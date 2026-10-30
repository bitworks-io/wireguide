import test from 'node:test';
import assert from 'node:assert/strict';
import { connectPreview } from './connect-preview.js';

const cfg = (dns, allowed, table) => ({
  interface: { dns, table },
  peers: [{ allowed_ips: allowed }],
});
const keys = (lines) => lines.map((l) => l.key);

test('no detail yields no lines', () => {
  assert.deepEqual(connectPreview(null, []), []);
});

test('global DNS: macOS replaces DNS on all services, elsewhere neutral', () => {
  const d = cfg(['10.66.66.1'], ['10.66.66.0/24']);
  const mac = connectPreview(d, [], { platform: 'MacIntel' });
  assert.equal(mac[0].key, 'preview.dns_global_mac');
  assert.deepEqual(mac[0].params, { servers: '10.66.66.1' });
  assert.equal(connectPreview(d, [], { platform: 'Win32' })[0].key, 'preview.dns_global');
});

test('split DNS names the resolver and the ~domains', () => {
  const l = connectPreview(cfg(['10.66.66.1', '~corp.example'], ['10.66.66.0/24']), []);
  assert.equal(l[0].key, 'preview.dns_split');
  assert.deepEqual(l[0].params, { servers: '10.66.66.1', domains: '~corp.example' });
  assert.equal(l[0].tone, 'info');
});

test('split DNS unsupported is an error: connecting fails', () => {
  const l = connectPreview(cfg(['10.66.66.1', '~corp.example'], ['10.66.66.0/24']), [], { splitSupported: false });
  assert.equal(l[0].key, 'preview.dns_split_unsupported');
  assert.equal(l[0].tone, 'error');
  // Plain global DNS is unaffected by split support.
  assert.equal(connectPreview(cfg(['1.1.1.1'], []), [], { splitSupported: false })[0].key, 'preview.dns_global');
});

test('search-only and empty DNS', () => {
  assert.deepEqual(connectPreview(cfg(['corp.example'], []), [])[0],
    { key: 'preview.dns_search', params: { domains: 'corp.example' }, tone: 'info' });
  assert.equal(connectPreview(cfg([], []), [])[0].key, 'preview.dns_none');
});

test('routes: full tunnel, split list', () => {
  assert.ok(keys(connectPreview(cfg([], ['0.0.0.0/0', '::/0']), [])).includes('preview.routes_full'));
  assert.ok(keys(connectPreview(cfg([], ['0.0.0.0/1', '128.0.0.0/1']), [])).includes('preview.routes_full'));
  const split = connectPreview(cfg([], ['10.0.0.0/8', '172.16.0.0/12']), []).find((l) => l.key === 'preview.routes_split');
  assert.equal(split.params.ranges, '10.0.0.0/8, 172.16.0.0/12');
});

test('LAN overlap is a warning, and the range is still listed as routed', () => {
  const l = connectPreview(cfg([], ['10.66.66.0/24', '192.168.50.0/24']),
    [{ range: '192.168.50.0/24', network: '192.168.50.0/24' }]);
  const split = l.find((x) => x.key === 'preview.routes_split');
  assert.equal(split.params.ranges, '10.66.66.0/24, 192.168.50.0/24');
  const warn = l.find((x) => x.key === 'preview.routes_overlap');
  assert.equal(warn.tone, 'warn');
  assert.deepEqual(warn.params, { range: '192.168.50.0/24', network: '192.168.50.0/24' });
  assert.ok(!keys(l).some((k) => k.includes('skipped')));
});

test('Table=off installs no routes and shows no overlap warning', () => {
  const l = connectPreview(cfg(['1.1.1.1'], ['0.0.0.0/0'], 'Off'), [{ range: '192.168.50.0/24', network: 'x' }]);
  assert.deepEqual(keys(l), ['preview.dns_global', 'preview.routes_none']);
});
