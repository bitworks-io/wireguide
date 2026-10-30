import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseDnsEntries, dnsModeOf, dnsChip, verifyDetail, verifyHint, tryVia, tryFailure,
  diagNoteKey, domainLabel, domainState, resolveHint,
} from './dns-mode.js';

// Echoes key + params so the tests check which i18n key was chosen.
const tr = (key, params) => (params && Object.keys(params).length ? `${key}${JSON.stringify(params)}` : key);

test('dnsModeOf classifies like the backend', () => {
  assert.equal(dnsModeOf(parseDnsEntries(['10.66.66.1', '~corp.example'])), 'split');
  assert.equal(dnsModeOf(parseDnsEntries(['1.1.1.1', 'fd00::1'])), 'global');
  assert.equal(dnsModeOf(parseDnsEntries(['corp.example'])), 'search');
  assert.equal(dnsModeOf(parseDnsEntries([])), 'none');
  assert.equal(dnsModeOf(parseDnsEntries(undefined)), 'none');
  // Split wins even with search domains; search without ~ is not split.
  assert.equal(dnsModeOf(parseDnsEntries(['corp.example', '~lab.example', '10.0.0.1'])), 'split');
});

test('dnsChip joins domains, hides none', () => {
  assert.deepEqual(dnsChip(tr, 'split', ['a.example', 'b.example']), {
    mode: 'split',
    text: 'tunnel.dns_chip_split{"domains":"a.example, b.example"}',
    hint: 'tunnel.dns_chip_split_hint',
  });
  assert.equal(dnsChip(tr, 'global').mode, 'global');
  assert.equal(dnsChip(tr, 'search').hint, 'tunnel.dns_chip_search_hint');
  assert.equal(dnsChip(tr, 'none'), null);
  assert.equal(dnsChip(tr, ''), null);
});

test('verifyDetail prefers the i18n key', () => {
  assert.equal(verifyDetail(tr, { detail: 'English', detail_key: 'route_more', detail_params: { n: '3' } }),
    'verify.detail_route_more{"n":"3","via":""}');
  assert.equal(verifyDetail(tr, { detail: '10.66.66.1 -> 10.66.66.1' }), '10.66.66.1 -> 10.66.66.1');
});

test('verifyDetail fills {via} from the resolver params', () => {
  const tpl = {
    'verify.detail_resolve_ok': '{name} -> {addrs} ({ms} ms) {via}',
    'tools.dns_try_via': 'via {resolver}',
    'tools.dns_try_via_domain': 'via {resolver} (~{domain})',
  };
  const fill = (key, params = {}) => (tpl[key] ?? key).replace(/\{(\w+)\}/g, (_, n) => params[n] ?? `{${n}}`);
  const row = (params) => ({ detail: 'English', detail_key: 'resolve_ok', detail_params: { name: 'nas.corp.example', addrs: '10.66.66.9', ms: '12', ...params } });
  assert.equal(verifyDetail(fill, row({ resolver: '10.66.66.1', match_domain: 'corp.example' })),
    'nas.corp.example -> 10.66.66.9 (12 ms) via 10.66.66.1 (~corp.example)');
  assert.equal(verifyDetail(fill, row({ resolver: '10.66.66.1' })), 'nas.corp.example -> 10.66.66.9 (12 ms) via 10.66.66.1');
  // No resolver: no dangling "via" and no trailing space.
  assert.equal(verifyDetail(fill, row({})), 'nas.corp.example -> 10.66.66.9 (12 ms)');
});

test('verifyHint is hidden for green rows', () => {
  assert.equal(verifyHint(tr, { status: 'green', hint_key: 'x' }), '');
  assert.equal(verifyHint(tr, { status: 'amber', hint_key: 'route_overlap' }), 'verify.hint_route_overlap');
  assert.equal(verifyHint(tr, { status: 'red', hint: 'plain' }), 'plain');
  assert.equal(verifyHint(tr, { status: 'red' }), '');
});

test('tryVia and tryFailure', () => {
  assert.equal(tryVia(tr, {}), '');
  assert.equal(tryVia(tr, { resolver: '10.66.66.1' }), 'tools.dns_try_via{"resolver":"10.66.66.1"}');
  assert.equal(tryVia(tr, { resolver: '10.66.66.1', match_domain: 'corp.example' }),
    'tools.dns_try_via_domain{"resolver":"10.66.66.1","domain":"corp.example"}');
  assert.equal(tryFailure(tr, { nxdomain: true }), 'tools.dns_try_nxdomain');
  assert.equal(tryFailure(tr, { timed_out: true }), 'tools.dns_try_timeout');
  assert.equal(tryFailure(tr, { error_code: 'invalid_name' }), 'tools.dns_try_invalid_name');
  assert.equal(tryFailure(tr, { error: 'boom' }), 'boom');
});

test('diagNoteKey is platform specific', () => {
  assert.equal(diagNoteKey('MacIntel'), 'tools.dns_leak_dig_note');
  assert.equal(diagNoteKey('Linux x86_64'), 'tools.dns_leak_linux_note');
  assert.equal(diagNoteKey('Win32'), '');
  assert.equal(diagNoteKey(undefined), '');
});

test('domain rows', () => {
  assert.equal(domainLabel({ domain: 'corp.example' }), '~corp.example');
  assert.equal(domainLabel({ domain: 'lan.example', search: true }), 'lan.example');
  assert.equal(domainState({ registered: true, resolver: '10.66.66.1' }), 'ok');
  assert.equal(domainState({ registered: false, resolver: '192.168.50.1' }), 'mismatch');
  assert.equal(domainState({ registered: false }), 'missing');
});

test('resolveHint', () => {
  assert.equal(resolveHint(['corp.example', 'x']), 'nas.corp.example');
  assert.equal(resolveHint([]), '');
  assert.equal(resolveHint(undefined), '');
});
