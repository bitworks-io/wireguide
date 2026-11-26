import { test } from 'node:test';
import assert from 'node:assert/strict';
import { recoveryNotice, recoveryLines, readSeen, writeSeen, RECOVERY_SEEN_KEY } from './recovery-notice.js';

const tr = (key, params = {}) => {
  const p = Object.entries(params).map(([k, v]) => `${k}=${v}`).join(',');
  return p ? `${key}|${p}` : key;
};

const info = (recovery, startedAt = '2026-10-30T10:00:00Z') => ({ available: true, started_at: startedAt, recovery });

test('no notice without a recovery report', () => {
  assert.equal(recoveryNotice(info(undefined), ''), null);
  assert.equal(recoveryNotice(info({}), ''), null);
  assert.equal(recoveryNotice({ available: false }, ''), null);
  assert.equal(recoveryNotice(null, ''), null);
  assert.equal(recoveryNotice(info({ firewall_flushed: true }, ''), ''), null);
});

test('notice lists what was cleaned', () => {
  const n = recoveryNotice(info({ tunnels_recovered: ['home-vpn'], dns_restored: ['home-vpn'], firewall_flushed: true }), '');
  assert.deepEqual(recoveryLines(tr, n), [
    'app.recovery_tunnels|names=home-vpn',
    'app.recovery_dns|names=home-vpn',
    'app.recovery_firewall',
  ]);
  assert.deepEqual(recoveryLines(tr, recoveryNotice(info({ firewall_flushed: true }), '')), ['app.recovery_firewall']);
});

test('once per helper start (deduped by started_at)', () => {
  const r = { tunnels_recovered: ['office-vpn'] };
  assert.equal(recoveryNotice(info(r, 'A'), 'A'), null);
  assert.equal(recoveryNotice(info(r, 'B'), 'A').startedAt, 'B');
});

test('seen marker survives failing storage', () => {
  const store = new Map();
  const ok = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v) };
  writeSeen(ok, 'A');
  assert.equal(store.get(RECOVERY_SEEN_KEY), 'A');
  assert.equal(readSeen(ok), 'A');
  const broken = { getItem: () => { throw new Error('denied'); }, setItem: () => { throw new Error('denied'); } };
  assert.equal(readSeen(broken), '');
  assert.doesNotThrow(() => writeSeen(broken, 'A'));
  assert.equal(readSeen(undefined), '');
});
