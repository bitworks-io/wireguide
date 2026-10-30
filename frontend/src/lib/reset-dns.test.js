import test from 'node:test';
import assert from 'node:assert/strict';
import { stepLabel, stepDetail, refusalNeeds, resetSucceeded } from './reset-dns.js';

// Mirrors the real translator: unknown keys come back unchanged.
const table = {
  'reset_dns.step.firewall': 'Firewall rules',
  'reset_dns.detail.disconnect_ok': 'Disconnected: {tunnels}',
};
const t = (key, params = {}) => {
  const v = table[key];
  if (v === undefined) return key;
  return v.replace(/\{(\w+)\}/g, (_, n) => params[n] ?? `{${n}}`);
};

test('stepLabel translates known steps and falls back to the wire name', () => {
  assert.equal(stepLabel(t, 'firewall'), 'Firewall rules');
  assert.equal(stepLabel(t, 'something_new'), 'something_new');
});

test('stepDetail localizes with params, else uses the English detail', () => {
  assert.equal(
    stepDetail(t, { detail_key: 'reset_dns.detail.disconnect_ok', detail_params: { tunnels: 'home-vpn' }, detail: 'Disconnected: home-vpn' }),
    'Disconnected: home-vpn',
  );
  assert.equal(stepDetail(t, { detail_key: 'reset_dns.detail.unknown', detail: 'English text' }), 'English text');
  assert.equal(stepDetail(t, { detail: 'only English' }), 'only English');
  assert.equal(stepDetail(t, null), '');
});

test('refusalNeeds reveals the option the helper asked for', () => {
  assert.deepEqual(refusalNeeds({ refused: true, reason: 'tunnels_active', connected_tunnels: ['a'] }), { force: true, killSwitchOff: false });
  assert.deepEqual(refusalNeeds({ refused: true, reason: 'kill_switch_on' }), { force: false, killSwitchOff: true });
  assert.deepEqual(refusalNeeds({ refused: false, steps: [] }), { force: false, killSwitchOff: false });
  assert.deepEqual(refusalNeeds(null), { force: false, killSwitchOff: false });
});

test('resetSucceeded requires every step ok and no refusal', () => {
  assert.equal(resetSucceeded({ refused: false, steps: [{ ok: true }, { ok: true }] }), true);
  assert.equal(resetSucceeded({ refused: false, steps: [{ ok: true }, { ok: false }] }), false);
  assert.equal(resetSucceeded({ refused: true, steps: [] }), false);
  assert.equal(resetSucceeded(null), false);
});
