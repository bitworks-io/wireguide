import test from 'node:test';
import assert from 'node:assert/strict';
import { protectionState, formatPermit, firewallDnsLine, criticalRow, isKnownCritical } from './dns-protection.js';

const tr = (key, params = {}) => key + (Object.keys(params).length ? ' ' + JSON.stringify(params) : '');

test('protectionState follows the helper flag and treats a missing dns_mode as unknown', () => {
  assert.equal(protectionState({ state: 'connected', dns_mode: 'global', dns_protected: true }, true), 'protected');
  assert.equal(protectionState({ state: 'connected', dns_mode: 'global' }, true), 'intended');
  assert.equal(protectionState({ state: 'connected', dns_mode: 'global' }, false), '');
  assert.equal(protectionState({ state: 'connected', dns_mode: 'split' }, true), '');
  assert.equal(protectionState({ state: 'connected', dns_mode: 'none' }, true), '');
  // Older helper: no dns_mode at all.
  assert.equal(protectionState({ state: 'connected' }, true), '');
  assert.equal(protectionState({ state: 'disconnected', dns_mode: 'global', dns_protected: true }, true), '');
  assert.equal(protectionState(null, true), '');
});

test('formatPermit names the tunnel and the interface scope', () => {
  assert.equal(formatPermit(tr, { server: '1.1.1.1', tunnel: 'home-vpn', interface: '' }),
    'settings.dns_permit_any {"who":"1.1.1.1 (home-vpn)"}');
  assert.equal(formatPermit(tr, { server: '10.66.66.1', interface: 'utun4' }),
    'settings.dns_permit_iface {"who":"10.66.66.1","iface":"utun4"}');
});

test('firewallDnsLine', () => {
  const fw = (status) => ({ available: true, status });
  assert.equal(firewallDnsLine(tr, { available: false }, true), null);
  assert.equal(firewallDnsLine(tr, null, true), null);
  assert.deepEqual(firewallDnsLine(tr, fw({ dns_protection_active: true, permits: [{ server: '1.1.1.1', tunnel: 'home-vpn', interface: '' }] }), true),
    { tone: 'ok', text: 'settings.dns_protection_allowing {"list":"settings.dns_permit_any {\\"who\\":\\"1.1.1.1 (home-vpn)\\"}"}' });
  assert.equal(firewallDnsLine(tr, fw({ dns_protection_active: true, permits: [] }), true).text, 'settings.dns_protection_blocking');
  assert.deepEqual(firewallDnsLine(tr, fw({ dns_protection_active: false, permits: [] }), true, true),
    { tone: 'muted', text: 'settings.dns_protection_inactive' });
  assert.equal(firewallDnsLine(tr, fw({ dns_protection_active: false }), true, false).text, 'settings.dns_protection_idle');
  assert.equal(firewallDnsLine(tr, fw({ dns_protection_active: false }), false), null);
  const err = firewallDnsLine(tr, fw({ dns_protection_active: false, dns_reconcile_error: 'busy' }), true);
  assert.equal(err.tone, 'error');
  assert.match(err.text, /dns_protection_error/);
  // A reconnect lifting the rules is not an error.
  assert.equal(firewallDnsLine(tr, fw({ suspended: true, dns_reconcile_error: 'busy' }), true).text, 'settings.dns_protection_suspended');
  assert.equal(firewallDnsLine(tr, fw({ suspended: true }), false), null);
});

test('criticalRow words known codes and passes others through', () => {
  assert.ok(isKnownCritical('dns_protection_failing'));
  assert.deepEqual(criticalRow(tr, { code: 'dns_protection_failing', where: 'DNS protection', detail: 'raw' }),
    { where: 'critical.dns_protection_failing_where', detail: 'critical.dns_protection_failing' });
  assert.deepEqual(criticalRow(tr, { code: '', where: 'eventLoop', detail: 'panic' }), { where: 'eventLoop', detail: 'panic' });
});
