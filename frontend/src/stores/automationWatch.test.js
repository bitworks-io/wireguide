import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setRulesBaseline, noteOwnSave, takeExternalRuleChanges, resetAutomationWatch } from './automationWatch.js';

const r = (ssid) => ({ do: 'connect', when: { type: 'ssid', ssid, ssids: [], negate: false } });
const medium = { do: 'disconnect', when: { type: 'medium', medium: 'wired' } };
const settings = (map, v2 = {}, v3 = {}) => ({
  automation: { per_tunnel_rules: map, per_tunnel_rules_v2: v2, per_tunnel_rules_v3: v3 },
});
const known = new Set(['P']);

beforeEach(resetAutomationWatch);

test('first call only seeds the baseline', () => {
  assert.deepEqual(takeExternalRuleChanges(settings({ P: [r('A')] }), known), []);
});

test('an own save is silent', () => {
  setRulesBaseline(settings({ P: [r('A')] }));
  noteOwnSave('P', [r('B')]);
  assert.deepEqual(takeExternalRuleChanges(settings({ P: [r('B')] }), known), []);
});

test('a stale read while a later own save is in flight is silent, twice', () => {
  setRulesBaseline(settings({ P: [r('A')] }));
  noteOwnSave('P', [r('B')]);
  noteOwnSave('P', [r('C')]);
  assert.deepEqual(takeExternalRuleChanges(settings({ P: [r('B')] }), known), []);
  assert.deepEqual(takeExternalRuleChanges(settings({ P: [r('C')] }), known), []);
});

test('an outside edit is reported; an expired own write does not mask it', () => {
  setRulesBaseline(settings({ P: [r('A')] }));
  assert.deepEqual(takeExternalRuleChanges(settings({ P: [r('X')] }), known), ['P']);
  noteOwnSave('P', [r('Y')], 0);
  assert.deepEqual(takeExternalRuleChanges(settings({ P: [r('Y')] }), known, 60000), ['P']);
});

test('an own removal of all rules is silent', () => {
  setRulesBaseline(settings({ P: [r('A')] }));
  noteOwnSave('P', []);
  assert.deepEqual(takeExternalRuleChanges(settings({}), known), []);
});

// A tunnel's list moves between storage keys when its rules change tier.
// Reading only per_tunnel_rules would see a delete (or, with another
// tunnel, a rename) instead of the edit.
test('rules are read from all three storage keys', () => {
  setRulesBaseline(settings({ P: [r('A')] }));
  noteOwnSave('P', [r('A'), medium]);
  assert.deepEqual(takeExternalRuleChanges(settings({}, {}, { P: [r('A'), medium] }), known), []);
  // An outside edit to a tier-3 list is still reported.
  assert.deepEqual(takeExternalRuleChanges(settings({}, {}, { P: [medium] }), known, Date.now() + 60000), ['P']);
  // Moving from _v3 to _v2 by an outside edit is an edit, not a delete.
  const neg = { do: 'connect', when: { type: 'ssid', ssid: 'A', negate: true } };
  assert.deepEqual(takeExternalRuleChanges(settings({}, { P: [neg] }, {}), known, Date.now() + 60000), ['P']);
});

test('a rename by the app is not reported', () => {
  setRulesBaseline(settings({ P: [r('A')] }));
  assert.deepEqual(takeExternalRuleChanges(settings({ Q: [r('A')] }), new Set(['Q'])), []);
});
