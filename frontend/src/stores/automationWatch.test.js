import { test, beforeEach } from 'vitest';
import assert from 'node:assert/strict';
import { setRulesBaseline, noteOwnSave, takeExternalRuleChanges, resetAutomationWatch } from './automationWatch.js';

const r = (ssid) => ({ do: 'connect', when: { type: 'ssid', ssid, ssids: [], negate: false } });
const settings = (map) => ({ automation: { per_tunnel_rules: map } });
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
