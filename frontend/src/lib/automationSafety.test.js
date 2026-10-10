import { test } from 'vitest';
import assert from 'node:assert/strict';
import { removeAt, restoreAt, changedRuleTunnels } from './automationSafety.js';

const r = (ssid, d = 'connect') => ({ do: d, when: { type: 'ssid', ssid, ssids: [], negate: false } });

test('removeAt / restoreAt round-trip to the original index', () => {
  const list = ['a', 'b', 'c', 'd'];
  const { list: rest, removed, index } = removeAt(list, 2);
  assert.deepEqual(rest, ['a', 'b', 'd']);
  assert.equal(removed, 'c');
  assert.deepEqual(restoreAt(rest, removed, index), list);
});

test('removeAt out of range removes nothing; restoreAt clamps', () => {
  assert.equal(removeAt(['a'], 5).removed, null);
  assert.equal(removeAt(['a'], -1).removed, null);
  assert.deepEqual(restoreAt(['a'], 'z', 9), ['a', 'z']);
  assert.deepEqual(restoreAt([], 'z', 0), ['z']);
});

test('changedRuleTunnels reports edited tunnels only', () => {
  const prev = { A: [r('x')], B: [r('y')] };
  const next = { A: [r('x')], B: [r('z')] };
  assert.deepEqual(changedRuleTunnels(prev, next), ['B']);
  assert.deepEqual(changedRuleTunnels(prev, prev), []);
});

test('rename is not an external edit; delete is not either', () => {
  assert.deepEqual(changedRuleTunnels({ Old: [r('x')] }, { New: [r('x')] }, new Set(['New'])), []);
  assert.deepEqual(changedRuleTunnels({ Gone: [r('x')] }, {}, new Set()), []);
});

test('rules emptied or added on an existing tunnel are reported', () => {
  const known = new Set(['A', 'B']);
  assert.deepEqual(changedRuleTunnels({ A: [r('x')] }, {}, known), ['A']);
  assert.deepEqual(changedRuleTunnels({}, { B: [r('q')] }, known), ['B']);
  assert.deepEqual(changedRuleTunnels({}, { B: [r('q')] }, new Set()), []);
});

test('reordered rules count as a change (order is priority)', () => {
  assert.deepEqual(changedRuleTunnels({ A: [r('x'), r('y')] }, { A: [r('y'), r('x')] }), ['A']);
});

test('rename with a stale known set is not reported for the old name', () => {
  const prev = { Old: [r('A')] };
  const next = { New: [r('A')] };
  assert.deepEqual(changedRuleTunnels(prev, next, new Set(['Old'])), []);
  assert.deepEqual(changedRuleTunnels(prev, next, new Set(['New'])), []);
});
