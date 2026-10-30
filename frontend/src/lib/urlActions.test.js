import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeURLActions, MAX_PENDING_URL_ACTIONS } from './urlActions.js';

const dis = (tunnel) => ({ kind: 'disconnect', tunnel, confirm: true });
const con = (tunnel) => ({ kind: 'connect', tunnel, confirm: true });

test('dedupes against actions already waiting across drains', () => {
  let q = [];
  // 50 URLs, each drained from the Go queue before the next arrives.
  for (let i = 0; i < 50; i++) q = mergeURLActions(q, [dis('Site')]);
  assert.deepEqual(q, [dis('Site')]);
});

test('caps the number of waiting sheets', () => {
  let q = [];
  for (let i = 0; i < 50; i++) q = mergeURLActions(q, [con(`t${i}`)]);
  assert.equal(q.length, MAX_PENDING_URL_ACTIONS);
  assert.deepEqual(q.map((a) => a.tunnel), ['t0', 't1', 't2', 't3']);
});

test('keeps distinct kinds for the same tunnel and tolerates empty input', () => {
  const q = mergeURLActions([], [con('Branch'), dis('Branch'), con('Branch')]);
  assert.deepEqual(q, [con('Branch'), dis('Branch')]);
  assert.deepEqual(mergeURLActions(q, null), q);
  assert.deepEqual(mergeURLActions(undefined, []), []);
});

test('tunnel names are compared case-sensitively', () => {
  const q = mergeURLActions([con('Home')], [con('home')]);
  assert.deepEqual(q.map((a) => a.tunnel), ['Home', 'home']);
});

test('admits a new action once a sheet is resolved', () => {
  let q = [];
  for (let i = 0; i < 4; i++) q = mergeURLActions(q, [con(`t${i}`)]);
  q = q.slice(1);
  q = mergeURLActions(q, [con('t9')]);
  assert.deepEqual(q.map((a) => a.tunnel), ['t1', 't2', 't3', 't9']);
});
