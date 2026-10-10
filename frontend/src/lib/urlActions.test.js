import { describe, it, expect } from 'vitest';
import { mergeURLActions, MAX_PENDING_URL_ACTIONS } from './urlActions.js';

const dis = (tunnel) => ({ kind: 'disconnect', tunnel, confirm: true });
const con = (tunnel) => ({ kind: 'connect', tunnel, confirm: true });

describe('mergeURLActions', () => {
  it('dedupes against actions already waiting across drains', () => {
    let q = [];
    // 50 URLs, each drained from the Go queue before the next arrives.
    for (let i = 0; i < 50; i++) q = mergeURLActions(q, [dis('Site')]);
    expect(q).toEqual([dis('Site')]);
  });

  it('caps the number of waiting sheets', () => {
    let q = [];
    for (let i = 0; i < 50; i++) q = mergeURLActions(q, [con(`t${i}`)]);
    expect(q.length).toBe(MAX_PENDING_URL_ACTIONS);
    expect(q.map((a) => a.tunnel)).toEqual(['t0', 't1', 't2', 't3']);
  });

  it('keeps distinct kinds for the same tunnel and tolerates empty input', () => {
    let q = mergeURLActions([], [con('Branch'), dis('Branch'), con('Branch')]);
    expect(q).toEqual([con('Branch'), dis('Branch')]);
    expect(mergeURLActions(q, null)).toEqual(q);
    expect(mergeURLActions(undefined, [])).toEqual([]);
  });

  it('admits a new action once a sheet is resolved', () => {
    let q = [];
    for (let i = 0; i < 4; i++) q = mergeURLActions(q, [con(`t${i}`)]);
    q = q.slice(1);
    q = mergeURLActions(q, [con('t9')]);
    expect(q.map((a) => a.tunnel)).toEqual(['t1', 't2', 't3', 't9']);
  });
});
