import { test } from 'vitest';
import assert from 'node:assert/strict';
import { ssidList, commitDraft, rowFromDisk, blankRow, cleanedRule, normRule, rulesDiffer, macCanon } from './automationRules.js';

test('ssidList trims, drops empties, dedupes case-insensitively', () => {
  assert.deepEqual(ssidList(' Home ', ['home', 'Office', '', 'OFFICE']), ['Home', 'Office']);
  assert.deepEqual(ssidList('', []), []);
});

test('rowFromDisk turns ssid / ssids into tags and carries negate/medium/label', () => {
  const single = rowFromDisk({ when: { type: 'ssid', ssid: 'CafeWiFi' }, do: 'connect' }, 1);
  assert.deepEqual(single.when.ssids, ['CafeWiFi']);
  assert.equal(single.when.ssid, '');
  const list = rowFromDisk({ when: { type: 'ssid', negate: true, ssids: ['A', 'B'] }, do: 'disconnect' }, 2);
  assert.deepEqual(list.when.ssids, ['A', 'B']);
  assert.equal(list.when.negate, true);
  const med = rowFromDisk({ when: { type: 'medium', negate: true, medium: 'wired' } }, 3);
  assert.equal(med.when.medium, 'wired');
  const upper = rowFromDisk({ when: { type: 'medium', medium: ' Wired ' }, do: 'connect' }, 6);
  assert.deepEqual(cleanedRule(upper), { when: { type: 'medium', medium: 'wired' }, do: 'connect' });
  assert.equal(med.do, 'connect');
  const lab = rowFromDisk({ when: { type: 'network', gateway_mac: 'aa:bb:cc:dd:ee:ff', label: 'Office' }, do: 'connect' }, 4);
  assert.equal(lab.when.label, 'Office');
  assert.equal(rowFromDisk({}, 5).when.type, 'network');
});

test('cleanedRule: one SSID saves as ssid, several as ssids', () => {
  const r = blankRow(1);
  r.when.type = 'ssid';
  assert.equal(cleanedRule(r), null);
  r.when.ssid = ' CafeWiFi ';  // draft only (typed, never committed)
  assert.deepEqual(cleanedRule(r), { when: { type: 'ssid', ssid: 'CafeWiFi' }, do: 'connect' });
  r.when.ssids = ['CafeWiFi'];
  r.when.ssid = 'Office';
  assert.deepEqual(cleanedRule(r), { when: { type: 'ssid', ssids: ['CafeWiFi', 'Office'] }, do: 'connect' });
  r.when.ssid = 'cafewifi'; // duplicate draft collapses
  assert.deepEqual(cleanedRule(r), { when: { type: 'ssid', ssid: 'CafeWiFi' }, do: 'connect' });
  r.when.negate = true;
  r.when.ssid = 'A,B';
  assert.deepEqual(cleanedRule(r), { when: { type: 'ssid', ssids: ['CafeWiFi', 'A', 'B'], negate: true }, do: 'connect' });
});

test('cleanedRule: medium needs a valid value; none_match drops negate', () => {
  const r = blankRow(1);
  r.when.type = 'medium';
  assert.equal(cleanedRule(r), null);
  r.when.medium = 'tethered';
  r.when.negate = true;
  r.do = 'disconnect';
  assert.deepEqual(cleanedRule(r), { when: { type: 'medium', medium: 'tethered', negate: true }, do: 'disconnect' });
  r.when.type = 'none_match';
  assert.deepEqual(cleanedRule(r), { when: { type: 'none_match' }, do: 'disconnect' });
});

test('commitDraft splits on commas and keeps the trailing draft', () => {
  const w = { ssid: 'A, B,C', ssids: ['X'] };
  commitDraft(w, false);
  assert.deepEqual(w.ssids, ['X', 'A', 'B']);
  assert.equal(w.ssid, 'C');
  commitDraft(w, true);
  assert.deepEqual(w.ssids, ['X', 'A', 'B', 'C']);
  assert.equal(w.ssid, '');
});

test('load -> cleanedRule round-trips the on-disk shape (self-write is not a diff)', () => {
  const disk = [
    { when: { type: 'ssid', ssid: 'CafeWiFi' }, do: 'connect' },
    { when: { type: 'ssid', negate: true, ssids: ['A', 'B'] }, do: 'connect' },
    { when: { type: 'medium', medium: 'wired' }, do: 'disconnect' },
    { when: { type: 'network', gateway_mac: 'AA-BB-CC-DD-EE-FF', label: 'Office' }, do: 'connect' },
    { when: { type: 'none_match' }, do: 'disconnect' },
  ];
  const local = disk.map((d, i) => cleanedRule(rowFromDisk(d, i)));
  assert.deepEqual(local[0], disk[0]);
  assert.deepEqual(local[1], disk[1]);
  assert.deepEqual(local[2], disk[2]);
  assert.equal(local[3].when.gateway_mac, macCanon('AA-BB-CC-DD-EE-FF'));
  assert.equal(rulesDiffer(disk, local), false);
});

test('rulesDiffer catches external edits to ssids, medium and negate', () => {
  const base = [{ when: { type: 'ssid', ssids: ['A', 'B'] }, do: 'connect' }];
  assert.equal(rulesDiffer(base, [{ when: { type: 'ssid', ssids: ['A', 'C'] }, do: 'connect' }]), true);
  assert.equal(rulesDiffer(base, [{ when: { type: 'ssid', ssids: ['A', 'B'], negate: true }, do: 'connect' }]), true);
  assert.equal(rulesDiffer(base, [{ when: { type: 'ssid', ssid: 'A', ssids: ['B'] }, do: 'connect' }]), false);
  const m = [{ when: { type: 'medium', medium: 'wired' }, do: 'connect' }];
  assert.equal(rulesDiffer(m, [{ when: { type: 'medium', medium: 'wifi' }, do: 'connect' }]), true);
  assert.equal(rulesDiffer(m, []), true);
  assert.equal(normRule({ when: { type: 'none_match', negate: true } }).negate, false);
});
