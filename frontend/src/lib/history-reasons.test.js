import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { END_REASONS, START_REASONS, endReasonKey, startReasonKey } from './history-reasons.js';

const locales = ['en', 'ko', 'ja', 'zh'].map(l => [
  l, JSON.parse(readFileSync(new URL(`../i18n/${l}.json`, import.meta.url), 'utf8')),
]);

function lookup(dict, key) {
  return key.split('.').reduce((o, k) => (o == null ? undefined : o[k]), dict);
}

test('end reasons map to their own label, unknown to Disconnected', () => {
  assert.equal(endReasonKey('watchdog'), 'history.reason_watchdog');
  assert.equal(endReasonKey('automation'), 'history.reason_automation');
  assert.equal(endReasonKey('app_quit'), 'history.reason_app_quit');
  assert.equal(endReasonKey(''), 'history.reason_user');
  assert.equal(endReasonKey(undefined), 'history.reason_user');
  assert.equal(endReasonKey('from_the_future'), 'history.reason_user');
});

test('start reasons map to a label; unknown or missing shows nothing', () => {
  assert.equal(startReasonKey('recovery'), 'history.start_recovery');
  assert.equal(startReasonKey('network_change'), 'history.start_network_change');
  assert.equal(startReasonKey(''), '');
  assert.equal(startReasonKey(undefined), '');
  assert.equal(startReasonKey('watchdog'), ''); // never a start reason
});

test('every history reason label exists in every locale', () => {
  const keys = [
    ...END_REASONS.map(endReasonKey),
    ...START_REASONS.map(startReasonKey),
    'history.started_by', 'history.ssid',
  ];
  for (const [locale, dict] of locales) {
    for (const key of keys) {
      const v = lookup(dict, key);
      assert.equal(typeof v, 'string', `${locale} is missing ${key}`);
      assert.ok(v.length > 0, `${locale} has an empty ${key}`);
    }
  }
});
