import test from 'node:test';
import assert from 'node:assert/strict';
import { startModeKey, isRepairBusy, offersRepair } from './helper-info.js';

test('startModeKey maps wire modes to i18n suffixes', () => {
  assert.equal(startModeKey('launchd-socket'), 'launchd_socket');
  assert.equal(startModeKey('legacy'), 'legacy');
  assert.equal(startModeKey('direct'), 'direct');
  assert.equal(startModeKey('something-new'), '');
  assert.equal(startModeKey(undefined), '');
});

test('isRepairBusy recognises the refusal token only', () => {
  assert.equal(isRepairBusy('helper_repair_busy: disconnect all tunnels (in use: [a])'), true);
  assert.equal(isRepairBusy(new Error('helper_repair_busy: x').message), true);
  assert.equal(isRepairBusy('spawn helper: user cancelled'), false);
  assert.equal(isRepairBusy(''), false);
});

test('offersRepair only for the repair_helper action', () => {
  assert.equal(offersRepair({ action: 'repair_helper', code: 'helper_unavailable' }), true);
  assert.equal(offersRepair({ where: 'eventLoop', detail: 'x' }), false);
  assert.equal(offersRepair(null), false);
});
