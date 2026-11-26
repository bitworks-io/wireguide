// Reason codes on history sessions. End reasons come from the helper's
// recent_disconnects (user, automation, recovery, watchdog) or the GUI
// itself (user, reconnect, app_quit); start reasons from the helper's
// last_change_reason. Unknown codes fall back so a newer helper never
// renders a raw i18n key.
export const END_REASONS = [
  'user', 'automation', 'wake', 'network_change', 'health_check',
  'reconnect', 'recovery', 'watchdog', 'app_quit', 'error',
];
export const START_REASONS = [
  'user', 'automation', 'wake', 'network_change', 'health_check',
  'reconnect', 'recovery',
];

// endReasonKey is the i18n key for how a session ended ("Disconnected"
// for anything unknown or missing, as before).
export function endReasonKey(reason) {
  return END_REASONS.includes(reason) ? `history.reason_${reason}` : 'history.reason_user';
}

// startReasonKey is the i18n key for what started a session, or '' when
// unknown (records made before start reasons existed, or an older helper).
export function startReasonKey(reason) {
  return START_REASONS.includes(reason) ? `history.start_${reason}` : '';
}
