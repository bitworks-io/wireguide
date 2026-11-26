// Pure helpers for the Settings > Advanced "Helper" card and the
// helper-unavailable banner, kept out of the components so they are testable.

// i18n key suffix for a helper start mode ("launchd-socket" -> "launchd_socket"),
// or '' for a mode the GUI does not know.
export function startModeKey(mode) {
  const key = String(mode || '').replace(/-/g, '_');
  return ['launchd_socket', 'legacy', 'direct'].includes(key) ? key : '';
}

// The Go side marks "refused: tunnels in use" with a stable token so the UI can
// show a translated explanation instead of the English error text.
export function isRepairBusy(message) {
  return String(message || '').includes('helper_repair_busy');
}

// Whether a critical_error entry offers the repair action.
export function offersRepair(entry) {
  return entry?.action === 'repair_helper';
}
