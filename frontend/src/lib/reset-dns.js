// Pure helpers for Settings > Advanced "Reset DNS & firewall", kept out of
// the component so they are testable. `t` is the i18n translator, which
// returns the key itself when a translation is missing.

function translated(t, key, params) {
  if (!key) return '';
  const out = t(key, params || {});
  return out && out !== key ? out : '';
}

// Localized step name, falling back to the wire name.
export function stepLabel(t, name) {
  return translated(t, 'reset_dns.step.' + name) || name;
}

// Localized step detail, falling back to the helper's English text.
export function stepDetail(t, step) {
  return translated(t, step?.detail_key, step?.detail_params) || step?.detail || '';
}

// Which confirm-sheet option a refused reset needs: the helper is
// authoritative (it also sees wanted and pending-restore tunnels the GUI
// status does not show).
export function refusalNeeds(resp) {
  if (!resp?.refused) return { force: false, killSwitchOff: false };
  return {
    force: resp.reason === 'tunnels_active',
    killSwitchOff: resp.reason === 'kill_switch_on',
  };
}

// Whether every step succeeded.
export function resetSucceeded(resp) {
  return !!resp && !resp.refused && (resp.steps || []).every((s) => s.ok);
}
