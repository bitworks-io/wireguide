// Pure rule-row logic for the Automation editor (AutomationEditor.svelte),
// kept free of Svelte/Wails so it is testable under plain node.
//
// A row is the editor's mutable form of a rule:
//   { _id, when: { type, negate, ssid, ssids, subnet, gateway_mac, label, medium }, do }
// For an ssid row, `ssids` holds the committed SSID tags and `ssid` is the
// draft text still being typed (it counts as part of the set, so typing
// one name and closing the dialog saves it, as before tags existed).

export const MEDIUMS = ['wifi', 'wired', 'tethered'];
export const DEFAULT_MEDIUM = 'wired';

export function macHex(v) { return (v || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase(); }
export function macInvalid(v) { const s = (v || '').trim(); return s !== '' && macHex(s).length !== 12; }
// Canonical form: lower-case, colon-separated (b0:38:6c:54:8b:ab).
export function macCanon(v) {
  const h = macHex(v);
  if (h.length !== 12) return (v || '').trim(); // leave as-is so the user can keep fixing
  return h.match(/.{2}/g).join(':');
}

// ssidList trims, drops empties and de-duplicates case-insensitively
// (SSID matching is case-insensitive), keeping the first spelling and order.
export function ssidList(...lists) {
  const out = [];
  const seen = new Set();
  for (const l of lists) {
    for (const raw of (Array.isArray(l) ? l : [l])) {
      const s = (raw || '').trim();
      if (!s) continue;
      const k = s.toLowerCase();
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(s);
    }
  }
  return out;
}

// splitDraft splits typed SSID text on commas.
export function splitDraft(text) {
  return (text || '').split(',');
}

// commitDraft moves complete names from the draft into the tags. With
// all=false the text after the last comma stays as the draft (the user is
// still typing it); with all=true (Enter, blur) everything is committed.
export function commitDraft(when, all) {
  const parts = splitDraft(when.ssid);
  const keep = all ? '' : parts.pop();
  when.ssids = ssidList(when.ssids || [], parts);
  when.ssid = keep;
  return when;
}

// rowFromDisk builds an editor row from a persisted rule. SSIDs (single or
// list) become tags; the draft starts empty.
export function rowFromDisk(r, id) {
  const w = r?.when || {};
  return {
    _id: id,
    when: {
      type: w.type || 'network',
      negate: !!w.negate,
      ssid: '',
      ssids: ssidList(w.ssid || '', w.ssids || []),
      subnet: w.subnet || '',
      gateway_mac: w.gateway_mac || '',
      // Not editable here; carried through the round-trip so a GUI
      // save never strips a label another writer attached.
      label: w.label || '',
      // Lower-cased like the engine, so a hand-edited "Wired" stays editable
      // (and isn't dropped as incomplete on the next save).
      medium: (w.medium || '').trim().toLowerCase(),
    },
    do: r?.do || 'connect',
  };
}

export function blankRow(id) {
  return { _id: id, when: { type: 'network', negate: false, ssid: '', ssids: [], subnet: '', gateway_mac: '', label: '', medium: '' }, do: 'connect' };
}

// cleanedRule returns the normalized persisted form of a row, or null while
// the row's condition is incomplete. One SSID is saved as `ssid`, several
// as `ssids` (then `ssid` is omitted), so a single-network rule keeps the
// exact on-disk shape it always had.
export function cleanedRule(r) {
  const t = r.when.type;
  let when = null;
  if (t === 'none_match') when = { type: 'none_match' };
  else if (t === 'ssid') {
    const set = ssidList(r.when.ssids || [], splitDraft(r.when.ssid));
    if (set.length === 1) when = { type: 'ssid', ssid: set[0] };
    else if (set.length > 1) when = { type: 'ssid', ssids: set };
  } else if (t === 'subnet' && r.when.subnet.trim() !== '') when = { type: 'subnet', subnet: r.when.subnet.trim() };
  else if (t === 'network' && r.when.gateway_mac.trim() !== '') when = { type: 'network', gateway_mac: macCanon(r.when.gateway_mac) };
  else if (t === 'medium' && MEDIUMS.includes(r.when.medium)) when = { type: 'medium', medium: r.when.medium };
  if (!when) return null;
  // "is not" only applies to concrete conditions; else can't be negated.
  if (r.when.negate && t !== 'none_match') when.negate = true;
  if (r.when.label) when.label = r.when.label;
  return { when, do: r.do };
}

// normRule puts a disk rule and a persisted-set rule through the SAME
// normalization (load's type fallback, MAC canonicalization, SSID set), so
// a self-write never reads as an external change.
export function normRule(d) {
  const w = d?.when || {};
  return {
    do: d?.do || 'connect',
    type: w.type || 'network',
    negate: !!w.negate && w.type !== 'none_match',
    ssids: ssidList(w.ssid || '', w.ssids || []).join('\n'),
    subnet: (w.subnet || '').trim(),
    mac: macCanon(w.gateway_mac || ''),
    label: w.label || '',
    medium: (w.medium || '').trim().toLowerCase(),
  };
}

// rulesDiffer reports whether the on-disk rules disagree with what the
// editor would persist right now. Positional compare: order is priority.
export function rulesDiffer(disk, local) {
  if (disk.length !== local.length) return true;
  return disk.some((d, i) => {
    const a = normRule(d), b = normRule(local[i]);
    return a.do !== b.do || a.type !== b.type || a.negate !== b.negate || a.ssids !== b.ssids ||
      a.subnet !== b.subnet || a.mac !== b.mac || a.label !== b.label || a.medium !== b.medium;
  });
}
