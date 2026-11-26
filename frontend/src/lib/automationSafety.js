// Pure helpers for the rule editor's safety net: undo of a removed rule,
// and detecting rule changes made outside the app. Free of Svelte/Wails
// imports so they run under node --test.
import { rulesDiffer, normRule } from './automationRules.js';

export const UNDO_MS = 5000;

// Returns the list without index i, plus what was removed. An out-of-range
// index removes nothing.
export function removeAt(list, i) {
  if (!Number.isInteger(i) || i < 0 || i >= list.length) return { list: [...list], removed: null, index: -1 };
  return { list: list.filter((_, idx) => idx !== i), removed: list[i], index: i };
}

// Re-inserts a removed item at its old index (clamped when the list has
// shrunk since).
export function restoreAt(list, item, index) {
  const at = Math.max(0, Math.min(index, list.length));
  const out = [...list];
  out.splice(at, 0, item);
  return out;
}

export const ruleSig = (rules) => JSON.stringify((rules || []).map(normRule));

// Which tunnels' rules differ between two { tunnel: rules[] } maps.
// A tunnel present in both maps is reported when its rules differ. A tunnel
// that appears or disappears is a create/delete, and a pair (disappeared,
// appeared) carrying identical rules is a rename; neither is a rules edit.
// An entry dropped because all its rules were removed is reported when the
// tunnel is still in `known` (the live tunnel names); pass null to skip
// that check.
export function changedRuleTunnels(prev, next, known = null) {
  const out = [];
  prev = prev || {};
  next = next || {};
  const names = new Set([...Object.keys(prev), ...Object.keys(next)]);
  const removedSigs = new Set(Object.keys(prev).filter((n) => !(n in next)).map((n) => ruleSig(prev[n])));
  const addedSigs = new Set(Object.keys(next).filter((n) => !(n in prev)).map((n) => ruleSig(next[n])));
  for (const n of names) {
    const inPrev = n in prev;
    const inNext = n in next;
    const a = prev[n] || [];
    const b = next[n] || [];
    if (inPrev && inNext) {
      if (rulesDiffer(a, b)) out.push(n);
    } else if (inNext) {
      // New entry: a rename if the same rules vanished elsewhere.
      if (b.length && !removedSigs.has(ruleSig(b)) && (!known || known.has(n))) out.push(n);
    } else if (inPrev) {
      // Entry dropped: all rules removed from a tunnel that still exists,
      // unless the same rules reappeared under a new name (a rename whose
      // tunnel list has not refreshed yet).
      if (known && known.has(n) && a.length && !addedSigs.has(ruleSig(a))) out.push(n);
    }
  }
  return out.sort();
}
