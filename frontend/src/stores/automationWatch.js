// Detects automation-rule edits made outside this window (CLI, another
// process) so the GUI can say so. This window registers every write it is
// about to make (noteOwnSave / noteOwnRules) BEFORE issuing it; a disk state
// matching a recently registered write is "own" whenever it is observed —
// including a stale read that lands while a later own save is in flight —
// so no timing window can produce a false toast.
import { changedRuleTunnels, ruleSig } from '../lib/automationSafety.js';

const OWN_TTL_MS = 30000;
const OWN_MAX = 16;

let baseline = null; // { tunnel: rules[] } as of the last disk state seen
let own = {}; // tunnel -> [{ sig, at }]

function rulesOf(settings) {
  return settings?.automation?.per_tunnel_rules || {};
}

// Seed/refresh the baseline without reporting anything (startup, after a
// restore performed by this window).
export function setRulesBaseline(settings) {
  baseline = structuredCloneSafe(rulesOf(settings));
}

// Register a write this window is about to make. Call before the write.
export function noteOwnSave(tunnel, rules, now = Date.now()) {
  const list = (own[tunnel] || []).filter((e) => now - e.at < OWN_TTL_MS);
  list.push({ sig: ruleSig(rules || []), at: now });
  own[tunnel] = list.slice(-OWN_MAX);
}

function isOwn(tunnel, rules, now) {
  const sig = ruleSig(rules || []);
  return (own[tunnel] || []).some((e) => now - e.at < OWN_TTL_MS && e.sig === sig);
}

// Compare fresh settings against the last seen disk state, advance it, and
// return the tunnels whose rules changed externally. `known` is the Set of
// live tunnel names.
export function takeExternalRuleChanges(settings, known, now = Date.now()) {
  const next = rulesOf(settings);
  const prev = baseline;
  baseline = structuredCloneSafe(next);
  if (prev === null) return [];
  return changedRuleTunnels(prev, next, known).filter((n) => !isOwn(n, next[n], now));
}

// Test helper.
export function resetAutomationWatch() {
  baseline = null;
  own = {};
}

function structuredCloneSafe(v) {
  return JSON.parse(JSON.stringify(v || {}));
}
