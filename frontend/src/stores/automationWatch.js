// Detects automation-rule edits made outside this window (the CLI, another
// process) so the app can say so. The window registers every rules write
// it is about to make (noteOwnSave) BEFORE issuing it; a disk state that
// matches a recently registered write is treated as its own whenever it is
// observed, including a stale read that lands while a later own save is in
// flight, so no timing window produces a false notice.
import { allRules } from '../lib/automationRules.js';
import { changedRuleTunnels, ruleSig } from '../lib/automationSafety.js';

const OWN_TTL_MS = 30000;
const OWN_MAX = 16;

let baseline = null; // { tunnel: rules[] } as of the last disk state seen
let own = {}; // tunnel -> [{ sig, at }]

// Rules live under three storage-tier keys (per_tunnel_rules, _v2, _v3);
// a tunnel's list moves between them as its rules change, so always merge.
function rulesOf(settings) {
  return clone(allRules(settings));
}

// Seed or refresh the baseline without reporting anything (startup, or
// after a write this window made and already knows about).
export function setRulesBaseline(settings) {
  baseline = rulesOf(settings);
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

// Compare fresh settings against the last disk state seen, advance it, and
// return the tunnels whose rules changed outside this window. `known` is
// the Set of live tunnel names. The first call only seeds the baseline.
export function takeExternalRuleChanges(settings, known, now = Date.now()) {
  const next = rulesOf(settings);
  const prev = baseline;
  baseline = next;
  if (prev === null) return [];
  return changedRuleTunnels(prev, next, known).filter((n) => !isOwn(n, next[n], now));
}

// Test helper.
export function resetAutomationWatch() {
  baseline = null;
  own = {};
}

function clone(v) {
  return JSON.parse(JSON.stringify(v || {}));
}
