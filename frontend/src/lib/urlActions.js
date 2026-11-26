// wireguide:// confirmation queue (frontend side).
//
// The Go queue (internal/app/url_actions.go) dedupes and caps only the
// actions still waiting there, and TakeURLActions drains it on every
// "url-action" event. Without the same rules here, a flood of URLs delivered
// one at a time (each drained before the next arrives) would pile up one
// confirmation sheet per URL. Keep the cap equal to maxPendingURLActions.
export const MAX_PENDING_URL_ACTIONS = 4;

const key = (a) => `${a && a.kind}|${a && a.tunnel}`;

// mergeURLActions appends incoming to existing, dropping duplicates (same
// kind and tunnel as one already waiting) and anything past the cap.
export function mergeURLActions(existing, incoming, max = MAX_PENDING_URL_ACTIONS) {
  const out = [...(existing || [])];
  const seen = new Set(out.map(key));
  for (const a of incoming || []) {
    if (!a || out.length >= max) break;
    const k = key(a);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(a);
  }
  return out;
}
