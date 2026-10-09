// The render-diff preview: what an unsaved edit would add to and remove from each host's input chain.
//
// A preview, not a gate. Saving is unaffected by what this says.
// The shape mirrors `src/preview-diff.ts` (`HostDiff`), read defensively because it crosses the wire.

export interface PreviewRule {
  verdict: string;
  proto: string;
  ports: string;
  sources: string[];
  destinations: string[];
  family: string;
}

export interface PreviewHost {
  host: string;
  inputPolicy?: { before: string | null; after: string | null };
  added: PreviewRule[];
  removed: PreviewRule[];
}

export type PreviewReply = { ok: true; changes: PreviewHost[] } | { ok: false; reason: string };

export function previewUrl(site: string): string {
  return site ? `/api/policy/preview?site=${encodeURIComponent(site)}` : "/api/policy/preview";
}

// Strict: every field `src/preview-diff.ts` always writes must be there with its type, or the whole
// answer is refused. Dropping a malformed host or rule would show it as "no change", and an empty
// list would print as "any".
const isStrings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

function readRule(v: unknown): PreviewRule | null {
  if (typeof v !== "object" || v === null) return null;
  const r = v as Record<string, unknown>;
  if (typeof r.verdict !== "string" || typeof r.proto !== "string" || typeof r.ports !== "string") return null;
  if (typeof r.family !== "string" || !isStrings(r.sources) || !isStrings(r.destinations)) return null;
  return {
    verdict: r.verdict, proto: r.proto, ports: r.ports,
    sources: [...r.sources], destinations: [...r.destinations], family: r.family,
  };
}

function readRules(v: unknown): PreviewRule[] | null {
  if (!Array.isArray(v)) return null;
  const out: PreviewRule[] = [];
  for (const x of v) {
    const r = readRule(x);
    if (!r) return null;
    out.push(r);
  }
  return out;
}

const isPolicyValue = (v: unknown): v is string | null => typeof v === "string" || v === null;

function readHost(v: unknown): PreviewHost | null {
  if (typeof v !== "object" || v === null) return null;
  const h = v as Record<string, unknown>;
  if (typeof h.host !== "string") return null;
  const added = readRules(h.added);
  const removed = readRules(h.removed);
  if (!added || !removed) return null;
  if (h.inputPolicy === undefined) return { host: h.host, added, removed };
  const ip = h.inputPolicy as { before?: unknown; after?: unknown } | null;
  if (typeof ip !== "object" || ip === null || !isPolicyValue(ip.before) || !isPolicyValue(ip.after)) return null;
  return { host: h.host, inputPolicy: { before: ip.before, after: ip.after }, added, removed };
}

const MALFORMED = "the preview answer is malformed; nothing below would be trustworthy";

export function readPreviewReply(data: unknown): PreviewReply {
  if (typeof data !== "object" || data === null) return { ok: false, reason: "the manager did not answer the preview" };
  const rec = data as { error?: unknown; changes?: unknown };
  if (typeof rec.error === "string") return { ok: false, reason: rec.error };
  if (!Array.isArray(rec.changes)) return { ok: false, reason: "the preview answer has no changes list" };
  const changes: PreviewHost[] = [];
  for (const x of rec.changes) {
    const h = readHost(x);
    if (!h) return { ok: false, reason: MALFORMED };
    changes.push(h);
  }
  return { ok: true, changes };
}

/** An answer, with what it was asked about: which site, and the exact rule file that was sent. */
export interface PreviewResult {
  site: string;
  content: string;
  changes: PreviewHost[];
}

/**
 * Whether a result still describes what is on screen.
 *
 * `stale` when the table or the site changed after the request was sent — including while it was in
 * flight — so an older answer, "no change" among them, is never shown as describing the current draft.
 */
export function previewView(
  result: PreviewResult | null,
  now: { site: string; content: string },
): { kind: "none" } | { kind: "stale" } | { kind: "shown"; changes: PreviewHost[] } {
  if (!result) return { kind: "none" };
  if (result.site !== now.site || result.content !== now.content) return { kind: "stale" };
  return { kind: "shown", changes: result.changes };
}

/** One rule as a line: `accept tcp 443 from 10.1.0.0/16 to 10.2.0.7/32`. */
export function ruleLine(r: PreviewRule): string {
  const what = [r.proto || "any", r.ports].filter(Boolean).join(" ");
  const from = r.sources.length ? r.sources.join(", ") : "any";
  const to = r.destinations.length ? r.destinations.join(", ") : "any";
  return `${r.verdict} ${what} from ${from} to ${to}`;
}
