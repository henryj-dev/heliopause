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

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

function readRule(v: unknown): PreviewRule | null {
  if (typeof v !== "object" || v === null) return null;
  const r = v as Record<string, unknown>;
  if (typeof r.verdict !== "string") return null;
  return {
    verdict: r.verdict,
    proto: typeof r.proto === "string" ? r.proto : "",
    ports: typeof r.ports === "string" ? r.ports : "",
    sources: strings(r.sources),
    destinations: strings(r.destinations),
    family: typeof r.family === "string" ? r.family : "",
  };
}

const policyValue = (v: unknown): string | null => (typeof v === "string" ? v : null);

export function readPreviewReply(data: unknown): PreviewReply {
  if (typeof data !== "object" || data === null) return { ok: false, reason: "the manager did not answer the preview" };
  const rec = data as { error?: unknown; changes?: unknown };
  if (typeof rec.error === "string") return { ok: false, reason: rec.error };
  if (!Array.isArray(rec.changes)) return { ok: false, reason: "the preview answer has no changes list" };
  const changes: PreviewHost[] = [];
  for (const h of rec.changes) {
    if (typeof h !== "object" || h === null || typeof (h as { host?: unknown }).host !== "string") continue;
    const host = h as { host: string; inputPolicy?: unknown; added?: unknown; removed?: unknown };
    const rules = (v: unknown) => (Array.isArray(v) ? v.map(readRule).filter((r): r is PreviewRule => r !== null) : []);
    const ip = host.inputPolicy as { before?: unknown; after?: unknown } | undefined;
    changes.push({
      host: host.host,
      ...(ip && typeof ip === "object" ? { inputPolicy: { before: policyValue(ip.before), after: policyValue(ip.after) } } : {}),
      added: rules(host.added),
      removed: rules(host.removed),
    });
  }
  return { ok: true, changes };
}

/** One rule as a line: `accept tcp 443 from 10.1.0.0/16 to 10.2.0.7/32`. */
export function ruleLine(r: PreviewRule): string {
  const what = [r.proto || "any", r.ports].filter(Boolean).join(" ");
  const from = r.sources.length ? r.sources.join(", ") : "any";
  const to = r.destinations.length ? r.destinations.join(", ") : "any";
  return `${r.verdict} ${what} from ${from} to ${to}`;
}
