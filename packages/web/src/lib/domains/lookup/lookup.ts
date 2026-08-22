// GET /api/policy/lookup and GET /api/policy/where-used, as this package
// is allowed to see them.
//
// Duplicated rather than imported from `heliopause`: the web package must not
// pull the library into a Vite bundle. The two questions stay in one domain
// because they share a screen — which rule decides this, and where is this
// written — but they are parsed apart so a merged list cannot be built by
// accident.

export type Verdict =
  | { kind: "matches" }
  | { kind: "no"; why: string }
  | { kind: "undecidable"; why: string; needsWorkload?: boolean };

export type PolicyAction = "allow" | "deny";
export type PolicyLayer = "host" | "workload";

export interface LookupHit {
  id: string;
  name: string;
  action: PolicyAction;
  layer: PolicyLayer;
  proto: string;
  ports: string;
  priority: number;
  src: Verdict;
  dst: Verdict;
  port: Verdict;
  proto_: Verdict;
}

export interface LookupView {
  matches: LookupHit[];
  undecidable: LookupHit[];
  needsWorkload: number;
  considered: number;
  generation: string | null;
  dirty: boolean;
}

export type LookupRead =
  | { ok: true; view: LookupView }
  | { ok: false; reason: string };

export type UsageMatch = "exact" | "contains";
export type UsageWhere = "src" | "dst" | "ports";

export interface Usage {
  policyId: string;
  where: UsageWhere;
  text: string;
  action: PolicyAction;
  layer: PolicyLayer;
  enabled: boolean;
  match: UsageMatch;
}

export interface RepeatedLiteral {
  value: string;
  count: number;
  policyIds: string[];
}

export interface WhereUsedView {
  query: string;
  usages: Usage[];
  repeated: RepeatedLiteral[];
  considered: number;
  generation: string | null;
}

export type WhereUsedRead =
  | { ok: true; view: WhereUsedView }
  | { ok: false; reason: string };

const ACTIONS = new Set<PolicyAction>(["allow", "deny"]);
const LAYERS = new Set<PolicyLayer>(["host", "workload"]);
const WHERES = new Set<UsageWhere>(["src", "dst", "ports"]);
const MATCHES = new Set<UsageMatch>(["exact", "contains"]);

export type LookupParams = {
  src: string;
  dst: string;
  srcWorkload: string;
  dstWorkload: string;
  port: string;
  proto: string;
  lang?: string;
};

/** The last search, in a new language — or null if there is nothing to replay. */
export function replayLookupLang(last: LookupParams | null, lang: string): LookupParams | null {
  if (!last) return null;
  if (last.lang === lang) return null;
  return { ...last, lang };
}

export function lookupSearch(params: LookupParams): string {
  const query = new URLSearchParams({
    src: params.src.trim(),
    dst: params.dst.trim(),
    srcWorkload: params.srcWorkload.trim(),
    dstWorkload: params.dstWorkload.trim(),
    port: params.port.trim(),
    proto: params.proto,
  });
  if (params.lang) query.set("lang", params.lang);
  return query.toString();
}

export function verdictWhy(verdict: Verdict): string {
  return verdict.kind === "matches" ? "" : verdict.why;
}

/** Hits waiting on a workload name — listed once as a sentence, not as forty rows. */
export function workloadDeferred(hits: readonly LookupHit[]): LookupHit[] {
  return hits.filter((hit) =>
    [hit.src, hit.dst].some((verdict) => verdict.kind === "undecidable" && verdict.needsWorkload === true),
  );
}

/** The undecidable remainder: cannot be restated away by naming a workload. */
export function remainingUndecidable(hits: readonly LookupHit[]): LookupHit[] {
  const deferred = new Set(workloadDeferred(hits));
  return hits.filter((hit) => !deferred.has(hit));
}

export function exactUsages(usages: readonly Usage[]): Usage[] {
  return usages.filter((usage) => usage.match === "exact");
}

export function coveringUsages(usages: readonly Usage[]): Usage[] {
  return usages.filter((usage) => usage.match === "contains");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readVerdict(value: unknown): Verdict | null {
  if (!isRecord(value) || typeof value.kind !== "string") return null;
  if (value.kind === "matches") return { kind: "matches" };
  if (value.kind === "no" && typeof value.why === "string") return { kind: "no", why: value.why };
  if (value.kind === "undecidable" && typeof value.why === "string") {
    return {
      kind: "undecidable",
      why: value.why,
      ...(value.needsWorkload === true ? { needsWorkload: true } : {}),
    };
  }
  return null;
}

function readHit(value: unknown): LookupHit | null {
  if (!isRecord(value)) return null;
  if (typeof value.id !== "string" || typeof value.name !== "string") return null;
  if (typeof value.action !== "string" || !ACTIONS.has(value.action as PolicyAction)) return null;
  if (typeof value.layer !== "string" || !LAYERS.has(value.layer as PolicyLayer)) return null;
  if (typeof value.proto !== "string" || typeof value.priority !== "number") return null;
  const src = readVerdict(value.src);
  const dst = readVerdict(value.dst);
  const port = readVerdict(value.port);
  const proto_ = readVerdict(value.proto_);
  if (!src || !dst || !port || !proto_) return null;
  return {
    id: value.id,
    name: value.name,
    action: value.action as PolicyAction,
    layer: value.layer as PolicyLayer,
    proto: value.proto,
    ports: typeof value.ports === "string" ? value.ports : "",
    priority: value.priority,
    src,
    dst,
    port,
    proto_,
  };
}

export function readLookupView(data: unknown): LookupRead {
  if (!isRecord(data)) return { ok: false, reason: "lookup view is not an object" };
  if (!Array.isArray(data.matches) || !Array.isArray(data.undecidable)) {
    return { ok: false, reason: "lookup view is missing matches/undecidable" };
  }
  if (typeof data.considered !== "number" || typeof data.needsWorkload !== "number") {
    return { ok: false, reason: "lookup view is missing considered/needsWorkload" };
  }
  const matches: LookupHit[] = [];
  for (const row of data.matches) {
    const hit = readHit(row);
    if (!hit) return { ok: false, reason: "a lookup match is malformed" };
    matches.push(hit);
  }
  const undecidable: LookupHit[] = [];
  for (const row of data.undecidable) {
    const hit = readHit(row);
    if (!hit) return { ok: false, reason: "an undecidable hit is malformed" };
    undecidable.push(hit);
  }
  return {
    ok: true,
    view: {
      matches,
      undecidable,
      needsWorkload: data.needsWorkload,
      considered: data.considered,
      generation: typeof data.generation === "string" ? data.generation : null,
      dirty: data.dirty === true,
    },
  };
}

function readUsage(value: unknown): Usage | null {
  if (!isRecord(value) || typeof value.policyId !== "string" || typeof value.text !== "string") return null;
  if (typeof value.action !== "string" || !ACTIONS.has(value.action as PolicyAction)) return null;
  if (typeof value.layer !== "string" || !LAYERS.has(value.layer as PolicyLayer)) return null;
  if (typeof value.where !== "string" || !WHERES.has(value.where as UsageWhere)) return null;
  if (typeof value.match !== "string" || !MATCHES.has(value.match as UsageMatch)) return null;
  if (typeof value.enabled !== "boolean") return null;
  return {
    policyId: value.policyId,
    where: value.where as UsageWhere,
    text: value.text,
    action: value.action as PolicyAction,
    layer: value.layer as PolicyLayer,
    enabled: value.enabled,
    match: value.match as UsageMatch,
  };
}

function readRepeated(value: unknown): RepeatedLiteral | null {
  if (!isRecord(value) || typeof value.value !== "string" || typeof value.count !== "number") return null;
  if (!Array.isArray(value.policyIds)) return null;
  const policyIds: string[] = [];
  for (const id of value.policyIds) {
    if (typeof id !== "string") return null;
    policyIds.push(id);
  }
  return { value: value.value, count: value.count, policyIds };
}

export function readWhereUsedView(data: unknown): WhereUsedRead {
  if (!isRecord(data)) return { ok: false, reason: "where-used view is not an object" };
  if (typeof data.query !== "string" || typeof data.considered !== "number") {
    return { ok: false, reason: "where-used view is missing query/considered" };
  }
  if (!Array.isArray(data.usages) || !Array.isArray(data.repeated)) {
    return { ok: false, reason: "where-used view is missing usages/repeated" };
  }
  const usages: Usage[] = [];
  for (const row of data.usages) {
    const usage = readUsage(row);
    if (!usage) return { ok: false, reason: "a usage row is malformed" };
    usages.push(usage);
  }
  const repeated: RepeatedLiteral[] = [];
  for (const row of data.repeated) {
    const literal = readRepeated(row);
    if (!literal) return { ok: false, reason: "a repeated-literal row is malformed" };
    repeated.push(literal);
  }
  return {
    ok: true,
    view: {
      query: data.query,
      usages,
      repeated,
      considered: data.considered,
      generation: typeof data.generation === "string" ? data.generation : null,
    },
  };
}
