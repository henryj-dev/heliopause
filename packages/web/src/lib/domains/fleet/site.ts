// The manager's GET /api/site, as this package is allowed to see it.
//
// Duplicated rather than imported from `heliopause`: the web package must not
// pull the library into a Vite bundle. The fields here are the ones the fleet
// table renders; extra keys from the server are ignored.

export type RelayResult =
  | { name: string; url: string; ok: true }
  | { name: string; url: string; ok: false; error: string };

export type ContradictionKind =
  | "artifact-hash-changed"
  | "artifact-hash-wrong"
  | "unknown-generation"
  | "kernel-unchanged";

export interface HostContradiction {
  kind: ContradictionKind;
  certainty: "certain" | "unexplained";
  detail: string;
}

export interface WorkloadMembership {
  at: string;
  namespaces: Record<string, string[]>;
  labelled: Record<string, string[]>;
}

export interface WorkloadHalf {
  cluster: string;
  state: string | null;
  expected: number;
  detail: string | null;
  membership: WorkloadMembership | null;
}

export interface SiteHost {
  vpc: string;
  host: string;
  state: string | null;
  generation: string | null;
  current: boolean;
  drifted: boolean;
  ageSec: number | null;
  stage: string | null;
  blockedBy: string | null;
  maintenance: string | null;
  /** Always an array. Empty means checked, nothing wrong — not "did not look". */
  contradictions: HostContradiction[];
  /** `null` on a host with no workload half. Not the same as `state: null`. */
  workload: WorkloadHalf | null;
  /**
   * Other tables filtering on this host. `null` = did not report; `[]` = looked, none.
   * Those two must not render the same.
   */
  unexpectedFilters: string[] | null;
  /**
   * Changes to our table the agent did not make. `null` = did not report; `[]` = watched, none.
   */
  intrusions: HostIntrusion[] | null;
  /** Ports another table redirects inbound. `null` = did not report; `[]` = looked, none. */
  publishedPorts: string[] | null;
  /**
   * Kernel IPv4 routes. `null` = did not report; `[]` = looked, none.
   * The number that matters is how many arrived by hand.
   */
  routes: HostRoute[] | null;
}

export interface HostRoute {
  dst: string;
  via: string;
  dev: string;
  proto: string;
  table: string;
  origin: "automatic" | "static" | "unstated" | null;
  handAdded: boolean;
}

export interface HostIntrusion {
  at: string;
  table: string;
  raw: string;
  pid: number | null;
  process: string | null;
  byAgent: boolean;
}

export interface SiteView {
  vpcs: RelayResult[];
  hosts: SiteHost[];
  /** Relay sentences. An unreachable VPC is the first of them. */
  problems: string[];
  reachable: number;
  asked: number;
}

export type SiteRead =
  | { ok: true; site: SiteView }
  | { ok: false; reason: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

const CONTRADICTION_KINDS = new Set<string>([
  "artifact-hash-changed",
  "artifact-hash-wrong",
  "unknown-generation",
  "kernel-unchanged",
]);

function readStringListMap(value: unknown): Record<string, string[]> | null {
  if (!isRecord(value)) return null;
  const out: Record<string, string[]> = {};
  for (const [key, list] of Object.entries(value)) {
    if (!Array.isArray(list) || list.some((item) => typeof item !== "string")) return null;
    out[key] = list;
  }
  return out;
}

function readMembership(value: unknown): WorkloadMembership | null {
  if (value === null || value === undefined) return null;
  if (!isRecord(value) || typeof value.at !== "string") return null;
  const namespaces = readStringListMap(value.namespaces);
  const labelled = readStringListMap(value.labelled);
  if (!namespaces || !labelled) return null;
  return { at: value.at, namespaces, labelled };
}

function readWorkload(value: unknown): WorkloadHalf | null {
  if (value === null || value === undefined) return null;
  if (!isRecord(value) || typeof value.cluster !== "string") return null;
  if (typeof value.expected !== "number") return null;
  return {
    cluster: value.cluster,
    state: typeof value.state === "string" ? value.state : null,
    expected: value.expected,
    detail: typeof value.detail === "string" ? value.detail : null,
    membership: readMembership(value.membership),
  };
}

function readContradiction(value: unknown): HostContradiction | null {
  if (!isRecord(value)) return null;
  if (typeof value.kind !== "string" || !CONTRADICTION_KINDS.has(value.kind)) return null;
  if (value.certainty !== "certain" && value.certainty !== "unexplained") return null;
  if (typeof value.detail !== "string") return null;
  return {
    kind: value.kind as ContradictionKind,
    certainty: value.certainty,
    detail: value.detail,
  };
}

function readContradictions(value: unknown): HostContradiction[] {
  if (!Array.isArray(value)) return [];
  const out: HostContradiction[] = [];
  for (const item of value) {
    const row = readContradiction(item);
    if (row) out.push(row);
  }
  return out;
}

function readStringListOrNull(value: unknown): string[] | null {
  if (value === null || value === undefined) return null;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) return null;
  return value;
}

function readIntrusion(value: unknown): HostIntrusion | null {
  if (!isRecord(value)) return null;
  if (typeof value.at !== "string" || typeof value.table !== "string" || typeof value.raw !== "string") return null;
  if (typeof value.byAgent !== "boolean") return null;
  return {
    at: value.at,
    table: value.table,
    raw: value.raw,
    pid: typeof value.pid === "number" ? value.pid : null,
    process: typeof value.process === "string" ? value.process : null,
    byAgent: value.byAgent,
  };
}

function readRoute(value: unknown): HostRoute | null {
  if (!isRecord(value)) return null;
  if (typeof value.dst !== "string" || typeof value.via !== "string") return null;
  if (typeof value.dev !== "string" || typeof value.proto !== "string" || typeof value.table !== "string") return null;
  if (typeof value.handAdded !== "boolean") return null;
  const origin = value.origin === "automatic" || value.origin === "static" || value.origin === "unstated"
    ? value.origin
    : null;
  return {
    dst: value.dst,
    via: value.via,
    dev: value.dev,
    proto: value.proto,
    table: value.table,
    origin,
    handAdded: value.handAdded,
  };
}

function readRoutes(value: unknown): HostRoute[] | null {
  if (value === null || value === undefined) return null;
  if (!Array.isArray(value)) return null;
  const out: HostRoute[] = [];
  for (const item of value) {
    const row = readRoute(item);
    if (row) out.push(row);
  }
  return out;
}

function readIntrusions(value: unknown): HostIntrusion[] | null {
  if (value === null || value === undefined) return null;
  if (!Array.isArray(value)) return null;
  const out: HostIntrusion[] = [];
  for (const item of value) {
    const row = readIntrusion(item);
    if (row) out.push(row);
  }
  return out;
}

function readHost(value: unknown): SiteHost | null {
  if (!isRecord(value)) return null;
  if (typeof value.vpc !== "string" || typeof value.host !== "string") return null;
  if (typeof value.current !== "boolean" || typeof value.drifted !== "boolean") return null;
  return {
    vpc: value.vpc,
    host: value.host,
    state: typeof value.state === "string" ? value.state : null,
    generation: typeof value.generation === "string" ? value.generation : null,
    current: value.current,
    drifted: value.drifted,
    ageSec: typeof value.ageSec === "number" ? value.ageSec : null,
    stage: typeof value.stage === "string" ? value.stage : null,
    blockedBy: typeof value.blockedBy === "string" ? value.blockedBy : null,
    maintenance: typeof value.maintenance === "string" ? value.maintenance : null,
    contradictions: readContradictions(value.contradictions),
    workload: readWorkload(value.workload),
    unexpectedFilters: readStringListOrNull(value.unexpectedFilters),
    intrusions: readIntrusions(value.intrusions),
    publishedPorts: readStringListOrNull(value.publishedPorts),
    routes: readRoutes(value.routes),
  };
}

function readRelay(value: unknown): RelayResult | null {
  if (!isRecord(value) || typeof value.name !== "string" || typeof value.url !== "string") return null;
  if (value.ok === true) return { name: value.name, url: value.url, ok: true };
  if (value.ok === false && typeof value.error === "string") {
    return { name: value.name, url: value.url, ok: false, error: value.error };
  }
  return null;
}

export function readSiteView(data: unknown): SiteRead {
  if (!isRecord(data)) return { ok: false, reason: "site view is not an object" };
  if (typeof data.asked !== "number" || typeof data.reachable !== "number") {
    return { ok: false, reason: "site view is missing asked/reachable" };
  }
  if (!Array.isArray(data.vpcs) || !Array.isArray(data.hosts)) {
    return { ok: false, reason: "site view is missing vpcs/hosts" };
  }
  const vpcs: RelayResult[] = [];
  for (const row of data.vpcs) {
    const relay = readRelay(row);
    if (!relay) return { ok: false, reason: "a vpc row is malformed" };
    vpcs.push(relay);
  }
  const hosts: SiteHost[] = [];
  for (const row of data.hosts) {
    const host = readHost(row);
    if (!host) return { ok: false, reason: "a host row is malformed" };
    hosts.push(host);
  }
  const problems = Array.isArray(data.problems)
    ? data.problems.filter((item): item is string => typeof item === "string")
    : [];
  return { ok: true, site: { vpcs, hosts, problems, asked: data.asked, reachable: data.reachable } };
}
