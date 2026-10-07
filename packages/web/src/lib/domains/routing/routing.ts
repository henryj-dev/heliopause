// GET /api/routes, as this package is allowed to see it.
//
// Duplicated rather than imported from `heliopause`: the web package must not
// pull the library into a Vite bundle. `rows === null` means this host has no
// model — that is not an empty declaration, and must not render as "undeclared".

export type RouteVerdict = "ok" | "missing" | "undeclared" | "unstated" | "automatic";

export interface RouteRow {
  dst: string;
  via: string;
  dev: string;
  table: string;
  verdict: RouteVerdict;
  owner: string;
  origin: string;
  note: string;
}

export interface RoutingHost {
  vpc: string;
  host: string;
  /**
   * `null` when this host is not in the routing model — or, when `declarationError` is set, when its
   * site's declarations could not be read. Not the same as `[]`.
   */
  rows: RouteRow[] | null;
  /** Why this host's declarations are unknown. `null` when its site was read (and from an older manager). */
  declarationError: string | null;
  missing: number;
  undeclared: number;
  unstated: number;
}

/** One relay's site, as the manager read its declarations. */
export interface RoutingSite {
  site: string;
  generation: string | null;
  dirty: boolean;
  error: string | null;
}

export interface RoutingView {
  generation: string | null;
  dirty: boolean;
  /** `[]` from a manager that predates per-site reading. */
  sites: RoutingSite[];
  hosts: RoutingHost[];
}

export type RoutingRead =
  | { ok: true; view: RoutingView }
  | { ok: false; reason: string };

const VERDICTS = new Set<RouteVerdict>(["ok", "missing", "undeclared", "unstated", "automatic"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readRow(value: unknown): RouteRow | null {
  if (!isRecord(value) || typeof value.dst !== "string" || typeof value.table !== "string") return null;
  if (typeof value.verdict !== "string" || !VERDICTS.has(value.verdict as RouteVerdict)) return null;
  return {
    dst: value.dst,
    via: typeof value.via === "string" ? value.via : "",
    dev: typeof value.dev === "string" ? value.dev : "",
    table: value.table,
    verdict: value.verdict as RouteVerdict,
    owner: typeof value.owner === "string" ? value.owner : "",
    origin: typeof value.origin === "string" ? value.origin : "",
    note: typeof value.note === "string" ? value.note : "",
  };
}

function readHost(value: unknown): RoutingHost | null {
  if (!isRecord(value) || typeof value.vpc !== "string" || typeof value.host !== "string") return null;
  const declarationError = typeof value.declarationError === "string" ? value.declarationError : null;
  if (value.rows === null) {
    return {
      vpc: value.vpc,
      host: value.host,
      rows: null,
      declarationError,
      missing: typeof value.missing === "number" ? value.missing : 0,
      undeclared: typeof value.undeclared === "number" ? value.undeclared : 0,
      unstated: typeof value.unstated === "number" ? value.unstated : 0,
    };
  }
  if (!Array.isArray(value.rows)) return null;
  const rows: RouteRow[] = [];
  for (const item of value.rows) {
    const row = readRow(item);
    if (!row) return null;
    rows.push(row);
  }
  return {
    vpc: value.vpc,
    host: value.host,
    rows,
    declarationError,
    missing: typeof value.missing === "number" ? value.missing : 0,
    undeclared: typeof value.undeclared === "number" ? value.undeclared : 0,
    unstated: typeof value.unstated === "number" ? value.unstated : 0,
  };
}

export function readRoutingView(data: unknown): RoutingRead {
  if (!isRecord(data)) return { ok: false, reason: "routing view is not an object" };
  if (!Array.isArray(data.hosts)) return { ok: false, reason: "routing view is missing hosts" };
  const hosts: RoutingHost[] = [];
  for (const row of data.hosts) {
    const host = readHost(row);
    if (!host) return { ok: false, reason: "a routing host is malformed" };
    hosts.push(host);
  }
  const sites: RoutingSite[] = [];
  for (const s of Array.isArray(data.sites) ? data.sites : []) {
    if (!isRecord(s) || typeof s.site !== "string") return { ok: false, reason: "a routing site is malformed" };
    sites.push({
      site: s.site,
      generation: typeof s.generation === "string" ? s.generation : null,
      dirty: s.dirty === true,
      error: typeof s.error === "string" ? s.error : null,
    });
  }
  return {
    ok: true,
    view: {
      generation: typeof data.generation === "string" ? data.generation : null,
      dirty: data.dirty === true,
      sites,
      hosts,
    },
  };
}

/**
 * The commits the sites were read at, when they are not all one — mid-sync, the top-level
 * `generation` names only the first readable site. Empty when they agree or when unknown.
 */
export function siteGenerationSplit(view: RoutingView): RoutingSite[] {
  const read = view.sites.filter((s) => s.generation !== null);
  return new Set(read.map((s) => s.generation)).size > 1 ? read : [];
}

export function hostIsClean(host: RoutingHost): boolean {
  return host.rows !== null && host.missing === 0 && host.undeclared === 0 && host.unstated === 0;
}

export function routingListing(view: RoutingView): "empty" | "hosts" {
  return view.hosts.length === 0 ? "empty" : "hosts";
}
