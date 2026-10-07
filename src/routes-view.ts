// `GET /routes`: each host's declared routes against what its kernel holds — per site.
//
// Pure. The manager reads one policy source per relay and polls the relays; this decides what they
// add up to. Kept out of the handler because the cases worth testing are the partial ones — one
// site's policy unreadable, the same host id declared by two sites — and those are data here.
//
// ## Each host is compared with its own site's declarations, and only those
//
// This used to read one site (the first relay) and compare every host in the fleet against it, so
// a host in any other VPC came back `rows: null` — "not in the model" — while its own site declared
// it (#132: az01's gw-01 declared two provisioning routes, the kernel held both, and this screen said
// neither existed). A host's declarations come from the site its relay serves; a host id another site
// happens to declare is not a declaration of this host.
//
// ## A site that could not be read is not a site with no model
//
// `rows: null` means "this host's site does not describe its routing". If an unreadable site also
// produced `null`, an outage at the renderer would read as a fleet nobody had described, which is
// the reassuring answer. So such a host carries `declarationError`, and the site's own entry in
// `sites` says why.

import { compareRoutes, readyToApply, type RouteComparison, type RouteDecl } from "./routes.ts";
import { screenSiteOf, type PolicySource } from "./policy-source.ts";
import type { SiteView } from "./manager.ts";

/** One relay's site, as the renderer answered for it. */
export type SiteSourceRead =
  | { site: string; ok: true; source: PolicySource }
  | { site: string; ok: false; error: string };

export interface RoutesSite {
  site: string;
  generation: string | null;
  dirty: boolean;
  /** Why this site's declarations could not be read. `null` when they were. */
  error: string | null;
}

export type RoutesHost = RouteComparison & {
  vpc: string;
  host: string;
  appliable: number;
  /**
   * Why this host's declarations are unknown, when its site could not be read. `null` otherwise.
   * With an error `rows` is `null` too, and does **not** mean "not in the model".
   */
  declarationError: string | null;
};

export interface RoutesView {
  /**
   * The first readable site's commit, in relay order — kept for the console that predates `sites`.
   * Every site is rendered from one policy repository, so they agree unless the renderer is mid-sync;
   * when they do not, `sites` is where the difference shows.
   */
  generation: string | null;
  dirty: boolean;
  sites: RoutesSite[];
  hosts: RoutesHost[];
}

function declaredByHost(source: PolicySource): Map<string, readonly RouteDecl[] | undefined> {
  const out = new Map<string, readonly RouteDecl[] | undefined>();
  const hosts = (screenSiteOf(source) as unknown as { hosts?: readonly { id: string; routes?: readonly RouteDecl[] }[] }).hosts ?? [];
  for (const h of hosts) out.set(h.id, h.routes);
  return out;
}

/**
 * Join per-site declarations with the fleet. `reads` is one entry per relay, in relay order.
 *
 * A host whose VPC has no entry in `reads` at all is reported the same way as an unreadable site —
 * its declarations were not looked at, and saying "no model" would claim they were.
 */
export function routesView(reads: readonly SiteSourceRead[], fleet: SiteView): RoutesView {
  const bySite = new Map<string, { declared: Map<string, readonly RouteDecl[] | undefined> } | { error: string }>();
  for (const r of reads) bySite.set(r.site, r.ok ? { declared: declaredByHost(r.source) } : { error: r.error });

  const firstOk = reads.find((r): r is Extract<SiteSourceRead, { ok: true }> => r.ok);
  return {
    generation: firstOk?.source.head.sha ?? null,
    dirty: firstOk?.source.head.dirty ?? false,
    sites: reads.map((r) => r.ok
      ? { site: r.site, generation: r.source.head.sha, dirty: r.source.head.dirty, error: null }
      : { site: r.site, generation: null, dirty: false, error: r.error }),
    hosts: fleet.hosts.map((h) => {
      const site = bySite.get(h.vpc) ?? { error: `no declarations were read for ${h.vpc}` };
      if ("error" in site) {
        return {
          vpc: h.vpc, host: h.host, rows: null, missing: 0, undeclared: 0, unstated: 0,
          appliable: 0, declarationError: site.error,
        };
      }
      const declared = site.declared.get(h.host);
      return {
        vpc: h.vpc,
        host: h.host,
        // `compareRoutes` keeps "in the model with no routes key" as `rows: null` and `routes: []`
        // as an empty declaration — the distinction `policy/dev-routes.test.ts` asserts.
        ...compareRoutes(declared, h.routes),
        appliable: readyToApply(declared),
        declarationError: null,
      };
    }),
  };
}
