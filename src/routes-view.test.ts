import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkedRead, routesView, type SiteSourceRead } from "./routes-view.ts";
import { collectPolicySource, parsePolicySource, type PolicySource } from "./policy-source.ts";
import { defineConfig } from "./config.ts";
import type { SiteView } from "./manager.ts";
import type { RouteDecl } from "./routes.ts";

/**
 * A policy source as the manager receives it — collected, serialised and parsed back — for a site
 * whose hosts declare the given routes (`undefined` = no `routes` key at all).
 */
function source(hosts: Record<string, readonly RouteDecl[] | undefined>, sha = "a".repeat(40)): PolicySource {
  const site = {
    cfg: defineConfig({ baseline: [] }),
    hosts: Object.entries(hosts).map(([id, routes]) => ({
      id, stage: "canary" as const, items: [], ...(routes === undefined ? {} : { routes }),
    })),
  };
  const collected = collectPolicySource({ site: site as never, sitePath: "/nonexistent/site.ts", label: "test", allowPaths: [] });
  return parsePolicySource(JSON.parse(JSON.stringify({
    ...collected,
    head: { sha, dirty: false },
    repo: { probes: [], commits: [], generation: sha.slice(0, 7) },
  })));
}

const route = (dst: string, owner: RouteDecl["owner"] = "provisioning"): RouteDecl =>
  ({ dst, dev: "eth1", owner, note: "" } as RouteDecl);

const kernel = (dst: string) => ({ dst, via: "", dev: "eth1", proto: "static", table: "main" });

/** The fleet: hosts per VPC, each with the routes its kernel reports. */
function fleet(hosts: Array<{ vpc: string; host: string; routes: ReturnType<typeof kernel>[] }>): SiteView {
  return { hosts: hosts.map((h) => ({ ...h })), vpcs: [], problems: [], generations: [], reachable: 0, asked: 0 } as unknown as SiteView;
}

const ok = (site: string, s: PolicySource): SiteSourceRead => ({ site, ok: true, source: s });

describe("routesView", () => {
  it("compares each host with its own site's declarations — the second site is not null any more", () => {
    // #132: az01's gw-01 declared two routes the kernel held, and the screen said `rows: null`
    // because only the first relay's site was read.
    const v = routesView(
      [ok("dev", source({ "gw-01.dev": [route("10.17.0.0/16")] })),
        ok("az01", source({ "gw-01.az01": [route("192.168.10.0/24"), route("192.168.20.0/24")] }))],
      fleet([
        { vpc: "dev", host: "gw-01.dev", routes: [kernel("10.17.0.0/16")] },
        { vpc: "az01", host: "gw-01.az01", routes: [kernel("192.168.10.0/24"), kernel("192.168.20.0/24")] },
      ]),
    );
    const az = v.hosts.find((h) => h.host === "gw-01.az01")!;
    assert.deepEqual(az.rows?.map((r) => [r.dst, r.verdict]), [["192.168.10.0/24", "ok"], ["192.168.20.0/24", "ok"]]);
    assert.equal(az.declarationError, null);
    assert.deepEqual(v.hosts.find((h) => h.host === "gw-01.dev")!.rows?.map((r) => r.verdict), ["ok"]);
  });

  it("does not compare a host with another site's declaration of the same id", () => {
    // Host ids repeat across VPCs by design. dev declaring `gw-01` must not describe az01's `gw-01`.
    const v = routesView(
      [ok("dev", source({ "gw-01": [route("10.17.0.0/16")] })), ok("az01", source({ "gw-01": undefined }))],
      fleet([{ vpc: "az01", host: "gw-01", routes: [kernel("10.17.0.0/16")] }]),
    );
    assert.equal(v.hosts[0]!.rows, null, "az01's gw-01 was compared with dev's declaration");
    assert.equal(v.hosts[0]!.declarationError, null);
  });

  it("keeps a host its site does not describe as rows: null, with no error", () => {
    const v = routesView([ok("dev", source({ "k3s-01.dev": undefined }))], fleet([{ vpc: "dev", host: "k3s-01.dev", routes: [] }]));
    assert.equal(v.hosts[0]!.rows, null);
    assert.equal(v.hosts[0]!.declarationError, null);
  });

  it("marks the hosts of an unreadable site with the reason, and leaves the other sites whole", () => {
    const v = routesView(
      [ok("dev", source({ "gw-01.dev": [route("10.17.0.0/16")] })), { site: "prod", ok: false, error: "the renderer returned 503" }],
      fleet([
        { vpc: "dev", host: "gw-01.dev", routes: [kernel("10.17.0.0/16")] },
        { vpc: "prod", host: "gw-01.prod", routes: [kernel("10.16.0.0/16")] },
      ]),
    );
    const prod = v.hosts.find((h) => h.vpc === "prod")!;
    assert.equal(prod.rows, null);
    assert.equal(prod.declarationError, "the renderer returned 503");
    assert.equal(v.hosts.find((h) => h.vpc === "dev")!.rows?.[0]?.verdict, "ok");
    assert.deepEqual(v.sites.map((s) => [s.site, s.error]), [["dev", null], ["prod", "the renderer returned 503"]]);
  });

  it("does not read a VPC with no site entry as one with no model", () => {
    const v = routesView([ok("dev", source({}))], fleet([{ vpc: "util", host: "gw-01.util", routes: [] }]));
    assert.match(v.hosts[0]!.declarationError ?? "", /no declarations were read for util/);
  });

  it("reports each site's generation, and the first readable one at the top", () => {
    // The renderer serves every site from one repository, so the sites normally agree. Mid-sync they
    // may not, and the top-level value then names only the first — `sites` is where the console
    // reads the difference.
    const v = routesView(
      [{ site: "dev", ok: false, error: "down" }, ok("prod", source({}, "b".repeat(40))), ok("util", source({}, "c".repeat(40)))],
      fleet([]),
    );
    assert.equal(v.generation, "b".repeat(40));
    assert.deepEqual(v.sites.map((s) => [s.site, s.generation]), [["dev", null], ["prod", "b".repeat(40)], ["util", "c".repeat(40)]]);
  });
});

describe("checkedRead", () => {
  const named = (name: string | undefined) => ({ ...source({}), ...(name === undefined ? {} : { siteName: name }) }) as PolicySource;

  it("refuses an answer for a different site than the one asked for", () => {
    const r = checkedRead("az01", 1, named("dev"));
    assert.equal(r.ok, false);
    assert.match(!r.ok ? r.error : "", /asked the renderer for az01 and it served dev/);
  });

  it("accepts an unnamed answer for the first relay only — a single-site renderer serves one site to everyone", () => {
    assert.equal(checkedRead("dev", 0, named(undefined)).ok, true);
    const second = checkedRead("az01", 1, named(undefined));
    assert.equal(second.ok, false);
    assert.match(!second.ok ? second.error : "", /did not say which site it served/);
  });

  it("accepts the site it asked for", () => {
    assert.equal(checkedRead("prod", 2, named("prod")).ok, true);
  });
});
