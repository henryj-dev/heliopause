// The line between evaluating a policy and rendering it.
//
// `manager-policy-boundary.test.ts` pins that the manager has no dynamic import and still serves the
// console. That is a source-level check and it cannot tell whether the console shows the *same*
// policy it used to. This file is that half: the screen built from a site that crossed the wire must
// equal the screen built from the site itself, cell for cell.
//
// The equality is the point. A serialisation that drops a field does not throw — it produces a page
// that renders, looks right, and is missing a table. The catalogue tables in particular are built
// from lists that arrive from the site, and this repository has already shipped one screen whose
// empty `usedBy` column asserted the opposite of the truth about a live source list.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildScreen } from "./policy-screen.ts";
import {
  collectPolicySource,
  editableFiles,
  parsePolicySource,
  PolicySourceError,
  POLICY_SOURCE_SCHEMA,
  screenSiteOf,
  serviceRefs,
} from "./policy-source.ts";
import { policyPage } from "./policy-ui.ts";
import { DEFAULT_CONFIG } from "./config.ts";
import type { Policy } from "./policy.ts";

/**
 * A path with no repository under it, so the fallbacks inside `buildScreen` produce nothing.
 *
 * Absolute on purpose. A relative label resolves against the *test runner's* working directory, so
 * `sitePath: "test"` made `policyCommits` run `git log` in this repository and fill the history table
 * with heliopause's own commits — which made the assertion that history survived the wire pass
 * whether or not anything crossed it. Found by deleting the passthrough and watching nothing fail.
 */
const NO_CHECKOUT = "/nonexistent/policy/site.ts";

const policy = (over: Partial<Policy> = {}): Policy => ({
  id: "p1", name: "n", src: { kind: "cidr", value: "10.0.0.0/8" },
  dst: { kind: "host", value: "h" }, proto: "tcp", ports: "22",
  action: "allow", denyMode: "drop", priority: 100, enabled: true, ...over,
});

/**
 * A site that uses every field the wire has to carry.
 *
 * Deliberately not minimal. A fixture with only `cfg` and `hosts` would round-trip perfectly while
 * `objects`, `zones`, `devices` and `workload` were being dropped, and those are exactly the fields
 * that were added late and therefore the ones a serialiser forgets — this repository has lost a new
 * field in the last step of an aggregation four times.
 */
const fixture = () => ({
  cfg: { ...DEFAULT_CONFIG, hookPolicy: { input: "drop" as const, output: "accept" as const } },
  zones: [{ id: "z-trusted", name: "trusted", cidrs: ["10.254.0.0/16"], trust: 2 }],
  devices: [{ id: "d1", name: "laptop", user: "jang@example.com", v4: "10.254.0.5" }],
  objects: [{
    id: "ao-operators",
    kind: "address" as const,
    name: "operators",
    members: [{ kind: "cf-user" as const, value: "jang@example.com" }],
  }],
  coverage: [{
    id: "B2",
    title: "ssh is refused from outside",
    expect: "blocked" as const,
    targets: [{ host: "h1", addr4: "203.0.113.9", port: 22, proto: "tcp" as const }],
  }],
  hosts: [{
    id: "h1",
    stage: "canary" as const,
    items: [{
      policy: policy({ id: "HOST-RULE", src: { kind: "object", value: "ao-operators" } }),
      srcCidrs: ["10.254.0.5/32"],
      dstCidrs: ["10.0.0.1/32"],
    }],
  }],
  workload: [{ policy: policy({ id: "WORKLOAD-RULE", dst: { kind: "k8s-service", value: "app/api" } }) }],
  resolveService: (ref: string) => (ref === "app/api" ? { namespace: "app", labels: { app: "api" } } : null),
});

/** What the renderer would have found beside the module. Fixed, so the comparison is about the wire. */
const repo = {
  probes: [{
    checkId: "B2",
    family: "v4" as const,
    addr: "203.0.113.9",
    port: 22,
    outcome: "refused" as const,
    at: "2026-08-01T00:00:00Z",
    observedFrom: "probe-01",
    ms: 12,
  }],
  commits: [{ id: "abc1234", subject: "policy: add a rule", author: "jang", at: "2026-08-01T00:00:00Z" }],
  generation: "abc1234",
};

const crossTheWire = (site: ReturnType<typeof fixture>) => {
  const collected = collectPolicySource({
    site: site as never,
    // No such directory, so `collectPolicySource` finds no probes, no commits and no git head — the
    // three things the fixture supplies by hand below. That keeps this test about serialisation
    // rather than about whether the machine running it has a policy checkout.
    sitePath: "/nonexistent/policy/site.ts",
    label: "test",
    allowPaths: [],
  });
  // The actual crossing. `structuredClone` would preserve things JSON cannot, which is the mistake
  // this is checking for.
  return parsePolicySource(JSON.parse(JSON.stringify({ ...collected, repo })));
};

describe("a policy that crossed the wire renders identically", () => {
  it("produces the same screen, field for field", () => {
    const site = fixture();
    // One clock for both builds. `buildScreen` used to read the clock itself, and this comparison
    // failed roughly one run in three when a second boundary fell between the two calls — `ageSec`
    // came out one apart and the diff was a single digit nobody could place. The flake is the reason
    // `now` is injectable at all; what the test is about is the crossing, not the time of day.
    const now = "2026-08-16T12:00:00.000Z";
    const direct = buildScreen({ site: site as never, sitePath: NO_CHECKOUT, label: "test", repo, now });
    const viaWire = buildScreen({
      site: screenSiteOf(crossTheWire(site)),
      sitePath: NO_CHECKOUT,
      label: "test",
      repo,
      now,
    });
    assert.deepEqual(viaWire, direct);
  });

  it("is the clock that made this comparison flaky, and it is now the caller's", () => {
    // Proof rather than five green runs. The flake needed a second boundary between two builds, so
    // "it passed a few times" is weak evidence; this shows the mechanism directly. One second apart
    // must move the age, and the same instant must not — if the first assertion fails the injected
    // clock is being ignored and the fix is decoration.
    const site = fixture();
    const build = (now: string) => buildScreen({ site: site as never, sitePath: NO_CHECKOUT, label: "test", repo, now });
    const a = JSON.stringify(build("2026-08-16T12:00:00.000Z"));
    const b = JSON.stringify(build("2026-08-16T12:00:01.000Z"));
    assert.notEqual(a, b, "the injected clock does not reach the ages — the flake would survive this fix");
    assert.equal(a, JSON.stringify(build("2026-08-16T12:00:00.000Z")), "the same instant produced two different screens");
  });

  it("carries the tables that arrive last", () => {
    // Named individually as well as compared wholesale. `deepEqual` on the whole screen fails with a
    // diff nobody can read; these say which table went missing, and they are the tables that go
    // missing.
    const screen = buildScreen({
      site: screenSiteOf(crossTheWire(fixture())),
      sitePath: NO_CHECKOUT,
      label: "test",
      repo,
    });
    assert.deepEqual(screen.extra.objects?.map((o) => o.id), ["ao-operators"]);
    assert.deepEqual(screen.extra.objects?.[0]?.usedBy, ["HOST-RULE"]);
    assert.ok(screen.extra.zones?.length, "the zone table did not survive");
    assert.ok(screen.extra.devices?.rows.length, "the device table did not survive");
    assert.ok(screen.extra.workload?.length, "the workload table did not survive");
    // **Not `rows.length`.** The coverage table has one row per *check*, and the checks come from
    // the site — so the table is the same length whether or not a single probe arrived, and every
    // cell just reads "unknown". Asserting the length passed with the probes thrown away, which is
    // the exact failure this table is built to make visible: an unmeasured cell must not look like
    // a measured one. The verdict is what the probe decides.
    const b2 = screen.extra.coverage?.rows.find((r) => r.check.id === "B2");
    assert.ok(b2, "the coverage table did not survive");
    // The vantage point, not the verdict. `observedFrom` is copied off a probe that matched, so it
    // is present only when one did — whereas a verdict has a value either way, and asserting on it
    // means first agreeing with `verdictFor` about what `refused` means for a `blocked` check (it
    // is a fail: an RST is the host answering, which is not the same as a packet being dropped).
    // That is a different test than this one.
    assert.equal(b2.v4.observedFrom, "probe-01", "the probe did not reach the screen — the cell is unmeasured");
    assert.ok(screen.extra.history?.length, "the history table did not survive");
    assert.equal(screen.meta.generation, "abc1234");
  });

  it("rebuilds the one function as a lookup", () => {
    // `resolveService` cannot cross as itself. `null` and a selector are different answers and
    // `cilium.ts` renders them differently, so both directions are checked — a table that answered
    // for everything would be as wrong as one that answered for nothing.
    const resolve = screenSiteOf(crossTheWire(fixture())).resolveService as (r: string) => unknown;
    assert.deepEqual(resolve("app/api"), { namespace: "app", labels: { app: "api" } });
    assert.equal(resolve("app/absent"), null);
  });

  it("finds the references the resolver has to be asked about", () => {
    assert.deepEqual(serviceRefs(fixture() as never), ["10.0.0.0/8", "app/api"]);
  });
});

describe("the renderer's answer is untrusted input", () => {
  const wire = () => JSON.parse(JSON.stringify(collectPolicySource({
    site: fixture() as never, sitePath: "/nonexistent/site.ts", label: "test", allowPaths: [],
  }))) as Record<string, unknown>;

  const refuses = (mutate: (p: Record<string, unknown>) => void, why: RegExp) => {
    const payload = wire();
    mutate(payload);
    assert.throws(() => parsePolicySource(payload), (e: Error) => e instanceof PolicySourceError && why.test(e.message));
  };

  it("refuses a schema it does not speak", () => {
    refuses((p) => { p.schemaVersion = POLICY_SOURCE_SCHEMA + 1; }, /schema/);
  });

  it("carries the renderer's build across the wire", () => {
    // The whole point of the field: the manager holds this next to its own and can finally say
    // whether the process that evaluated the policy is the code it thinks it is.
    const p = parsePolicySource(wire());
    assert.match(String(p.build), /^[0-9a-f]{12}$/, "the renderer did not name its build");
  });

  it("accepts a renderer too old to name itself", () => {
    // 🔑 The compatibility that makes this shippable. Every renderer deployed today omits the field;
    // requiring it would refuse all of them at once in order to report that one is stale, which is a
    // worse outage than the one being reported. `ObservedRoute.origin` is absent from old agents for
    // exactly this reason and is handled the same way.
    const payload = wire();
    delete payload.build;
    const p = parsePolicySource(payload);
    assert.equal(p.build, undefined, "an absent build must stay absent rather than becoming a value");
  });

  it("refuses a build that is present and not a string", () => {
    // Absent is a fact; empty or wrongly typed is a renderer that answered the question badly, and
    // the console would print it straight into the banner.
    refuses((p) => { p.build = 7; }, /build must be a non-empty string/);
    refuses((p) => { p.build = ""; }, /build must be a non-empty string/);
  });

  it("refuses a site whose tables are not tables", () => {
    refuses((p) => { (p.site as Record<string, unknown>).hosts = "all of them"; }, /hosts must be an array/);
  });

  it("refuses a key that would write through to Object.prototype", () => {
    // `JSON.parse` defines own properties and is safe by itself; the values here get copied into
    // lookups downstream, which is where a key named `__proto__` stops being inert.
    refuses((p) => { p.services = JSON.parse('{"__proto__": {"namespace": "x"}}'); }, /__proto__/);
  });

  it("refuses a payload built in-process instead of sent", () => {
    // A function cannot survive JSON, so one arriving here means somebody wired the collector
    // straight into the renderer and skipped the wire — which is C1 with extra steps.
    refuses((p) => { (p.site as Record<string, unknown>).resolveService = () => null; }, /carries data only/);
  });

  it("escapes a policy that tries to be a script tag", () => {
    // The one that matters for the browser. This data came from a process that runs whatever is in
    // the policy repository, so a rule id is attacker-controlled text on an authenticated page.
    const site = fixture();
    site.hosts[0]!.items[0]!.policy.id = '</script><script>alert(1)</script>';
    site.hosts[0]!.items[0]!.policy.name = '"><img src=x onerror=alert(2)>';
    const screen = buildScreen({ site: screenSiteOf(crossTheWire(site)), sitePath: NO_CHECKOUT, label: "t", repo });
    const html = policyPage(screen.rows, screen.meta, screen.extra);
    // What is dangerous is a tag opening, not the words inside it. `onerror=alert(2)` survives
    // escaping *as text* — `=` and parentheses are not escaped and do not need to be — so asserting
    // on the payload string fails against correct output. Measured while writing this: the first
    // version of this test failed on a page whose markup was perfectly escaped.
    assert.ok(!html.includes("<script>alert(1)"), "an injected script tag reached the page");
    assert.ok(!html.includes("<img src=x"), "an injected element reached the page");
    // The known positive: the text is there, escaped, rather than the two assertions above passing
    // because the row was dropped and there was nothing on the page to escape.
    assert.ok(html.includes("&lt;/script&gt;"), "the id did not reach the page at all — this test proves nothing");
    assert.ok(html.includes("&lt;img src=x"), "the name did not reach the page at all");
  });
});

// Which editable files reach the page.
//
// **The defect this pins was an absence.** `HELIOPAUSE_POLICY_EDITABLE` has named two files since the
// console learned to write, `/policy/edit` accepted either the whole time, and the page carried
// `allowPaths[0]` — so `dev.ts`, which is where a device approval or a new zone is written, was
// configured as editable and could not be edited from the console. Nothing errored, nothing logged,
// and no test failed: the seventh time this repository has found something built and never called.
describe("every editable file reaches the console, not just the first", () => {
  const two = { "policies.json": "{}", "dev.ts": "export const site = {};" };

  it("offers the second configured file — the known positive is that it is offered at all", () => {
    const { primary, more } = editableFiles(["policies.json", "dev.ts"], two);
    assert.equal(primary?.path, "policies.json");
    assert.deepEqual(more.map((f) => f.path), ["dev.ts"]);
  });

  it("gives the rule table the JSON document wherever it sits in the list", () => {
    // Order in `allowPaths` is a configuration detail. If it decided which editor an operator gets,
    // swapping two environment values would silently replace the rule table with a text box.
    const { primary, more } = editableFiles(["dev.ts", "policies.json"], two);
    assert.equal(primary?.path, "policies.json");
    assert.deepEqual(more.map((f) => f.path), ["dev.ts"]);
  });

  it("drops a path the renderer could not read rather than offering it empty", () => {
    // An editor over an empty string has a save button that would commit nothing over the real file.
    const { primary, more } = editableFiles(["policies.json", "dev.ts"], { "policies.json": "{}" });
    assert.equal(primary?.path, "policies.json");
    assert.deepEqual(more, []);
  });

  it("offers nothing when nothing is readable, rather than an editor with no content", () => {
    assert.deepEqual(editableFiles(["policies.json"], {}), { primary: null, more: [] });
  });

  it("still edits when the only readable file is not JSON", () => {
    // No rule table to give, but the file section is a working editor, and the alternative is a
    // read-only page for a file the write route would have accepted.
    const { primary, more } = editableFiles(["policies.json", "dev.ts"], { "dev.ts": "x" });
    assert.equal(primary?.path, "dev.ts");
    assert.deepEqual(more, []);
  });
});
