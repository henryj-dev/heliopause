// The process that runs the policy author's code, started for real.
//
// ## Why this is not a source-level test
//
// `manager-policy-boundary.test.ts` used to assert that `refuseIfArmed()` appeared in the renderer's
// source. Deleting the *call* did not fail it — the regex matched the `function refuseIfArmed():
// void` declaration two hundred lines above, because `refuseIfArmed()` is a substring of
// `refuseIfArmed(): void`. Found by injecting exactly that defect; the same class of miss has now
// happened three times in this repository, twice through a name surviving in a comment.
//
// So the guard is exercised by starting the process. There is no way to write a test that passes
// while the check does not run.
//
// ## What is being guarded
//
// This is the only process in the system that evaluates the policy repository, which is audit
// finding C1's containment: a hostile commit runs *here*, where there is no signing key, no GitHub
// App key, no OIDC secret and no service account token. "There is nothing here" is a property of the
// deployment rather than of the code — a manifest that copies the manager's `envFrom` by habit, or
// forgets `automountServiceAccountToken: false`, produces a renderer that looks identical from the
// outside and has moved C1 rather than fixed it. Refusing to start is the only outcome that cannot
// be missed.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parsePolicySource } from "./policy-source.ts";

const BIN = fileURLToPath(new URL("../bin/heliopause-policy-render.ts", import.meta.url));

/**
 * A checkout laid out the way the image lays it out.
 *
 * `<root>/policy/site.ts` beside `<root>/src`, because a site module imports the model with
 * `../src` and the renderer refuses to start where that would not resolve. A flat fixture with the
 * module at the root passed for as long as the renderer did not check, and the deployment that
 * mounted the checkout at `/policy` — the same mistake — answered 503 on every request.
 */
function checkout(): string {
  const root = mkdtempSync(join(tmpdir(), "hp-policy-"));
  mkdirSync(join(root, "src"));
  const dir = join(root, "policy");
  mkdirSync(dir);
  writeFileSync(join(dir, "policies.json"), '{\n  "schemaVersion": 1,\n  "groups": []\n}\n');
  writeFileSync(
    join(dir, "site.ts"),
    `export const site = {
       cfg: { hookPolicy: { input: "drop", output: "accept" } },
       hosts: [{ id: "h1", stage: "canary", items: [] }],
       objects: [{ id: "ao-x", kind: "address", name: "x", members: [{ kind: "cidr", value: "10.0.0.0/8" }] }],
     };\n`,
  );
  return dir;
}

interface Started {
  proc: ChildProcessByStdio<null, Readable, Readable>;
  port: number;
  stop: () => void;
}

/** Start the renderer and wait for the line that reports the port it actually bound. */
/** The bearer every `start()` above configures. Named once so the two cannot drift. */
const BEARER = "test-bearer";

/**
 * `GET /source` with the token, which is now the only way in.
 *
 * The tests below are about what the renderer *serves*; carrying the header at each call site would
 * put an authentication detail into every one of them, and the one test that is genuinely about the
 * bearer builds its own request.
 */
const fetchSource = (port: number, init: RequestInit = {}) =>
  fetch(`http://127.0.0.1:${port}/source`, {
    ...init,
    headers: { authorization: `Bearer ${BEARER}`, ...(init.headers ?? {}) },
  });

function start(dir: string, extraEnv: Record<string, string> = {}): Promise<Started> {
  const proc = spawn(process.execPath, [BIN], {
    env: {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      HELIOPAUSE_POLICY_SITE: join(dir, "site.ts"),
      HELIOPAUSE_POLICY_LABEL: "test-site",
      HELIOPAUSE_POLICY_ALLOW_PATHS: "policies.json",
      // 0, so two of these can run at once and neither waits on a fixed port somebody else holds.
      HELIOPAUSE_POLICY_RENDER_PORT: "0",
      HELIOPAUSE_POLICY_RENDER_HOST: "127.0.0.1",
      // Required since 2026-08-22. It used to default to empty, and `bearerOk` returned true on an
      // empty token — so the default deployment served the whole policy to anyone who could reach
      // the port. Every start here has to carry one now, which is also what makes the refusal below
      // a real negative rather than the fixture being incomplete.
      HELIOPAUSE_POLICY_RENDER_TOKEN: "test-bearer",
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  // **Both pipes get drained.** A child whose stderr fills its 64 kB buffer blocks on the write and
  // never reaches the next line, and the parent then waits on a process that is waiting on the
  // parent. A run of this file hung for fourteen minutes that way, with `--test-timeout=0` meaning
  // nothing ever cut it off. Listening on stdout alone is the bug; the assertions were fine.
  let err = "";
  proc.stderr.on("data", (b: Buffer) => { err += b.toString(); });
  return new Promise((resolve, reject) => {
    const give = (e: Error) => {
      proc.kill("SIGKILL");
      reject(new Error(`${e.message}${err ? `\n${err}` : ""}`));
    };
    const fail = setTimeout(() => give(new Error("the renderer never reported a port")), 15_000);
    let out = "";
    proc.stdout.on("data", (b: Buffer) => {
      out += b.toString();
      const m = /listening on [^:]+:(\d+)/.exec(out);
      if (!m) return;
      clearTimeout(fail);
      resolve({
        proc,
        port: Number(m[1]),
        stop: () => proc.kill("SIGKILL"),
      });
    });
    proc.on("exit", (code) => {
      clearTimeout(fail);
      // Not `give` — it is already gone, and killing a reaped pid is how a test starts reporting
      // ESRCH instead of the reason the process died.
      reject(new Error(`the renderer exited with ${code} before listening${err ? `\n${err}` : ""}`));
    });
  });
}

/** Start it expecting it not to start, and hand back what it said on the way out. */
function startExpectingRefusal(dir: string, extraEnv: Record<string, string>): Promise<{ code: number; err: string }> {
  const proc = spawn(process.execPath, [BIN], {
    env: {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      HELIOPAUSE_POLICY_SITE: join(dir, "site.ts"),
      HELIOPAUSE_POLICY_RENDER_PORT: "0",
      HELIOPAUSE_POLICY_RENDER_HOST: "127.0.0.1",
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  return new Promise((resolve) => {
    let err = "";
    proc.stderr.on("data", (b: Buffer) => { err += b.toString(); });
    // Drained and discarded. Same reason as in `start()`: an undrained pipe stops the child, and a
    // stopped child never exits, and this promise only settles on exit.
    proc.stdout.resume();
    // **The timeout is the point of this function, not a safety net.** Without it, the one outcome
    // this test exists to catch — the renderer starting when it should have refused — makes the
    // promise wait on an exit that never comes. Measured: deleting the `refuseIfArmed()` call hung
    // the run for twenty-six minutes and left an orphaned renderer holding the runner's pipe open,
    // so `--test-timeout` did not end it either. A test that hangs on the defect reports nothing.
    const gaveUp = setTimeout(() => {
      proc.kill("SIGKILL");
      resolve({ code: 0, err: `${err}\n(it was still running after 10s — it did not refuse)` });
    }, 10_000);
    proc.on("exit", (code) => {
      clearTimeout(gaveUp);
      resolve({ code: code ?? -1, err });
    });
  });
}

describe("the renderer refuses to start holding a credential", () => {
  it("exits on a credential-shaped environment variable", async () => {
    const dir = checkout();
    try {
      const { code, err } = await startExpectingRefusal(dir, {
        HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE: "/etc/heliopause/signing.key",
      });
      assert.equal(code, 2, "the renderer started while holding the artifact signing key");
      assert.match(err, /HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE/, "it did not say which one");
      // Names, never values. This message goes to a container log that is not as private as the
      // secret it is complaining about.
      assert.ok(!err.includes("/etc/heliopause/signing.key"), "the refusal printed the value");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("still starts holding the bearer that authenticates its caller", async () => {
    // The one exception, and it needs a test of its own: a check that refused every variable with
    // TOKEN in the name would make the renderer unable to hold the credential that protects it,
    // and the fix an operator would reach for is deleting the check.
    const dir = checkout();
    let started: Started | undefined;
    try {
      started = await start(dir, { HELIOPAUSE_POLICY_RENDER_TOKEN: "s3cret" });
      // A different token from the fixture's, so a wrong bearer is refused rather than merely an
      // absent one — those are different failures and only one of them was ever tested.
      const res = await fetch(`http://127.0.0.1:${started.port}/source`, {
        headers: { authorization: `Bearer ${BEARER}` },
      });
      assert.equal(res.status, 401, "the bearer was configured and not enforced");
      const none = await fetch(`http://127.0.0.1:${started.port}/source`);
      assert.equal(none.status, 401, "a request with no bearer at all was served");
      const ok = await fetch(`http://127.0.0.1:${started.port}/source`, {
        headers: { authorization: "Bearer s3cret" },
      });
      assert.equal(ok.status, 200);
    } finally {
      started?.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("the renderer refuses a checkout mounted where its imports do not resolve", () => {
  it("exits rather than answering 503 on every request", async () => {
    // The failure this replaces: the first deployment mounted the checkout at `/policy`, so
    // `dev.ts`'s `import "../src/…"` reached for `/src` — not in the image. The pod came up
    // healthy, passed its probes, and returned a module-resolution error naming a path that
    // appears in no manifest, once per request, forever.
    //
    // The mount is decided when the pod is written and is knowable before anything is cloned, so
    // the right time to refuse is startup. `../src` is *this image's* directory, not the policy
    // repository's — there is nothing to wait for.
    const root = mkdtempSync(join(tmpdir(), "hp-policy-flat-"));
    try {
      // Flat: the module at the root, with no `src` one level up. This is what `/policy/dev.ts`
      // looks like from inside the container.
      writeFileSync(join(root, "site.ts"), "export const site = { cfg: {}, hosts: [] };\n");
      const { code, err } = await startExpectingRefusal(root, {
        HELIOPAUSE_POLICY_SITE: join(root, "site.ts"),
      });
      assert.equal(code, 2, "the renderer started on a checkout whose imports cannot resolve");
      assert.match(err, /imports do not resolve/);
      // It has to say where to put it. "Wrong path" without the right one sends the reader to the
      // module system instead of to the manifest.
      assert.match(err, /\/opt\/heliopause\/policy/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("the renderer answers with a policy the manager can parse", () => {
  it("serves a payload that survives the manager's validation", async () => {
    const dir = checkout();
    let started: Started | undefined;
    try {
      started = await start(dir);
      const res = await fetchSource(started.port);
      assert.equal(res.status, 200);
      // Parsed with the manager's own function rather than by hand: the two processes agree or this
      // fails, which is the only property that matters about a wire format with one producer and one
      // consumer.
      const source = parsePolicySource(await res.json());
      assert.equal(source.label, "test-site");
      assert.deepEqual((source.site as { objects?: { id: string }[] }).objects?.map((o) => o.id), ["ao-x"]);
      // The editable file travelled. Without it the console renders read-only, which is a working
      // page that quietly cannot save.
      assert.match(source.files["policies.json"] ?? "", /"schemaVersion": 1/);
    } finally {
      started?.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("sees an edit to the policy file when the site module has not been touched", async () => {
    // The defect this exists for, in production for eleven hours on 2026-08-16: the cache was keyed
    // on the site module's mtime alone, on the stated assumption that "mtime is what git-sync
    // changes when it lands a new commit". `git reset --hard` rewrites only files whose content
    // changed, and two commits that day touched `policies.json` and nothing else — so the key never
    // moved and the console served the checkout as it stood when the pod started. The approver read
    // pre-narrowing rules on the screen where they approved the narrowing.
    //
    // The fixture reproduces exactly that shape: change the editable file, leave the module alone.
    // Its mtime is pinned rather than merely untouched, because a test that writes both files in the
    // same second can pass on a filesystem with coarse mtime granularity while the bug is present.
    const dir = checkout();
    let started: Started | undefined;
    try {
      // A whole-second timestamp, set before the first request and restored after the write. It has
      // to be pinned on both sides and it has to be an integer: `utimesSync` stores whole
      // milliseconds, so restoring a captured `mtimeMs` of `…950.635` yields `…951` and the old
      // mtime-only key would move on its own — the test would pass without the fix, on rounding.
      const pinned = 1_700_000_000;
      const site = join(dir, "site.ts");
      utimesSync(site, pinned, pinned);
      started = await start(dir);
      const before = statSync(site).mtimeMs;
      const first = parsePolicySource(await (await fetchSource(started.port)).json());
      assert.match(first.files["policies.json"] ?? "", /"groups": \[\]/);

      writeFileSync(join(dir, "policies.json"), '{\n  "schemaVersion": 1,\n  "groups": ["after"]\n}\n');
      utimesSync(site, pinned, pinned);
      assert.equal(statSync(site).mtimeMs, before, "the fixture must not move the module");

      const second = parsePolicySource(await (await fetchSource(started.port)).json());
      assert.match(
        second.files["policies.json"] ?? "",
        /"after"/,
        "the console served a policy file the checkout no longer has",
      );
    } finally {
      started?.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reports a broken policy module instead of serving a stale one", async () => {
    // A cache that keeps the last policy that evaluated is a screen that lies about what is
    // deployed, and it lies most convincingly right after somebody breaks the policy.
    const dir = checkout();
    let started: Started | undefined;
    try {
      started = await start(dir);
      assert.equal((await fetchSource(started.port)).status, 200);
      writeFileSync(join(dir, "site.ts"), "throw new Error('the policy does not load');\n");
      const res = await fetchSource(started.port);
      assert.equal(res.status, 503, "a broken policy module was served from cache");
      assert.match(String(((await res.json()) as { error?: string }).error), /the policy does not load/);
    } finally {
      started?.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/**
 * Two site modules in one checkout, each naming its own zone in its host ids.
 *
 * `alpha`/`beta` rather than real zone names on purpose: the leak scanner cannot tell a comment from
 * a site record, and it should not have to.
 */
function twoSites(): { dir: string; sites: string; alpha: string; beta: string } {
  const root = mkdtempSync(join(tmpdir(), "hp-policy-multi-"));
  mkdirSync(join(root, "src"));
  const dir = join(root, "policy");
  mkdirSync(dir);
  writeFileSync(join(dir, "policies.json"), '{\n  "schemaVersion": 1,\n  "groups": []\n}\n');
  const body = (zone: string, extra = "") =>
    `export const site = {
       cfg: { hookPolicy: { input: "drop", output: "accept" } },
       hosts: [{ id: "gw-01.${zone}", stage: "canary", items: [] }],
       objects: [{ id: "ao-${zone}", kind: "address", name: "${zone}${extra}",
                   members: [{ kind: "cidr", value: "10.0.0.0/8" }] }],
     };\n`;
  const alpha = join(dir, "alpha.ts");
  const beta = join(dir, "beta.ts");
  writeFileSync(alpha, body("alpha"));
  writeFileSync(beta, body("beta"));
  return { dir, sites: `alpha=${alpha},beta=${beta}`, alpha, beta };
}

/** `start()` pins `HELIOPAUSE_POLICY_SITE`; multi-site runs have to clear it. Empty reads as unset. */
const MULTI = (sites: string) => ({ HELIOPAUSE_POLICY_SITE: "", HELIOPAUSE_POLICY_SITES: sites });

const fetchAt = (port: number, path: string, init: RequestInit = {}) =>
  fetch(`http://127.0.0.1:${port}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${BEARER}`, ...(init.headers ?? {}) },
  });

describe("the renderer serves every site it was given", () => {
  it("answers each name with its own policy", async () => {
    // Both directions in one test. A renderer that ignored `?site=` and always served the first
    // module would pass a one-site assertion, and that is precisely the defect: on 2026-09-28 the
    // console asked for three VPCs and got one site's hosts three times.
    const { dir, sites } = twoSites();
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const a = parsePolicySource(await (await fetchAt(started.port, "/source?site=alpha")).json());
      const b = parsePolicySource(await (await fetchAt(started.port, "/source?site=beta")).json());
      assert.equal(a.site.hosts?.[0]?.id, "gw-01.alpha");
      assert.equal(b.site.hosts?.[0]?.id, "gw-01.beta");
      // The name travels, so the manager can say whether it got what it asked for.
      assert.equal(a.siteName, "alpha");
      assert.equal(b.siteName, "beta");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("lists what it holds, behind the same bearer as the policy itself", async () => {
    const { dir, sites } = twoSites();
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const listed = (await (await fetchAt(started.port, "/sites")).json()) as { sites?: { name: string }[] };
      assert.deepEqual(listed.sites?.map((s) => s.name), ["alpha", "beta"]);
      // Site names are zone names — the same class of fact the payload carries, so the same gate.
      const bare = await fetch(`http://127.0.0.1:${started.port}/sites`);
      assert.equal(bare.status, 401, "the site list answered without a bearer");
      const wrong = await fetchAt(started.port, "/sites", { headers: { authorization: "Bearer nope" } });
      assert.equal(wrong.status, 401, "the site list answered a wrong bearer");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("refuses a name it does not serve rather than falling back to one it does", async () => {
    // A fallback here is the incident with a typo in place of a manifest.
    const { dir, sites } = twoSites();
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const res = await fetchAt(started.port, "/source?site=gamma");
      assert.equal(res.status, 404);
      const said = String(((await res.json()) as { error?: string }).error);
      assert.match(said, /gamma/);
      assert.match(said, /alpha, beta/, "the refusal does not say what it does serve");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("goes dark rather than guessing when a caller names no site", async () => {
    // The old manager's request shape. With one site it is unambiguous and still answered — that is
    // what lets the new image deploy before the manager learns `?site=`. With two it is a 400: an
    // answer here would be this process choosing a VPC on the caller's behalf.
    const { dir, sites, alpha } = twoSites();
    let one: Started | undefined;
    let two: Started | undefined;
    try {
      one = await start(dir, MULTI(`alpha=${alpha}`));
      assert.equal((await fetchAt(one.port, "/source")).status, 200, "a single named site stopped answering");

      two = await start(dir, MULTI(sites));
      const res = await fetchAt(two.port, "/source");
      assert.equal(res.status, 400);
      assert.match(String(((await res.json()) as { error?: string }).error), /name one with \?site=/);
    } finally {
      one?.stop();
      two?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("keeps each site's cache to itself", async () => {
    // One cache slot for every site is merely wasteful. A key that drops the site is what serves
    // alpha's payload under beta's name, and on the page that answer is indistinguishable from a
    // correct one.
    //
    // ## How to prove this test is alive
    //
    // Two things identify the site — the `Map` bucket and the path inside `sourceStamp` — and they
    // are redundant on purpose. So removing **either one alone leaves this test green**, and that is
    // the right outcome rather than a dead test: the other mechanism still holds. It goes red when
    // both are removed together, on the first assertion, because beta's request then answers with
    // alpha's payload. Measured 2026-09-29; a single-point mutation here proves nothing either way.
    const { dir, sites, alpha, beta } = twoSites();
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      // Pin the two modules to the *same* mtime first. They already share a git state and an
      // allowlist, so with equal mtimes every other ingredient of the stamp is identical — which is
      // the adversarial case, and the only one that can tell a site-blind cache from a correct one.
      // Left to chance the two files differ by a millisecond and the bug hides.
      const pin = new Date(Date.now() - 60_000);
      utimesSync(alpha, pin, pin);
      utimesSync(beta, pin, pin);

      const a1 = parsePolicySource(await (await fetchAt(started.port, "/source?site=alpha")).json());
      const b1 = parsePolicySource(await (await fetchAt(started.port, "/source?site=beta")).json());
      assert.notDeepEqual(a1.site, b1.site, "the two fixtures never differed — this proves nothing");

      // Move beta only, and move its mtime with it: the stamp reads mtimes, and a write inside the
      // same millisecond does not shift one.
      writeFileSync(beta, `export const site = {
         cfg: { hookPolicy: { input: "drop", output: "accept" } },
         hosts: [{ id: "gw-01.beta", stage: "canary", items: [] }],
         objects: [{ id: "ao-beta", kind: "address", name: "beta-moved",
                     members: [{ kind: "cidr", value: "10.0.0.0/8" }] }],
       };\n`);
      const t = statSync(beta);
      utimesSync(beta, t.atime, new Date(t.mtimeMs + 5_000));

      const a2 = parsePolicySource(await (await fetchAt(started.port, "/source?site=alpha")).json());
      const b2 = parsePolicySource(await (await fetchAt(started.port, "/source?site=beta")).json());
      assert.deepEqual(a2.site, a1.site, "an edit to beta changed what alpha serves");
      assert.notDeepEqual(b2.site, b1.site, "beta's edit was served from a stale cache");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });
});

describe("a site module has to be the site it is declared as", () => {
  it("refuses to start when a declared name is not what the module's hosts say", async () => {
    // The 2026-09-28 incident at its earliest checkable point, and one copy-paste away in a
    // manifest: `alpha=…/beta.ts` produces a renderer that answers `?site=alpha` with beta's
    // firewall, and nothing downstream knows what alpha was supposed to hold.
    const { dir, beta } = twoSites();
    try {
      const { code, err } = await startExpectingRefusal(dir, {
        HELIOPAUSE_POLICY_SITE: "",
        HELIOPAUSE_POLICY_SITES: `alpha=${beta}`,
        HELIOPAUSE_POLICY_RENDER_TOKEN: BEARER,
      });
      assert.equal(code, 2, `the renderer came up serving beta's hosts as alpha\n${err}`);
      // The message, not just the code — a refusal for some other reason would satisfy the code.
      assert.match(err, /alpha/, "it did not say which declared name was wrong");
      assert.match(err, /gw-01\.beta/, "it did not name the host that gave it away");
    } finally {
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("starts when every name matches its module — the known positive", async () => {
    // Without this, the refusal above is equally satisfied by a renderer that never starts.
    const { dir, sites } = twoSites();
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("keeps serving its siblings when one module will not import", async () => {
    // Refusing to start on a module that throws would mean a git-sync landing a broken file takes
    // every other VPC's console down at the next pod restart — an outage manufactured by the fix.
    const { dir, sites, beta } = twoSites();
    writeFileSync(beta, "throw new Error('beta does not load');\n");
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200, "alpha went down with beta");
      const bad = await fetchAt(started.port, "/source?site=beta");
      assert.equal(bad.status, 503);
      assert.match(String(((await bad.json()) as { error?: string }).error), /beta does not load/);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("refuses when both site variables are set", async () => {
    // Two answers to one question. Merging them would make the behaviour depend on which line of the
    // manifest was edited last.
    const { dir, sites, alpha } = twoSites();
    try {
      const { code, err } = await startExpectingRefusal(dir, {
        HELIOPAUSE_POLICY_SITE: alpha,
        HELIOPAUSE_POLICY_SITES: sites,
        HELIOPAUSE_POLICY_RENDER_TOKEN: BEARER,
      });
      assert.equal(code, 2);
      assert.match(err, /both set/);
    } finally {
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });
});
