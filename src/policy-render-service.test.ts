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
// `fetch` will not send a malformed request target, so one test speaks HTTP directly.
import { connect } from "node:net";
import type { Readable } from "node:stream";
import {
  chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parsePolicySource } from "./policy-source.ts";
// Imported so the budget assertions derive both sides from the same table the renderer reads, rather
// than restating numbers that would then have to be kept in step by hand.
import { ENV_BOUNDS } from "./env-spec.ts";

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
  /**
   * Everything the renderer said on stdout up to and including the "listening" line.
   *
   * The startup verification logs before the listener exists, so those lines are already consumed by
   * this harness's own reader by the time `start()` resolves — a test that attaches afterwards sees
   * none of them. Without this, nothing the process says at startup is assertable at all, which is
   * how the declared-name caveat shipped with no test.
   */
  startupLog: string;
  /**
   * Everything said on stdout **so far**, including after startup.
   *
   * `startupLog` is frozen at the "listening" line, so a line the renderer logs while serving a
   * request was unassertable — which is how a bound whose only visible effect is a log line had no
   * test. The reader stays attached; this reads what it has accumulated.
   */
  output: () => string;
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
        startupLog: out,
        output: () => out,
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

  it("answers the same payload on a cache miss and a cache hit", async () => {
    // The evaluation step serialises the whole `PolicySource` and its caller parses it back, so a
    // served answer has crossed a wire boundary that did not exist before. This is the known
    // positive for that boundary: the first request evaluates and round-trips, the second is served
    // from the cache without re-evaluating, and the two have to be the same payload.
    //
    // Byte equality, not field spot-checks. What this guards against is a conversion that drops or
    // reshapes something nobody thought to assert on — `repo.probes` is exactly such a field,
    // carried past `toWire` and into the serialiser untouched.
    const dir = checkout();
    let started: Started | undefined;
    try {
      started = await start(dir);
      const first = await fetchSource(started.port);
      assert.equal(first.status, 200);
      const miss = await first.text();
      const second = await fetchSource(started.port);
      assert.equal(second.status, 200);
      const hit = await second.text();
      assert.equal(hit, miss, "the cached answer differs from the evaluated one");
      // A known positive for the comparison itself: two empty bodies would satisfy `assert.equal`,
      // so the test has to show it compared a payload rather than nothing.
      assert.ok(miss.length > 100, `the payload was too small to be a source: ${miss.length} bytes`);
      assert.match(miss, /"schemaVersion"/);
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

  it("renders an edit to a file the site module imports, not only the file's text", async () => {
    // The test above checks `files["policies.json"]`, which is read from disk on every evaluation —
    // so it passed while the policy itself stayed stale. The module *imports* that file, and ES
    // modules are cached by URL: `?v=` on the site module re-evaluated the module and handed it the
    // JSON it had read at pod start. The key moved, the generation moved, the text on screen moved,
    // and the rules did not. Found 2026-09-30: three console-added mailer rules published as a new
    // generation, confirmed on all three hosts, and absent from every ruleset.
    //
    // So this asserts on `site` — what the renderer evaluated — and the fixture derives it from the
    // imported file the way `dev.ts` derives its policies from `policies.json`.
    const dir = checkout();
    let started: Started | undefined;
    try {
      writeFileSync(join(dir, "policies.json"), '{\n  "schemaVersion": 1,\n  "groups": [],\n  "tag": "before"\n}\n');
      writeFileSync(
        join(dir, "site.ts"),
        `import P from "./policies.json" with { type: "json" };
         export const site = {
           cfg: { hookPolicy: { input: "drop", output: "accept" } },
           hosts: [{ id: "h1", stage: "canary", items: [] }],
           objects: [{ id: "ao-" + P.tag, kind: "address", name: P.tag, members: [{ kind: "cidr", value: "10.0.0.0/8" }] }],
         };\n`,
      );
      const pinned = 1_700_000_000;
      const site = join(dir, "site.ts");
      utimesSync(site, pinned, pinned);
      utimesSync(join(dir, "policies.json"), pinned, pinned);
      started = await start(dir);
      const objectIds = (s: { site: unknown }) => (s.site as { objects?: { id: string }[] }).objects?.map((o) => o.id);
      const first = parsePolicySource(await (await fetchSource(started.port)).json());
      assert.deepEqual(objectIds(first), ["ao-before"]);

      writeFileSync(join(dir, "policies.json"), '{\n  "schemaVersion": 1,\n  "groups": [],\n  "tag": "after"\n}\n');
      // A different whole second, so the stamp moves on the JSON file alone and not on rounding.
      utimesSync(join(dir, "policies.json"), pinned + 1, pinned + 1);
      utimesSync(site, pinned, pinned);

      const second = parsePolicySource(await (await fetchSource(started.port)).json());
      assert.match(second.files["policies.json"] ?? "", /"after"/, "the fixture did not land");
      assert.deepEqual(
        objectIds(second),
        ["ao-after"],
        "the file on screen changed and the policy rendered from it did not",
      );
    } finally {
      started?.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("renders an edit reached through a subdirectory, and keeps one copy of each policy module", async () => {
    // The first fix versioned an import only when it sat under the *importing* module's directory.
    // Found by an independent review (2026-09-30): `sub/a.ts` importing `../up.json` or
    // `../other/data.json` still got the pod-start copy, and `../class.ts` loaded twice — versioned
    // from the root, unversioned from `sub/` — so `instanceof` went false on the first evaluation,
    // which it had not been before the fix. No policy tree had a subdirectory yet; this is the day
    // one appears.
    const dir = checkout();
    let started: Started | undefined;
    try {
      mkdirSync(join(dir, "sub"));
      mkdirSync(join(dir, "other"));
      const write = (tag: string) => {
        writeFileSync(join(dir, "up.json"), JSON.stringify({ tag }));
        writeFileSync(join(dir, "other", "data.json"), JSON.stringify({ tag }));
      };
      write("before");
      writeFileSync(join(dir, "class.ts"), "export class Local {}\n");
      writeFileSync(
        join(dir, "sub", "a.ts"),
        `import up from "../up.json" with { type: "json" };
         import other from "../other/data.json" with { type: "json" };
         import { Local } from "../class.ts";
         export const made = new Local();
         export const tags = up.tag + "-" + other.tag;\n`,
      );
      writeFileSync(
        join(dir, "site.ts"),
        `import { made, tags } from "./sub/a.ts";
         import { Local } from "./class.ts";
         export const site = {
           cfg: { hookPolicy: { input: "drop", output: "accept" } },
           hosts: [{ id: "h1", stage: "canary", items: [] }],
           objects: [{ id: "ao-" + tags, kind: "address", name: String(made instanceof Local),
                       members: [{ kind: "cidr", value: "10.0.0.0/8" }] }],
         };\n`,
      );
      const pinned = 1_700_000_000;
      utimesSync(join(dir, "site.ts"), pinned, pinned);
      utimesSync(join(dir, "policies.json"), pinned, pinned);
      started = await start(dir);
      const read = async () => {
        const s = parsePolicySource(await (await fetchSource(started!.port)).json());
        const o = (s.site as { objects?: { id: string; name: string }[] }).objects?.[0];
        return { id: o?.id, identity: o?.name };
      };
      assert.deepEqual(await read(), { id: "ao-before-before", identity: "true" });

      write("after");
      // Only an allowed path moves the stamp; the two imported files are not in it, which is the
      // ordinary case — a commit moves the sha. Touching policies.json stands in for that.
      utimesSync(join(dir, "policies.json"), pinned + 1, pinned + 1);
      utimesSync(join(dir, "site.ts"), pinned, pinned);
      assert.deepEqual(
        await read(),
        { id: "ao-after-after", identity: "true" },
        "an import reached through a subdirectory stayed stale, or a policy module loaded twice",
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
  // ## A probe file, so the paths that read one are reachable
  //
  // `readCoverageProbes` only calls `JSON.parse` when `readdirSync` matches a `coverage-*.json`, so
  // without this file every shape that attacks that parser does nothing and passes. One such shape
  // was written, observed to answer 200, and removed as unreproducible (#126) — the fixture was
  // missing this line, not the renderer missing the defect.
  //
  // Contents are deliberately empty: the shapes that care replace the parser, so what the file holds
  // never reaches the answer. It has to exist, not to say anything.
  writeFileSync(join(dir, "coverage-a.json"), '{"probes":[]}\n');
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

/**
 * A readiness body without `workers`, for the assertions that pin the readiness contract exactly.
 *
 * `workers` is how many evaluation threads are alive at that instant, and a `/readyz` that has to
 * re-evaluate starts some of its own — so it is a timing measurement, not part of the answer these
 * assertions describe. The tests that are *about* it read it directly; @see "a module that spins
 * forever fails only its own site". Dropping it here rather than writing a number into each expected
 * object keeps those assertions about serving, total and faults, which is what they were written for.
 */
const readinessOf = async (res: Response): Promise<Record<string, unknown>> => {
  const { workers: _, ...rest } = (await res.json()) as Record<string, unknown>;
  return rest;
};

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

  it("labels each site with its own name, not the one the process was given", async () => {
    // `HELIOPAUSE_POLICY_LABEL` is one value for the process and the console prints it as "which
    // site this is". Left alone, picking `beta` would draw a page headed with alpha's label — a
    // screen reporting the opposite of what it drew, which is the shape of the incident this whole
    // change exists to stop. stardust caught this in the deployment manifest before it shipped: the
    // live value there names a module (`heliopause-deploy/dev.ts`), so all three sites would have
    // claimed to be dev.
    const { dir, sites } = twoSites();
    let started: Started | undefined;
    try {
      started = await start(dir, { ...MULTI(sites), HELIOPAUSE_POLICY_LABEL: "checkout/alpha.ts" });
      const a = parsePolicySource(await (await fetchAt(started.port, "/source?site=alpha")).json());
      const b = parsePolicySource(await (await fetchAt(started.port, "/source?site=beta")).json());
      assert.equal(a.label, "alpha");
      assert.equal(b.label, "beta", "beta was drawn under the label the process was started with");
      const listed = (await (await fetchAt(started.port, "/sites")).json()) as { sites?: { label: string }[] };
      assert.deepEqual(listed.sites?.map((s) => s.label), ["alpha", "beta"]);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("keeps the given label when there is one unnamed site", async () => {
    // The single-site deployment is unchanged: nothing named it, so the operator's label is the
    // only thing that can describe it and replacing that with "policy" would lose information.
    const dir = checkout();
    let started: Started | undefined;
    try {
      started = await start(dir);
      const got = parsePolicySource(await (await fetchSource(started.port)).json());
      assert.equal(got.label, "test-site");
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

  it("answers a ?site= it was never given a name for, which is the rollout order", async () => {
    // New manager, renderer still deployed with the old single-site variable. It sends `?site=dev`
    // to a process that named nothing. A 404 here would force the renderer's env to be flipped
    // before the manager is rolled — and flipping it first is exactly what takes the console down,
    // because the old manager's nameless request then gets a 400. This cell is what lets the two be
    // deployed in the order that keeps the console up.
    const dir = checkout();
    let started: Started | undefined;
    try {
      started = await start(dir);
      const res = await fetchAt(started.port, "/source?site=dev-icn-vtr");
      assert.equal(res.status, 200, "a single unnamed site refused a name it could not contradict");
      const got = parsePolicySource(await res.json());
      // And it does not pretend to be the site it was asked for. The absence is the honest answer:
      // the manager reads it as "this renderer cannot say" and falls back to the host-id rule.
      assert.equal(got.siteName, undefined, "an unnamed site answered with a name it was handed");
    } finally {
      started?.stop();
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

  it("still refuses when the misdeclared module is slow to import", { timeout: 30_000 }, async () => {
    // ## The budget above the refusal quietly turned a configuration fault into a content one
    //
    // The startup verification bounds each import so that a module which never settles cannot stop
    // the process reaching `server.listen`. But a timeout means the zone check **never ran**, and
    // the `catch` distinguishes `ZoneMismatchError` — refuse, it cannot heal itself — from every
    // other failure — log, it changes commit to commit. A timed-out misdeclared site landed in the
    // second branch, so the pod came up and served 503 for that VPC behind one log line instead of
    // exiting 2 with the sentence that says which of the two names is wrong.
    //
    // Measured: the same wrong-zone module exits 2 at 148ms when it imports instantly, and merely
    // logged when a budget shorter than its import cut it off. Any `await` at a policy module's top
    // level — one `readFile`, a dynamic import, a cold transpile — is enough to be on the wrong side
    // of that line. So the budget has to be larger than a real cold import, which is what this pins:
    // a module that takes a second still gets zone-checked and still refuses.
    const { dir, beta } = twoSites();
    writeFileSync(beta, `await new Promise((r) => setTimeout(r, 1000));\n${readFileSync(beta, "utf8")}`);
    try {
      const { code, err } = await startExpectingRefusal(dir, {
        HELIOPAUSE_POLICY_SITE: "",
        HELIOPAUSE_POLICY_SITES: `alpha=${beta}`,
        HELIOPAUSE_POLICY_RENDER_TOKEN: BEARER,
        HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: "10000",
      });
      assert.equal(code, 2, `a slow misdeclared module came up instead of refusing\n${err}`);
      assert.match(err, /gw-01\.beta/, "it did not name the host that gave it away");
    } finally {
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("verifies its sites together, so one hung module does not delay the rest", { timeout: 30_000 }, async () => {
    // ## The bound was additive, and additive is its own outage
    //
    // This loop was `for … await`, so N hung sites cost N budgets before `server.listen` — and until
    // that line nothing answers, `/healthz` included, because the listener does not exist yet.
    // Measured 2s × 3 = 6.1s; at the 30s default with the three-VPC deployment this file keeps
    // describing, that is ninety seconds dark, against a liveness probe of 30s × 3. The bound added
    // to stop a hang reached the crashloop the `/healthz` comment says must never be created.
    //
    // Two hung sites and a budget of 2s: serial is ~4s, together is ~2s. The threshold sits between
    // them, so this fails if the loop ever goes back to sequential.
    const { dir, sites, alpha, beta } = twoSites();
    const hang = "await new Promise(() => {});\nexport const site = { cfg: {}, hosts: [] };\n";
    writeFileSync(alpha, hang);
    writeFileSync(beta, hang);
    let started: Started | undefined;
    // Derived from the budget rather than written as a number, so tuning one moves the other. The
    // threshold sits between one budget and two; measured five runs at 2147–2169ms parallel against
    // 4119ms serial, so the slack is over a second on a ~150ms fixed cost.
    const budget = 2_000;
    const began = Date.now();
    try {
      started = await start(dir, { ...MULTI(sites), HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: String(budget) });
      const took = Date.now() - began;
      assert.ok(
        took < budget * 1.75,
        `startup took ${took}ms against a ${budget}ms budget — that is one budget per site, so the ` +
          `sites were verified one after another`,
      );
      // And it is listening, which is the point of bounding at all.
      assert.equal((await fetchAt(started.port, "/healthz")).status, 200);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("reports why a module failed without pointing at the declared name", { timeout: 30_000 }, async () => {
    // ## What this test protects, across two rewrites of the message it reads
    //
    // The property is **not** a wording: it is that a failure which is not a zone fault does not send
    // an operator to the site name in their Deployment. That has been protected three different ways.
    //
    // 1. The line said nothing, and silence read as "the check passed".
    // 2. A caveat was added — "the declared-name check did not run for it" — selected by
    //    `why.includes("did not finish within")`. Wrong on both sides: it covered only the timeout, and
    //    the string was `evaluateWithin`'s own wording, so a module could throw that text and choose
    //    which sentence an operator read.
    // 3. The caveat was carried by a class a module cannot reach (`ZoneCheckedError`), and a second
    //    branch said "is the site it is declared as" when the check had passed.
    //
    // 🔑 **The third is gone because the zone check moved.** It now runs last, on the parsed wire,
    // since a check inside the worker runs in a realm the module controls. Every content failure
    // therefore happens before it, so "the check passed" is never available to say — and "the check did
    // not run", while true of everything, points at the name for failures that have nothing to do with
    // it. That is defect 1 and defect 3's motivation arriving together.
    //
    // So the message says the reason and nothing about the name. The three assertions below are the
    // property, not the sentence: no naming cue, a reason that is present, and — in the test after this
    // one — a real mismatch still being loud and fatal.
    //
    // Both failure shapes are driven, because the predicate that selected the old caveat was wrong on
    // exactly the half that was not tested: one site hangs past its budget, the other throws at import.
    //
    // ⚠️ The hang holds a handle open (`setInterval`). A bare `await new Promise(() => {})` is no longer
    // a budget hang: in a worker it leaves the event loop empty and Node ends the thread with exit 13
    // in milliseconds — measured, and asserted separately in "names a top-level await that never
    // settles". The first version of this test used the bare form and expected "did not finish
    // within", which in-process was true and in a worker is a budget that never ran out.
    const { dir, sites, alpha, beta } = twoSites();
    writeFileSync(alpha, "setInterval(() => {}, 1000);\nawait new Promise(() => {});\nexport const site = { cfg: {}, hosts: [] };\n");
    writeFileSync(beta, "throw new Error('beta will not import');\n");
    let started: Started | undefined;
    try {
      started = await start(dir, { ...MULTI(sites), HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: "1000" });
      const said = started.startupLog;
      // ① No naming cue, for either failure. The words are the ones the two retired messages used, so
      // reintroducing either of them fails here.
      for (const cue of [/declared.name/i, /check did not run/i, /is the site it is declared as/i]) {
        assert.ok(
          !cue.test(said),
          `a failure that is not a zone fault pointed at the declared name (${cue.source}):\n${said}`,
        );
      }
      // ② The reason is present — for both, and each naming its own cause. Without this, ① is satisfied
      // by a message that says nothing at all, which is defect 1.
      assert.match(said, /alpha did not evaluate at startup and will answer 503 until it does: .*did not finish within/);
      assert.match(said, /beta did not evaluate at startup and will answer 503 until it does: .*beta will not import/);
      // And it did come up: neither failure may be fatal.
      assert.equal((await fetchAt(started.port, "/healthz")).status, 200);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("names a top-level await that never settles, rather than calling it a timeout", { timeout: 30_000 }, async () => {
    // A module that awaits nothing-at-all leaves the worker's loop empty, and Node ends the thread with
    // exit 13 before any budget can fire. That is a real ending with a real cause, and reporting it as
    // "did not finish within" would name a budget that never ran out. The budget here is long on
    // purpose: if the reason still says "within", the timer fired, which means exit 13 was missed.
    const { dir, sites, alpha } = twoSites();
    writeFileSync(alpha, "await new Promise(() => {});\nexport const site = { cfg: {}, hosts: [] };\n");
    let started: Started | undefined;
    try {
      started = await start(dir, { ...MULTI(sites), HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: "20000" });
      const said = started.startupLog;
      assert.match(said, /alpha did not evaluate at startup and will answer 503 until it does: .*never settled \(exit 13\)/);
      assert.doesNotMatch(said, /did not finish within/);
      assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 503);
      assert.equal((await fetchAt(started.port, "/source?site=beta")).status, 200);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("is still loud and fatal when the declared name really is wrong", { timeout: 30_000 }, async () => {
    // ③ The other half of the property above. Dropping the naming cue from content failures must not
    // make a real mismatch quieter: this one is the fault the startup block treats as unable to heal
    // itself, so it refuses to come up at all.
    //
    // 🔑 Without this test, ① is satisfiable by removing the zone check entirely.
    const { dir, beta } = twoSites();
    writeFileSync(beta, 'export const site = { cfg: {}, hosts: [{ id: "h1.somewhere-else", stage: "canary", items: [] }] };\n');
    try {
      const { code, err } = await startExpectingRefusal(dir, {
        HELIOPAUSE_POLICY_SITE: "",
        HELIOPAUSE_POLICY_SITES: `beta=${beta}`,
        HELIOPAUSE_POLICY_RENDER_TOKEN: BEARER,
      });
      assert.equal(code, 2, `a declared-name mismatch must refuse to start\n${err}`);
      // The exit code alone would pass if the process refused for an unrelated reason, which this
      // file has recorded as a way a refusal test goes hollow. The message has to name the host that
      // gave it away.
      assert.match(err, /somewhere-else/, `it did not name the host that gave it away\n${err}`);
    } finally {
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("does not blame the declared name when the check ran and the content failed", { timeout: 30_000 }, async () => {
    // ## The caveat's other side, and the reason it is now carried rather than inferred
    //
    // `collectPolicySource` runs **after** the zone check has passed, so anything it throws is a
    // content fault on a correctly-declared site. Made unconditional, the caveat told those sites
    // "the declared-name check did not run for it" — sending an operator to edit a Deployment that is
    // right while a `JSON.stringify` failure in the policy repo sits untouched. Reproduced with an
    // ordinary accidental cycle, which is the likeliest way to reach it.
    //
    // So the predicate has been wrong in both directions on successive commits — first a string match
    // that covered only timeouts, then no condition at all — and both times because it was inferred
    // from the failure rather than carried with it. `ZoneCheckedError` carries it. This test is the
    // half that was blind: the neighbouring one drives a hang and an import throw, both of which fail
    // *before* the check, so it stayed green through the over-claim.
    const { dir, sites, alpha } = twoSites();
    writeFileSync(alpha, `${readFileSync(alpha, "utf8")}
const cycle = {};
cycle.parentOfItself = cycle;
site.hosts[0].notes = cycle;
`);
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const said = started.startupLog;
      // The property this test has always held, now without the reassurance sentence it used to read
      // (that sentence needed the zone check to run first, and it runs last now — see "reports why a
      // module failed without pointing at the declared name"): a content fault does not send the
      // operator to the site name. ① no naming cue, ② the cause is there.
      for (const cue of [/declared.name/i, /check did not run/i]) {
        assert.doesNotMatch(
          said, cue,
          `a content fault was reported as a possible naming fault:\n${said}`,
        );
      }
      assert.match(
        said, /alpha did not evaluate at startup and will answer 503 until it does: .*circular/i,
        `the cause did not reach the operator:\n${said}`,
      );
      // beta is untouched, so the positive half must still be there — otherwise this passes against a
      // renderer that stopped verifying anything.
      assert.match(said, /verified beta — /);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("cannot be made to forge a log line by a policy module", { timeout: 30_000 }, async () => {
    // ## The claim the previous commit shipped without a test
    //
    // It removed a predicate a module could choose between two true sentences with and called the
    // result "nothing for a module to spoof" — while `${error.message}` was still interpolated
    // verbatim. A module throwing `"boom\n[policy-render] verified beta — 12 hosts"` printed a forged
    // **`verified`** line, the positive signal an operator scans for, and the pod came up looking
    // clean. That is a strictly stronger forgery than the one removed: the predicate let a module pick
    // between true sentences, this let it manufacture a false one.
    //
    // Every "this is now closed" sentence needs one of these or it does not ship — that is the rule
    // four rounds of review produced, and this is the first test written to it.
    const { dir, sites, beta } = twoSites();
    writeFileSync(
      beta,
      'throw new Error("boom\\n[policy-render] verified beta — 12 hosts\\n[policy-render] evaluated beta at deadbee");\n',
    );
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const said = started.startupLog;
      assert.doesNotMatch(said, /^\[policy-render\] verified beta — 12 hosts$/m, "a module forged a verified line");
      assert.doesNotMatch(said, /^\[policy-render\] evaluated beta at deadbee$/m, "a module forged an evaluated line");
      // The text still has to reach the operator — marked, not dropped. The character-level cases
      // (ANSI, a lone `\r`, U+2028) live in `src/log-scrub.test.ts`; what this asserts is the
      // integration: module-thrown text reaches stdout through `log`, and through the shared control.
      assert.match(said, /boom\uFFFD+\[policy-render\] verified beta/, "the message was lost, not marked");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("a module cannot force a refusal by throwing the renderer's own error class", { timeout: 30_000 }, async () => {
    // ## Class identity is not provenance
    //
    // A site module imports the model with `../src` — the spelling the mount check demands — and Node
    // realpaths module URLs, so the module's `../src/site-zone.ts` and the renderer's are the **same
    // module instance**: the `ZoneMismatchError` class object is literally the same one. A module that
    // throws it therefore satisfied `instanceof ZoneMismatchError` in the startup loop, which answers
    // that with `process.exit(2)`. Reproduced before the fix: the pod refused to start, printing a
    // refusal sentence the module had authored, and every co-served site's console went with it.
    //
    // The precondition is the deployment this file insists on: with the checkout at
    // `/opt/heliopause/policy` and the binary at `/opt/heliopause/bin`, both `../src` spellings resolve
    // to `/opt/heliopause/src`. So the fixture points `<root>/src` at the real `src/` — anything less
    // and `instanceof` would not hold and the test would pass for the wrong reason.
    const { dir, sites, beta } = twoSites();
    // Replace the placeholder `src` that `twoSites` creates with a link to the real one, so the
    // module's `../src/site-zone.ts` resolves to the same file the renderer imports.
    rmSync(join(dir, "..", "src"), { recursive: true, force: true });
    symlinkSync(fileURLToPath(new URL(".", import.meta.url)), join(dir, "..", "src"));
    // Two ways in, and the second is why the brand is a `WeakSet` rather than a subclass: a subclass
    // inherits statics, so `Symbol.hasInstance` defined on the shared parent makes `instanceof
    // <subclass>` answer true for anything. Measured before the fix — a plainly-constructed error
    // satisfied `instanceof Own`. A module cannot add an entry to a set it cannot name.
    writeFileSync(beta, `import { ZoneMismatchError } from "../src/site-zone.ts";
Object.defineProperty(ZoneMismatchError, Symbol.hasInstance, { value: () => true, configurable: true });
export const site = {
  cfg: { hookPolicy: { input: "drop", output: "accept" } },
  hosts: [{ id: "gw-01.beta", stage: "canary", items: [] }],
  workload: [{ kind: "service", value: "kube-system/coredns" }],
  resolveService() { throw new ZoneMismatchError("forged by the policy module"); },
};
`);
    let started: Started | undefined;
    try {
      // If the module could still force a refusal this throws "exited with 2 before listening", which
      // is the assertion: reaching a listener at all is the property.
      started = await start(dir, MULTI(sites));
      const said = started.startupLog;
      assert.doesNotMatch(said, /refusing to start/, `a module forced a refusal:\n${said}`);
      // Treated as a content fault: the one-line non-fatal message, carrying the module's text.
      assert.match(
        said, /beta did not evaluate at startup and will answer 503 until it does: .*forged by the policy module/,
        `a module-authored zone error was not treated as a content fault:\n${said}`,
      );
      // alpha is untouched, so it must still be served — the pod staying up is the whole point.
      assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200);
      // And beta answers, rather than the request being the thing that kills the process.
      assert.equal((await fetchAt(started.port, "/source?site=beta")).status, 503);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("survives a policy module that throws a nullish value", { timeout: 30_000 }, async () => {
    // ## `throw null` was two tokens and a crashloop
    //
    // `throw` takes any value. The startup loop read `(e as Error).message` before either branch, so a
    // nullish throw raised a `TypeError` at the read: exit 1, `server.listen` never reached, and at
    // `replicas: 1` with `Recreate` that is every co-served site's console down — the outage that
    // loop's own comment refuses to manufacture. `throw 42` survived and printed the reason as the
    // literal word `undefined`.
    //
    // It also broke `ZoneCheckedError` directly: constructing it from `(e as Error).message` threw
    // inside the catch, so the wrapper never existed and a post-zone-check failure was blamed on the
    // declared name — the confusion that class exists to end.
    // The last four make coercion itself throw, which is what a module reaches for once `null` is
    // handled: a `toString` that throws, a `Symbol.toPrimitive` that throws, `Object.create(null)`
    // (no `toString` to find at all), and a Proxy whose `get` trap throws. Measured before the fix,
    // four of five made `asError` throw — restoring the crash from inside the function that prevents it.
    for (const thrown of [
      "null", "undefined", "42", '"a string"', "{}",
      "{ toString() { throw new Error('nope'); } }",
      "{ [Symbol.toPrimitive]() { throw new Error('nope'); } }",
      "Object.create(null)",
      "new Proxy({}, { get() { throw new Error('nope'); } })",
    ]) {
      const { dir, sites, beta } = twoSites();
      writeFileSync(beta, `throw ${thrown};\n`);
      let started: Started | undefined;
      try {
        started = await start(dir, MULTI(sites));
        const said = started.startupLog;
        assert.match(said, /beta .*did not evaluate at startup/, `throw ${thrown}: no report`);
        // Not "the reason says non-error value" for every case: a thrown Proxy never reaches `asError`
        // as itself. Node's own module machinery touches the rejected value first, its `get` trap
        // throws, and what arrives here is already an ordinary `Error`. Asserting the message shape
        // for that case failed against correct behaviour — the property is that the process survives
        // and reports something an operator can act on, which the per-case checks here cover.
        assert.doesNotMatch(
          said, /until it does:\s*$/m,
          `throw ${thrown}: the report had no reason in it at all`,
        );
        // The reason has to name the value, not read as the word `undefined`.
        assert.doesNotMatch(
          said, /until it does: undefined$/m,
          `throw ${thrown}: the reason was the word "undefined"`,
        );
        assert.match(said, /verified alpha — /, `throw ${thrown}: it stopped verifying the others`);
      } finally {
        started?.stop();
        rmSync(join(dir, ".."), { recursive: true, force: true });
      }
    }
  });

  it("answers 503 rather than dying when a nullish throw reaches a request", { timeout: 30_000 }, async () => {
    // ## The half the startup fix did not cover, and it is the worse half
    //
    // `asError` was applied where the startup loop catches, so a module's `throw null` stopped killing
    // startup — and that made it worse. Measured: the pod came up, `/healthz` answered 200, and the
    // **first `/source` request** read `.message` off `null` inside a rejection handler, so an
    // unhandled rejection took the process out with exit 1. It passed both probes and then died when
    // the manager asked for policy, which is a crashloop driven by ordinary polling.
    //
    // The normalisation now sits in `evaluateWithin`'s rejection, which every consumer of
    // `currentSource` passes through — `/source`, `/readyz` and the startup loop — rather than at the
    // four places that read `.message`. This file noted that exact "second path a per-call-site fix
    // forgets" about `console.error` one commit before repeating it.
    const { dir, sites, beta } = twoSites();
    writeFileSync(beta, "throw null;\n");
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      assert.equal((await fetchAt(started.port, "/healthz")).status, 200);
      const res = await fetchAt(started.port, "/source?site=beta");
      assert.equal(res.status, 503, "a nullish throw did not become a 503");
      assert.match(
        String(((await res.json()) as { error?: string }).error),
        /policy module threw a non-error value: null/,
        "the reason did not name the value that was thrown",
      );
      // Still alive, and still serving its sibling — the property the exit-1 crash destroyed.
      assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200);
      assert.equal((await fetchAt(started.port, "/healthz")).status, 200);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("answers 400 to a request target it cannot parse, and keeps serving", { timeout: 30_000 }, async () => {
    // ## The worst thing seven review rounds found, and it was there the whole time
    //
    // `new URL("//[", "http://placeholder")` throws `ERR_INVALID_URL`: `//` makes the target
    // protocol-relative, so `[` begins an IPv6 host and fails. The request handler is a synchronous
    // `createServer` callback, so the throw was uncaught — **exit 1** — and it happened *before* the
    // bearer check. One unauthenticated `GET //[` from anything that could reach the port took the pod
    // down, and at `replicas: 1` with `Recreate` every zone's console went with it.
    //
    // Unchanged from `origin/main` of this repository, so it predates this branch rather than being
    // introduced by it. That is a statement about this repository; the running image is built from
    // another one, and its tag does not resolve here. `//[::1`, `//%` and `http://[` do the same.
    const { dir, sites } = twoSites();
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const port = started.port;
      const raw = (target: string): Promise<string> => new Promise((resolve) => {
        const sock = connect(port, "127.0.0.1", () => {
          sock.write(`GET ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
        });
        let buf = "";
        sock.on("data", (d: Buffer) => { buf += d.toString(); });
        sock.on("close", () => resolve(buf.split("\r\n")[0] ?? ""));
        sock.on("error", () => resolve("socket error"));
        setTimeout(() => { sock.destroy(); resolve("timeout"); }, 4_000);
      });
      for (const target of ["//[", "//[::1", "//%"]) {
        assert.match(await raw(target), /^HTTP\/1\.1 400 /, `${target} did not get a 400`);
      }
      // Still alive and still answering — the property the uncaught throw destroyed.
      assert.equal((await fetchAt(port, "/healthz")).status, 200);
      assert.equal((await fetchAt(port, "/source?site=alpha")).status, 200);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("survives a module whose error resists being read", { timeout: 30_000 }, async () => {
    // ## Three shapes that each ended the process, all in the error-handling path itself
    //
    // - **A thrown Proxy with a `getPrototypeOf` trap.** `thrown instanceof Error` walks the prototype
    //   chain, so the classification in `asError` ran the trap and threw — inside a rejection handler
    //   that had already cleared its timer, so nothing caught it. A revoked Proxy does the same with
    //   `TypeError: Cannot perform 'getPrototypeOf' on a proxy that has been revoked`.
    // - **An `Error` whose `.message` getter throws.** `asError` returned `Error` instances unchanged,
    //   so the getter survived to the log line and the 503 body, outside every guard.
    //
    // Each of these is a normal-looking configuration mistake away from a real one: a getter that
    // reads something undefined, a Proxy left revoked by a helper. The fix is that conversion reads
    // the message once, into a string this process owns.
    const shapes: Record<string, string> = {
      proxyPrototype: 'new Proxy({}, { getPrototypeOf() { throw new Error("trap"); } })',
      revokedProxy: '(() => { const r = Proxy.revocable({}, {}); r.revoke(); return r.proxy; })()',
      unreadableMessage:
        '(() => { const e = new Error("x"); Object.defineProperty(e, "message", ' +
        '{ get() { throw new Error("message trap"); } }); return e; })()',
    };
    for (const [name, expr] of Object.entries(shapes)) {
      const { dir, sites, beta } = twoSites();
      writeFileSync(beta, `throw ${expr};\n`);
      let started: Started | undefined;
      try {
        started = await start(dir, MULTI(sites));
        assert.match(
          started.startupLog, /beta .*did not evaluate at startup/,
          `${name}: it did not report the failure`,
        );
        // The request path too, since that is where the previous round's fix did not reach.
        assert.equal((await fetchAt(started.port, "/source?site=beta")).status, 503, `${name}: no 503`);
        assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200, `${name}: alpha lost`);
        assert.equal((await fetchAt(started.port, "/healthz")).status, 200, `${name}: process gone`);
      } finally {
        started?.stop();
        rmSync(join(dir, ".."), { recursive: true, force: true });
      }
    }
  });

  it("keeps its provenance check working when a module patches WeakSet", { timeout: 30_000 }, async () => {
    // ## The set was unreachable; the lookup was not
    //
    // `foundHere` called `OUR_ZONE_MISMATCHES.has(...)`, which resolves `has` on `WeakSet.prototype`
    // at call time. A configuration module runs in this realm, so
    // `WeakSet.prototype.has = () => true` in one made every error look like one this process built —
    // turning an ordinary content fault into `exit 2` with a refusal nobody configured. Measured.
    //
    // Binding `has` before the first `import()` is what makes the set's unreachability the only thing
    // that matters, and this drives it: the module patches the prototype *and* throws an ordinary
    // error, which must still be a content fault.
    const { dir, sites, beta } = twoSites();
    writeFileSync(beta, `WeakSet.prototype.has = () => true;
throw new Error("an ordinary content fault");
`);
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      assert.doesNotMatch(
        started.startupLog, /refusing to start/,
        `a patched WeakSet forced a refusal:\n${started.startupLog}`,
      );
      assert.match(started.startupLog, /beta .*did not evaluate at startup/);
      assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("answers nothing rather than an empty body", { timeout: 30_000 }, async () => {
    // ## Not throwing is not the same as producing a body
    //
    // The serialisation guard was written for a `toJSON` that throws. An inherited one that **returns
    // `undefined`** does not throw: `JSON.stringify` returns `undefined`, the `catch` never runs, and
    // `res.end(undefined)` goes out as a **200 with an empty body** under `application/json`. The
    // manager parses nothing and has no error to report — the quietest possible failure, and the
    // declared `let text: string` is why it read as impossible.
    //
    // Found by an independent audit of this branch. `/healthz` is unaffected either way: it answers a
    // constant that was serialised when the file was written, which is asserted here so that staying
    // 200 is a checked property and not a coincidence.
    const { dir, sites, beta } = twoSites();
    writeFileSync(
      beta,
      'Object.defineProperty(Object.prototype, "toJSON", { value() { return undefined; }, configurable: true });\n' +
        'throw new Error("bad beta");\n',
    );
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const port = started.port;
      const deadline = (): RequestInit => ({ signal: AbortSignal.timeout(10_000) });
      const healthz = await fetchAt(port, "/healthz", deadline());
      assert.equal(healthz.status, 200, "the liveness probe stopped answering");
      assert.deepEqual(await healthz.json(), { ok: true }, "/healthz went through the serialiser");
      // ## 🔑 The poisoned site fails; the others no longer do
      //
      // Before the worker, the `toJSON` lived in the renderer's own realm, so it took over every
      // serialisation the process did: measured on `da80b7b` with this exact module, `/source?site=alpha`,
      // `/source?site=beta` and `/readyz` all answered **503 "the answer could not be serialised"**. That
      // was cross-site contamination — alpha poisoned nothing — and the assertion here used to require
      // it, because the only thing that could be guaranteed then was "not an empty 200".
      //
      // In a worker the prototype it poisons belongs to beta's thread alone. Measured on this tree:
      // alpha 200, readiness 200 (degraded, 1 of 2 serving), beta 503. The property the test always
      // protected — no empty body, no unserialisable answer passed off as success — still holds, and
      // it is asserted for every path; what changed is that a healthy site is no longer collateral.
      for (const path of ["/source?site=alpha", "/source?site=beta", "/readyz"]) {
        const res = await fetchAt(port, path, deadline());
        const text = await res.text();
        assert.notEqual(text, "", `${path}: an empty body went out with ${res.status}`);
        // Every body parses: nothing unserialisable went out under any status.
        JSON.parse(text);
      }
      const alpha = await fetchAt(port, "/source?site=alpha", deadline());
      assert.equal(alpha.status, 200, "alpha poisoned nothing and was taken down with beta");
      assert.equal(((await alpha.json()) as { siteName?: string }).siteName, "alpha");
      const beta = await fetchAt(port, "/source?site=beta", deadline());
      assert.equal(beta.status, 503, "the poisoning site was reported as healthy");
      const ready = (await (await fetchAt(port, "/readyz", deadline())).json()) as { serving?: number; total?: number };
      assert.deepEqual([ready.serving, ready.total], [1, 2], "readiness did not count beta as down and alpha as up");
      assert.equal((await fetchAt(port, "/healthz", deadline())).status, 200, "healthz after");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("does not count a git checkout against the scan cap", { timeout: 60_000 }, async () => {
    // ## 🔴 The test that would have stopped a full outage, and did not exist
    //
    // The policy directory **is a git checkout**, and `.git` holds thousands of entries on its own:
    // measured in a real tree, 3,116 entries with it and 49 without. The version of the cap that
    // counted everything and refused above it would therefore have answered 503 for **every site on
    // every deployment** — a full console outage shipped as a fix for a memory leak, which had itself
    // been shipped as a fix for a frozen cache key.
    //
    // Nothing in this suite could have caught it, because `twoSites()` builds a directory with no
    // `.git` in it. That is the whole reason this test exists: the fixture was more forgiving than the
    // world, and every assertion about the cap was made against the forgiving one.
    const { dir, sites, beta } = twoSites();
    // 🔑 **Each skip has to be enough on its own.** The first fixture put 700 files in each of three
    // hidden directories, so removing dot-skipping exposed 1,400 and removing `node_modules`-skipping
    // exposed 700 — both under the 2,000 cap, so either mutation survived and the test held up neither
    // rule. Each directory now carries more than the cap by itself.
    for (const hidden of [".git", "node_modules"]) {
      const sub = join(dir, hidden);
      mkdirSync(sub);
      for (let i = 0; i < 2_100; i += 1) writeFileSync(join(sub, `o${i}.ts`), `export const n${i} = ${i};\n`);
    }
    // And a dot-**file** the module actually imports. The predicate skipped any entry whose name began
    // with a dot, before the directory check, so this helper was importable, versioned by the resolve
    // hook, and invisible to the stamp — a stale payload for a change inside the scanned directory. The
    // assertion that catches it is the edit below, not the status code.
    writeFileSync(join(dir, ".helper.ts"), 'export const mark = "first";\n');
    writeFileSync(beta, `import { mark } from "./.helper.ts";
export const site = {
  cfg: { hookPolicy: { input: "drop", output: "accept" } },
  hosts: [{ id: "gw-01.beta", stage: "canary", items: [] }],
  objects: [{ id: "ao-beta", kind: "address", name: mark,
              members: [{ kind: "cidr", value: "10.0.0.0/8" }] }],
};
`);
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const port = started.port;
      const deadline = (): RequestInit => ({ signal: AbortSignal.timeout(20_000) });
      for (const site of ["alpha", "beta"]) {
        assert.equal(
          (await fetchAt(port, `/source?site=${site}`, deadline())).status, 200,
          `${site} was refused because of files a module graph cannot reach`,
        );
      }
      assert.doesNotMatch(
        started.output(), /entries beside/,
        "the scan overflowed on an ordinary checkout",
      );
      // The dot-file half: a helper whose name begins with a dot is imported, so a change to it has to
      // move the stamp. Skipping dot-*entries* rather than dot-*directories* makes this answer "first"
      // forever while the module says "second".
      const named = async (): Promise<unknown> => {
        const r = await fetchAt(port, "/source?site=beta", deadline());
        assert.equal(r.status, 200, "beta lost");
        return ((await r.json()) as { site?: { objects?: { name?: unknown }[] } })
          .site?.objects?.[0]?.name;
      };
      assert.equal(await named(), "first", "the fixture's marker is not where this test reads it");
      writeFileSync(join(dir, ".helper.ts"), 'export const mark = "second";\n');
      const later = new Date(Date.now() + 5_000);
      utimesSync(join(dir, ".helper.ts"), later, later);
      assert.equal(
        await named(), "second",
        "a dot-file the module imports is invisible to the stamp, so its edit was never seen",
      );
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("serves a 200-deep tree under at most 64 descriptors", { timeout: 60_000 }, async () => {
    // ## Named for what it shows, on the third attempt
    //
    // The walk opens a directory handle, reads it, and closes it in a `finally` before opening the next,
    // so in the implementation descriptor use is constant in the depth of the tree. **This test cannot
    // see that.** Two earlier names claimed more than it measures:
    //
    //   · "holds one directory handle at a time" — an implementation holding two passes just as well.
    //   · "does not use more descriptors as the tree gets deeper" — a review retained every tenth handle
    //     and measured peak use going from 3 at depth 20 to 21 at depth 200, while **both** scans still
    //     succeeded under a 64-handle budget. Growth was present and the test was green.
    //
    // What it establishes is the sentence in its name: this tree, this budget, served. That rules out
    // descriptor use that grows *unboundedly* with depth, which is what a leaked handle per level looks
    // like, and rules out nothing finer. Each earlier name was the property I wanted rather than the one
    // being measured — the same substitution this file keeps recording, three times on one line.
    //
    // It exists because nothing else asserted any of this: a mutation matrix came back six-for-six red
    // and none of those six removed the closure, injected a read failure, or counted descriptors. "Six
    // red" said nothing about resource behaviour at all.
    //
    // ## 🔴 And the limit has to be checked, because asking for it can fail
    //
    // `ulimit -n 64` fails on a host whose **hard** limit is lower, and the shell then carries on under
    // whatever the limit already was. If that is 1024, a 200-deep chain proves nothing and this test
    // passes anyway — a resource assertion that silently stops asserting, which is worse than not having
    // one. So the child reports the limit it actually runs under and the assertion below requires it to
    // be no higher than what was asked for. Lower is stricter and fine; higher is a failure.
    const LIMIT = 64;
    const DEPTH = 200;
    let started: { proc: ChildProcessByStdio<null, Readable, Readable>; dir: string } | undefined;
    const { dir, sites, beta } = twoSites();
    try {
      let deep = dir;
      for (let i = 0; i < DEPTH; i += 1) {
        deep = join(deep, `d${i}`);
        mkdirSync(deep);
      }
      writeFileSync(join(deep, "leaf.ts"), "export const leaf = 1;\n");
      writeFileSync(beta, `export const site = {
  cfg: { hookPolicy: { input: "drop", output: "accept" } },
  hosts: [{ id: "gw-01.beta", stage: "canary", items: [] }],
};
`);
    // `ulimit` is a shell builtin, so the child is started through `sh`. `exec` keeps the process
    // identity the harness's reader expects, and `ulimit -n` afterwards prints what was actually
    // applied — the value the assertion reads, rather than the value that was requested.
    const proc = spawn("sh", ["-c", `ulimit -n ${LIMIT}; ulimit -n 1>&2; exec "$0" "$@"`, process.execPath, BIN], {
      env: {
        PATH: process.env.PATH ?? "",
        HOME: process.env.HOME ?? "",
        HELIOPAUSE_POLICY_RENDER_TOKEN: BEARER,
        HELIOPAUSE_POLICY_RENDER_PORT: "0",
        HELIOPAUSE_POLICY_RENDER_HOST: "127.0.0.1",
        ...MULTI(sites),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    started = { proc, dir };
    let out = "";
    let err = "";
    proc.stdout.on("data", (b: Buffer) => { out += b.toString(); });
    proc.stderr.on("data", (b: Buffer) => { err += b.toString(); });
      const port = await new Promise<number>((resolve, reject) => {
        const fail = setTimeout(() => reject(new Error(`never listened:\n${out}\n${err}`)), 20_000);
        proc.stdout.on("data", () => {
          const m = /listening on [^:]+:(\d+)/.exec(out);
          if (m) { clearTimeout(fail); resolve(Number(m[1])); }
        });
        proc.on("exit", (code) => {
          clearTimeout(fail);
          reject(new Error(`exited with ${code} before listening:\n${out}\n${err}`));
        });
      });
      // The limit the child is really under, from the child. Asking is not the same as getting.
      const applied = Number(/^\s*(\d+)\s*$/m.exec(err)?.[1]);
      assert.ok(
        Number.isInteger(applied) && applied > 0,
        `the child did not report its descriptor limit, so this test cannot know what it ran under:\n${err}`,
      );
      assert.ok(
        applied <= LIMIT,
        `the descriptor limit is ${applied}, not ${LIMIT} or less — \`ulimit\` did not take, so a ` +
          `${DEPTH}-deep tree proves nothing about descriptor growth and this test was passing for free`,
      );
      const res = await fetchAt(port, "/source?site=beta", { signal: AbortSignal.timeout(20_000) });
      assert.equal(
        res.status, 200,
        `a ${DEPTH}-deep tree was not served under a ${applied}-descriptor limit, which is what ` +
          `descriptor use growing with depth looks like: ${(await res.json() as { error?: string }).error ?? ""}`,
      );
      assert.doesNotMatch(out + err, /EMFILE/, "the walk ran out of descriptors");
    } finally {
      started?.proc.kill("SIGKILL");
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("refuses a site whose tree it could not finish reading", { timeout: 60_000 }, async () => {
    // ## A directory that cannot be enumerated is not an empty one
    //
    // The walk caught the failure and continued, which made an unreadable directory contribute nothing
    // and the stamp come back **complete**. The two are different states and only one of them is safe
    // to cache: a directory can deny enumeration while still allowing a known filename to be opened, so
    // a helper stays importable and becomes unstampable at the same instant. Fail-open, in the function
    // whose only job is to notice change. Found by a third review of these twenty lines.
    //
    // Refusing is consistent with the overflow: no complete stamp, no answer. It does mean a permissions
    // fault anywhere under the policy directory refuses every site sharing it, which is the same shared
    // blast radius the overflow has and is stated at the code.
    if (process.getuid?.() === 0) {
      // root ignores the mode bits, so there is no unreadable directory to make. Said rather than
      // skipped silently: a test that quietly does nothing is the shape this file keeps recording.
      console.log("skipped: running as root, which can read a 0o000 directory");
      return;
    }
    const { dir, sites } = twoSites();
    const sealed = join(dir, "sealed");
    mkdirSync(sealed);
    writeFileSync(join(sealed, "helper.ts"), 'export const mark = "first";\n');
    chmodSync(sealed, 0o000);
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const port = started.port;
      const deadline = (): RequestInit => ({ signal: AbortSignal.timeout(20_000) });
      const refused = await fetchAt(port, "/source?site=beta", deadline());
      assert.equal(
        refused.status, 503,
        "a site whose directory could not be read was served from a stamp that cannot be complete",
      );
      // 🔑 The cause, not the cap. This is what the previous version got wrong: every enumeration
      // failure was reported as "more than 2000 entries", discarding the `errno` at the only point
      // that had it.
      const why = (await refused.json() as { error?: string }).error ?? "";
      assert.match(why, /could not be read \(EACCES\)/, `the refusal does not name the cause: ${why}`);
      assert.match(why, /sealed/, "the refusal does not name which directory could not be read");
      assert.doesNotMatch(
        why, /more than 2000 entries/,
        "an unreadable directory was reported as the scan cap being exceeded",
      );
      // The process stays up and the probe answers: a reported configuration fault, not a crashloop.
      assert.equal((await fetchAt(port, "/healthz", deadline())).status, 200, "the process went down");
    } finally {
      // Before `rmSync`, or the cleanup cannot enter it either.
      chmodSync(sealed, 0o700);
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("refuses a site whose tree is larger than the scan cap", { timeout: 60_000 }, async () => {
    // ## Three answers were tried above the cap, and the first two were worse than the defect
    //
    // The scan reads the entry module's neighbours so that breaking only a `./helper.ts` is noticed.
    // Above the cap it cannot be complete, and what to do then took three goes:
    //
    //   1. **Stamp a placeholder** (`over-400`). A constant, so the key stopped moving and the cache
    //      served its first answer forever — the exact defect the scan was added to fix.
    //   2. **Evaluate without caching**, minting a fresh `?v=` per request so the re-evaluation was
    //      real. ES modules are keyed by URL and never evicted: **7.32 KiB retained per distinct URL**
    //      measured on Node 26.4 after a forced GC, against nothing for 4,000 imports of one URL. At a
    //      poll every few seconds that is an OOM kill, and at `replicas: 1` every console goes with it.
    //   3. **Refuse**, which is this. Nothing new enters the module registry and an operator gets a
    //      reason.
    //
    // The second was found by an independent re-review, and the test it passed is why it got that far:
    // "the edit is still seen" was true and never asked what seeing it cost.
    //
    // ⚠️ **Sites that share a directory share the refusal**, which the assertions below say out loud.
    // In the fleet all three site modules live in one policy directory, so an oversized tree there is
    // not a per-site 503 — it is every console. That is the cost of refusing, and it is why the cap is
    // set far above an ordinary checkout (49 entries measured, against a cap of 2,000) and why the test
    // above exists to keep `.git` out of the count. A tree that still overflows is one somebody built.
    const { dir, sites } = twoSites();
    const filler = join(dir, "filler");
    mkdirSync(filler);
    // 🔑 **Non-source files on purpose.** The cap counts entries *visited*, not entries that match the
    // extension filter, and this fixture is what tells those apart: two thousand `.md` files overflow
    // the walk while contributing nothing to the match list. With matching files both counts overflow
    // together, a mutation swapping one for the other changed no test, and the matrix reported the line
    // as holding nothing up. A cap counted over matches is the version that let a thousand directories
    // holding one `.ts` each cost a full traversal on every request.
    for (let i = 0; i < 2_100; i += 1) writeFileSync(join(filler, `f${i}.md`), `# note ${i}\n`);
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const port = started.port;
      const deadline = (): RequestInit => ({ signal: AbortSignal.timeout(20_000) });
      const refused = await fetchAt(port, "/source?site=beta", deadline());
      assert.equal(refused.status, 503, "a site whose tree cannot be stamped was served anyway");
      const why = (await refused.json() as { error?: string }).error ?? "";
      assert.match(
        why, /more than 2000 entries beside it/,
        "the refusal does not say why, so an operator cannot act on it",
      );
      // And it names *this* cause rather than the other one. Both used to arrive as a bare `null` and
      // be reported as the cap, so a permissions fault on a four-file directory sent an operator to
      // look at a limit nowhere near being reached.
      assert.doesNotMatch(why, /could not be read/, "an overflow was reported as an unreadable directory");
      assert.equal(
        (await fetchAt(port, "/source?site=alpha", deadline())).status, 503,
        "alpha shares this directory, so it shares the refusal — if this is 200 the scan became per-site",
      );
      // What the refusal is for: the process stays up and the probe keeps answering, so this is a
      // reported configuration fault rather than a crashloop.
      assert.equal((await fetchAt(port, "/healthz", deadline())).status, 200, "the process went down");
      assert.equal((await fetchAt(port, "/source?site=beta", deadline())).status, 503, "not idempotent");
      assert.equal((await fetchAt(port, "/healthz", deadline())).status, 200, "the process went down");
      assert.match(
        started.output(), /entries beside/,
        "the refusal was never logged, so it is invisible in the journal",
      );
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("stays up when a module breaks in a way no guard had named", { timeout: 90_000 }, async () => {
    // ## Five shapes the tenth round's captures did not cover, all measured live in `origin/main`
    //
    // The captures closed globals being *replaced*. These are the same realm reached differently, and
    // each of them exited 1 rather than answering 503 for the one site whose module was wrong:
    //
    //   - `resolveService` returning a circular object or a `BigInt`: `collectPolicySource` stored the
    //     resolver's answer without passing it through the wire crossing, so it passed startup
    //     verification and threw in the renderer's serialiser on the **first request**.
    //   - a throwing `Object.prototype.toJSON`: `JSON.stringify` calls a `toJSON` it *finds on the
    //     value*, inherited included, so capturing the function closed nothing — every response threw,
    //     `/healthz` with it.
    //   - a throwing `Object.prototype.then` getter: resolving a promise with an object reads `.then`
    //     off it. `Promise.all` resolves its result array, so the throw landed outside every per-site
    //     `catch`. `origin/main` survives this with a 503 and this branch did not, which made it the
    //     one finding of the six that this branch had **introduced**.
    //   - a module's own `setTimeout` callback throwing after its import resolved: nothing from this
    //     file is on that stack, so the default action exited — **after** both probes had passed.
    //
    // What no shape may do is take the process or `/healthz` down.
    //
    // 🔑 **This paragraph used to say that poisoning a prototype breaks every module's render, "so
    // every site answering 503 is the correct answer and not a regression".** That was the in-process
    // renderer describing its own limit as the specification. Measured on `da80b7b` (before the
    // worker): `poisonedToJSON` answered alpha 503 — a site that poisoned nothing, taken down by its
    // neighbour's prototype. That is cross-site contamination, the defect AGENTS.md's table records,
    // and the old 503 was the defect. The worker gives each evaluation its own realm, so the poisoned
    // prototype ends with beta's thread; alpha now answers 200, and the row says so.
    const resolver = (body: string): string => `export const site = {
  cfg: { hookPolicy: { input: "drop", output: "accept" } },
  hosts: [{ id: "gw-01.beta", stage: "canary", items: [] }],
  workload: [{ kind: "service", value: "kube-system/coredns" }],
  resolveService() { ${body} },
};
`;
    const shapes: { name: string; body: string; beta: number; alpha: number }[] = [
      { name: "circularResolverResult", body: resolver("const hit = {}; hit.self = hit; return hit;"), beta: 503, alpha: 200 },
      { name: "bigintResolverResult", body: resolver("return { port: 1n };"), beta: 503, alpha: 200 },
      {
        name: "poisonedToJSON",
        body: 'Object.defineProperty(Object.prototype, "toJSON", { value() { throw new Error("bad serializer"); }, configurable: true });\nthrow new Error("bad beta");\n',
        // alpha was 503 before the worker (measured on `da80b7b`) — cross-site contamination. See above.
        beta: 503, alpha: 200,
      },
      {
        // ## `alpha: 200` — and that number changed when the evaluation seam landed
        //
        // It was `503`: the poisoning reached the healthy site. Promise resolution reads `.then` off
        // whatever it resolves, so resolving a `PolicySource` **object** ran the poisoned getter on
        // every site's evaluation, not just the one that poisoned it. That is the cross-site
        // contamination row in AGENTS.md's eleventh-round table, and `503` here recorded the defect
        // rather than asking for it.
        //
        // The seam serialises each evaluation and resolves the **string**, so there is no `.then` to
        // read. `beta` still fails — it threw — and `alpha` now answers `/source` normally, which is
        // the property that was wanted all along.
        //
        // ⚠️ **`/source`, not every route.** `readiness()` still resolves a plain object, so
        // `/readyz` goes 503 under this same module — the poisoning is closed on this path and open
        // on that one. An earlier version of this comment and of AGENTS.md said it was closed, full
        // stop; independent review reproduced the `/readyz` half.
        //
        // **Measured, not reasoned.** Reverting just that one line to resolve an object
        // (`resolve({ wire } as unknown as string)`) turns this back:
        //
        //     ✖ stays up when a module breaks in a way no guard had named
        //       AssertionError: poisonedThen: alpha — actual 503, expected 200
        //
        // ⚠️ `poisonedToJSON` above keeps `alpha: 503`, and the difference is the point: `toJSON` is
        // called **by the serialisation itself**, so moving to bytes cannot close it. A byte boundary
        // closes the operations that read a value; it does not close the one that writes it.
        name: "poisonedThen",
        body: 'Object.defineProperty(Object.prototype, "then", { get() { throw new Error("broken then"); }, configurable: true });\nthrow new Error("bad beta");\n',
        beta: 503, alpha: 200,
      },
      {
        // ## Serialisable and still refused — the validator is the third behaviour change
        //
        // `protectedHosts: "bad"` is a string, so it writes fine; `parsePolicySource` refuses it
        // (`src/policy-source.ts:245`). Running that validator inside the evaluation step means the
        // renderer now refuses, at the site that produced it, a payload it used to serve and let the
        // manager reject. Before this change the response was 200 with a shape the far side would not
        // accept — "healthy and unconsumable", which is the state the validator exists to prevent.
        //
        // **Pinned by a mutation** (run by the independent review, not by me): removing the
        // evaluation-time validation makes this fail —
        //
        //     ✖ stays up when a module breaks in a way no guard had named
        //       serialisableButInvalid: beta — 200 !== 503
        //
        // and with the validation in place, startup logs the validator's own error and readiness
        // reports serving **1/2**. So the shape reaches the path it names rather than passing for
        // some neighbouring reason — which is the check the removed `replacedProbeParser` shape
        // failed (#126).
        name: "serialisableButInvalid",
        body:
          'export const site = { cfg: { protectedHosts: "bad" }, hosts: [{ id: "h1.beta", stage: "canary", items: [] }] };\n',
        beta: 503, alpha: 200,
      },
      {
        name: "lateThrowFromModuleTimer",
        body:
          'setTimeout(() => { throw new Error("late config failure"); }, 400);\n' +
          'export const site = {\n' +
          '  cfg: { hookPolicy: { input: "drop", output: "accept" } },\n' +
          '  hosts: [{ id: "gw-01.beta", stage: "canary", items: [] }],\n' +
          '};\n',
        beta: 200, alpha: 200,
      },
    ];
    for (const shape of shapes) {
      const { dir, sites, beta } = twoSites();
      writeFileSync(beta, shape.body);
      let started: Started | undefined;
      try {
        started = await start(dir, MULTI(sites));
        const port = started.port;
        const deadline = (): RequestInit => ({ signal: AbortSignal.timeout(10_000) });
        assert.equal((await fetchAt(port, "/healthz", deadline())).status, 200, `${shape.name}: healthz`);
        assert.equal((await fetchAt(port, "/source?site=alpha", deadline())).status, shape.alpha, `${shape.name}: alpha`);
        assert.equal((await fetchAt(port, "/source?site=beta", deadline())).status, shape.beta, `${shape.name}: beta`);
        // The late throw fires at 400ms, so this is the assertion that shape exists for: a pod that
        // passed both probes and then died is the worst shape operationally, because it looks healthy.
        await new Promise((r) => setTimeout(r, 900));
        assert.equal((await fetchAt(port, "/healthz", deadline())).status, 200, `${shape.name}: healthz after`);
        // `/readyz` reports the swallowed fault rather than hiding it.
        const ready = (await (await fetchAt(port, "/readyz", deadline())).json()) as {
          faults?: number;
          error?: string;
        };
        // `faults` is required in **every** shape, the unserialisable fallback included. A field that
        // is present most of the time and absent under one condition gets its absence read as a zero,
        // and that condition is the one where serialisation is broken — so it must carry the count too.
        assert.equal(
          typeof ready.faults, "number",
          `${shape.name}: readiness did not report a fault count`,
        );
        // Under a poisoned `toJSON` the readiness body used to be the literal fallback, "the answer could
        // not be serialised" — the poison reached this process's own serialiser (measured on `da80b7b`).
        // It now stays in beta's worker, so readiness serialises normally and must count the outage.
        if (shape.name === "poisonedToJSON") {
          assert.equal(ready.error, undefined, `${shape.name}: the poison reached the renderer's own serialiser`);
        }
        if (shape.name === "lateThrowFromModuleTimer") {
          assert.ok((ready.faults ?? 0) > 0, `${shape.name}: the fault was swallowed silently`);
        }
      } finally {
        started?.stop();
        rmSync(join(dir, ".."), { recursive: true, force: true });
      }
    }
  });

  // ## #126 — a replaced probe parser, and what the expectation should be
  //
  // `readCoverageProbes` reads `coverage-*.json` with an **uncaptured** `JSON.parse`
  // (`src/policy-screen.ts:146`), so a module replacing the global chooses what a probe holds. A
  // `BigInt` survives collection — the row builder checks three string fields — and then the
  // whole-source serialisation throws. `beta`, the poisoning site, answers 503.
  //
  // ## 🔑 #126 is closed by the worker, and this is the test that was waiting for it
  //
  // `alpha`, which poisoned nothing, used to answer **503** as well: the module never restored the
  // global, so the healthy site's evaluation used the replaced parser too. Evaluating in a worker ends
  // it — the replacement lives in a realm that is terminated after that one site, so it cannot reach
  // `alpha`'s evaluation at all.
  //
  // ⚠️ Written as a `todo` asserting the **desired** value (`alpha: 200`), with a second test pinning
  // the 503 and named "#126 is still open" so a fix would turn it red and ask to be deleted. It did,
  // and it was. That is the whole mechanism working: the expectation was never changed to match the
  // defect, so the fix arrived as a fix rather than as a regression.
  //
  // ⚠️ The first draft had put this in the matrix above with `alpha: 503` as the expected value — the
  // shape AGENTS.md records as "관찰된 동작이 기대값이 되는 순간 — 테스트가 구멍을 봉인한다". A review
  // caught it. Had it stayed, this PR would have broken that row and looked like the regression.
  //
  // This shape was written once, observed to answer 200 for `beta`, and removed as unreproducible.
  // The renderer was right and the fixture was wrong — `twoSites` wrote no `coverage-*.json`, so the
  // replaced parser was never called. That 200 did not mean "no defect"; it meant "that code did not
  // run".
  const POISONS_PROBE_PARSER =
    'JSON.parse = () => ({ probes: [{ checkId: "c", addr: "a", at: "t", n: 1n }] });\n' +
    'export const site = { cfg: {}, hosts: [{ id: "h1.beta", stage: "canary", items: [] }] };\n';

  async function probeParserSites(): Promise<{ alpha: number; beta: number; stop: () => void; dir: string }> {
    const { dir, sites, beta } = twoSites();
    writeFileSync(beta, POISONS_PROBE_PARSER);
    const started = await start(dir, MULTI(sites));
    const at = async (site: string) =>
      (await fetchAt(started.port, `/source?site=${site}`, { signal: AbortSignal.timeout(10_000) })).status;
    // `alpha` first, because it is the question — asking it after `beta` would leave "did the order
    // matter" unanswered. Startup already evaluated both, so neither request is a first evaluation.
    const alpha = await at("alpha");
    const statusBeta = await at("beta");
    return { alpha, beta: statusBeta, stop: started.stop, dir };
  }

  it(
    "a healthy site still answers when another site's module replaces JSON.parse",
    { timeout: 30_000 },
    async () => {
      const got = await probeParserSites();
      try {
        assert.equal(got.alpha, 200, "alpha poisoned nothing and should still be served");
      } finally {
        got.stop();
        rmSync(join(got.dir, ".."), { recursive: true, force: true });
      }
    },
  );

  it("stops serving a cached answer when a file the module imports breaks", { timeout: 30_000 }, async () => {
    // ## The stamp read the entry module, not what the entry module imports
    //
    // A policy module's `import "./helper.ts"` was in none of the stamp's inputs — entry module,
    // allowlisted files, git sha — so breaking only the helper left the cache answering **200 with the
    // last good payload** for a site that no longer evaluates. Not an outage: a screen that lies about
    // what is deployed, which is what the comment above `cached` says must never happen. Measured here,
    // and confirmed in the running image by the cluster's operator, who found no `readdirSync` in it.
    //
    // A helper *outside* the module's directory is still invisible to the stamp. That is a stated gap,
    // not a claim this test covers.
    const { dir, sites, beta } = twoSites();
    const helper = join(dir, "helper.ts");
    writeFileSync(helper, 'export const mark = "first";\n');
    writeFileSync(beta, `import { mark } from "./helper.ts";
export const site = {
  cfg: { hookPolicy: { input: "drop", output: "accept" } },
  hosts: [{ id: "gw-01.beta", stage: "canary", items: [] }],
  objects: [{ id: "ao-beta", kind: "address", name: mark,
              members: [{ kind: "cidr", value: "10.0.0.0/8" }] }],
};
`);
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const port = started.port;
      assert.equal((await fetchAt(port, "/source?site=beta")).status, 200, "the good answer was not served");
      writeFileSync(helper, 'throw new Error("helper broke");\n');
      const later = new Date(Date.now() + 5_000);
      utimesSync(helper, later, later);
      assert.equal(
        (await fetchAt(port, "/source?site=beta")).status, 503,
        "a stale 200 was served for a site whose helper no longer evaluates",
      );
      assert.equal((await fetchAt(port, "/source?site=alpha")).status, 200, "alpha lost");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("survives a module that replaces the globals it will be described with", { timeout: 60_000 }, async () => {
    // ## The value was read carefully and then handed to a constructor the module owned
    //
    // `import()` evaluates a policy module in this process's own realm, so a module can assign to
    // `globalThis.Error`. Every guard in the renderer reads the thrown value defensively and then builds
    // an `Error` to carry it — which called the module's function. `asError` does that inside
    // `evaluateWithin`'s rejection handler, the one point every module failure funnels through, and a
    // throw in a rejection handler is an unhandled rejection: **exit 1 in the startup loop, before
    // `server.listen`**, so a crashloop and every co-served console dark at `replicas: 1`/`Recreate`.
    //
    // The handler's comment already described that mechanism. It did not close this door, because the
    // comment was about the thrown *value* being unreadable and this is the *constructor* being
    // replaced — the same "one of two sites" shape this file keeps recording, one abstraction up.
    //
    // Reaching a listener is the assertion in every shape. The other three are here because they are
    // the same idea through different globals, and they were already survivable — so this test is also
    // the record that they were checked rather than assumed.
    const shapes: Record<string, string> = {
      replacesError: 'globalThis.Error = function () { throw 1; };\nthrow "plain";\n',
      replacesString:
        'globalThis.String = function () { throw 1; };\nthrow { toString() { throw 1; } };\n',
      poisonsObjectPrototype:
        'Object.defineProperty(Object.prototype, "message", { get() { throw new Error("proto trap"); }, configurable: true });\nthrow Object.create(Object.prototype);\n',
      replacesSetTimeout: 'globalThis.setTimeout = function () { throw 1; };\nthrow "plain";\n',
      // `send` serialises every response and the readiness memo reads the clock, so these two reach
      // `/healthz` and `/readyz` rather than `/source`. Both are asserted below for that reason.
      replacesJson: 'globalThis.JSON = { stringify() { throw 1; }, parse() { throw 1; } };\nthrow "plain";\n',
      replacesDate: 'globalThis.Date = function () { throw 1; };\nthrow "plain";\n',
      // The budget timer builds an `Error` too, and only a module that **hangs** reaches it. Without
      // the capture this throws inside a `setTimeout` callback, which is an uncaught exception rather
      // than a rejection — still exit 1, by a third door. The budgets are lowered below so that six
      // shapes and one hang fit in the test's own deadline.
      hangsAndReplacesError:
        'globalThis.Error = function () { throw 1; };\nawait new Promise(() => {});\n',
    };
    for (const [name, body] of Object.entries(shapes)) {
      const { dir, sites, beta } = twoSites();
      writeFileSync(beta, body);
      // `HELIOPAUSE_POLICY_ALLOW_PATHS` is what makes `sourceStamp` coerce an mtime, which is one of
      // the two shared `String` calls; the fixture already writes a `policies.json` for it to find.
      // With the default budgets a hanging module would hold startup for 30s per shape.
      const env = {
        ...MULTI(sites),
        HELIOPAUSE_POLICY_ALLOW_PATHS: "policies.json",
        HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: "700",
        HELIOPAUSE_POLICY_SOURCE_BUDGET_MS: "700",
      };
      let started: Started | undefined;
      try {
        started = await start(dir, env);
        const port = started.port;
        assert.match(
          started.startupLog, /beta .*did not evaluate at startup/,
          `${name}: the failure was not reported`,
        );
        // An explicit deadline on every call. A held socket keeps the `node:test` runner alive even
        // with `{timeout}` on the test, so a run that never finishes is not a red — it is nothing.
        const deadline = () => ({ signal: AbortSignal.timeout(10_000) });
        assert.equal(
          (await fetchAt(port, "/source?site=alpha", deadline())).status, 200,
          `${name}: alpha lost`,
        );
        assert.equal(
          (await fetchAt(port, "/source?site=beta", deadline())).status, 503,
          `${name}: no 503`,
        );
        // `/healthz` needs the serialiser and nothing else; `/readyz` needs the clock as well. Alpha
        // still evaluates, so readiness is 200 and degraded rather than 503.
        assert.equal((await fetchAt(port, "/healthz", deadline())).status, 200, `${name}: healthz`);
        const ready = await fetchAt(port, "/readyz", deadline());
        assert.equal(ready.status, 200, `${name}: readyz`);
        assert.deepEqual(await readinessOf(ready), { ok: true, degraded: true, serving: 1, total: 2, faults: 0 }, name);
        // Again, immediately: the memo compares `Date.now()` to when it settled, so the clock is only
        // read on a second request inside the window. One call leaves that capture untested.
        const memoised = await fetchAt(port, "/readyz", deadline());
        assert.equal(memoised.status, 200, `${name}: memoised readyz`);
        assert.deepEqual(await readinessOf(memoised), { ok: true, degraded: true, serving: 1, total: 2, faults: 0 }, name);
        if (name === "replacesString") {
          // The second shared `String` call is inside `sourceStamp`'s `try`/`catch`, so a replaced
          // coercion throws nothing — it makes **every** mtime component `"-"`. The stamp then stops
          // moving and the cache serves whatever loaded first, which is the stale-on-error cache the
          // comment above `cached` says must not exist. So the consequence to assert is not a status
          // code: it is whether an edit to a *different*, healthy site is still seen.
          const named = async (): Promise<unknown> => {
            const r = await fetchAt(port, "/source?site=alpha", deadline());
            assert.equal(r.status, 200, "alpha lost while checking the stamp");
            return ((await r.json()) as { site?: { objects?: { name?: unknown }[] } })
              .site?.objects?.[0]?.name;
          };
          assert.equal(await named(), "alpha", "the fixture's marker is not where this test reads it");
          const alphaPath = join(dir, "alpha.ts");
          writeFileSync(alphaPath, readFileSync(alphaPath, "utf8").replace('"alpha"', '"alpha-edited"'));
          const later = new Date(Date.now() + 5_000);
          utimesSync(alphaPath, later, later);
          assert.equal(await named(), "alpha-edited", "the stamp stopped moving — a stale policy is served");
        }
      } finally {
        started?.stop();
        rmSync(join(dir, ".."), { recursive: true, force: true });
      }
    }
  });

  it("classifies without walking a prototype chain a module controls", { timeout: 30_000 }, async () => {
    // ## Two classifications, and only one of them had been fixed
    //
    // Whether the declared-name check had already passed was carried by
    // `error instanceof ZoneCheckedError`. `instanceof` walks a prototype chain, so an `Error` handed
    // back inside a revoked `Proxy.revocable` made the classification itself throw —
    // `TypeError: Cannot perform 'getPrototypeOf' on a proxy that has been revoked` — at startup,
    // before the listener existed. The round before guarded the `instanceof` inside `asError` and left
    // this one: the same fix applied to one of two sites, which is the shape this file keeps finding.
    //
    // ⚠️ **This test does not prove the membership change, and saying so matters.** Reverting the
    // classification to `instanceof ZoneCheckedError` leaves all of these green — measured. The reason
    // is that `asError` in `evaluateWithin` normalises a revoked proxy into a plain `Error` this
    // process owns *before* the classification runs, so no proxy reaches it today. The reviewer that
    // found it said as much: their reproduction was of the extracted code, with full-service
    // verification deferred.
    //
    // The change is kept anyway, because the alternative is to rely on `asError` running first on
    // every path that reaches a classification — which is the "another layer catches it" argument this
    // file distrusts everywhere else. What this test pins is the property that matters to an operator:
    // a module that hands back an error resisting inspection does not take the other zones down.
    const shapes: Record<string, string> = {
      revokedProxyAroundError:
        '(() => { const r = Proxy.revocable(new Error("wrapped"), {}); r.revoke(); return r.proxy; })()',
      prototypeTrapAroundError:
        'new Proxy(new Error("wrapped"), { getPrototypeOf() { throw new Error("trap"); } })',
    };
    for (const [name, expr] of Object.entries(shapes)) {
      const { dir, sites, beta } = twoSites();
      writeFileSync(beta, `throw ${expr};\n`);
      let started: Started | undefined;
      try {
        // Reaching a listener at all is the assertion: unguarded, `start()` throws "exited with 1".
        started = await start(dir, MULTI(sites));
        assert.match(
          started.startupLog, /beta .*did not evaluate at startup/,
          `${name}: the failure was not reported`,
        );
        assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200, `${name}: alpha lost`);
        assert.equal((await fetchAt(started.port, "/source?site=beta")).status, 503, `${name}: no 503`);
      } finally {
        started?.stop();
        rmSync(join(dir, ".."), { recursive: true, force: true });
      }
    }
  });

  it("does not blame the declared name when an unreadable error comes from past the check", { timeout: 30_000 }, async () => {
    // ## The fifth `.message` read, missed because it builds a message rather than printing one
    //
    // `ZoneCheckedError` is constructed from the failure's message, and that construction used
    // `asError(e).message`. `asError` returns an `Error` unchanged — on purpose, because the membership
    // checks key on identity — so a throwing `.message` getter survived it and threw *there*, before
    // the wrapper existed. The failure then propagated unclassified, and the startup loop reported that
    // the declared-name check had not run for a site where it had: an operator sent to edit a
    // Deployment that is correct.
    //
    // The four interpolation points were converted to `reasonOf` in the previous round; this one reads
    // the message to *build* a message, which is why it was not among them.
    //
    // The throw has to come from past the zone check, so it is `resolveService` — reached because
    // `site.workload` holds a `{kind, value}` pair — rather than the module's top level.
    const { dir, sites, beta } = twoSites();
    writeFileSync(beta, `export const site = {
  cfg: { hookPolicy: { input: "drop", output: "accept" } },
  hosts: [{ id: "gw-01.beta", stage: "canary", items: [] }],
  workload: [{ kind: "service", value: "kube-system/coredns" }],
  resolveService() {
    const e = new Error("x");
    Object.defineProperty(e, "message", { get() { throw new Error("message trap"); } });
    throw e;
  },
};
`);
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const said = started.startupLog;
      // The trap now fires in the worker, where `failureText` reads it under a guard. The property is
      // unchanged: no naming cue, and a line that still says the site failed rather than nothing.
      for (const cue of [/declared.name/i, /check did not run/i]) {
        assert.doesNotMatch(said, cue, `an unreadable content fault was blamed on the declared name:\n${said}`);
      }
      assert.match(
        said, /beta did not evaluate at startup and will answer 503 until it does: .*could not be read/,
        `the unreadable failure was not reported at all:\n${said}`,
      );
      assert.equal((await fetchAt(started.port, "/source?site=beta")).status, 503);
    } finally {
      started?.stop();
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

  it("says how many sites it can actually serve, and says nothing when asked how", async () => {
    // ## `2/2 Running` while serving nothing
    //
    // That was a real state on 2026-09-29: the pod was Ready, `/healthz` answered `{ok:true}`, and
    // all three sites were 503 because the render raced its own policy checkout. Nothing in the
    // cluster could tell that apart from a healthy pod, and a person opening the console was the
    // only repair.
    //
    // `/readyz` is that missing sentence. It is **not** wired to a probe — see the route's own
    // comment for why replicas=1 + Recreate makes wiring it a net loss of information — so this
    // asserts the value, which is the whole of what it is for.
    const { dir, sites, beta } = twoSites();
    writeFileSync(beta, "throw new Error('beta does not load');\n");
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const res = await fetchAt(started.port, "/readyz");
      // 200 with one of two, and `degraded` carrying the part the status code cannot. Refusing here
      // would let a broken `dev.ts` take prod's and util's consoles down, which is the trade the
      // startup verification already refused to make — and the test below pins the other half.
      assert.equal(res.status, 200, "one broken site made the whole renderer report unready");
      assert.deepEqual(await readinessOf(res), { ok: true, degraded: true, serving: 1, total: 2, faults: 0 });
      // Documentation, not coverage — and saying which it is matters. `deepEqual` above already
      // rejects any added key, so a leak dies there and this line is never the failure; measured by
      // injecting `names: "alpha,beta"` into the body, which fails on the line above. It is kept
      // because the property is worth stating at the point it is relied on, not because it catches
      // anything the previous line would miss.
      const body = await (await fetchAt(started.port, "/readyz")).text();
      assert.ok(!body.includes("alpha") && !body.includes("beta"), `named a site: ${body}`);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("refuses a caller without the bearer, because reaching it makes this process do work", async () => {
    // ## The assertion that was missing, and why its absence was invisible
    //
    // This route was unauthenticated on the argument that counts leak nothing. Counts do leak
    // nothing — but `currentSource` calls `sourceStamp` → `policyHead`, which runs **two synchronous
    // `execFileSync("git", …)` per site before its own cache is consulted**. A review measured
    // 42.7 ms each and held `/healthz` — this pod's *liveness* probe — above a second with thirty
    // concurrent unauthenticated requests. That is kubelet killing the container on demand, at
    // `replicas: 1` with no surge pod.
    //
    // 🔴 **And the whole suite stayed green when the gate was added**, because `fetchAt` always sends
    // `Bearer test-bearer`. Every assertion about this route was made by an authenticated caller, so
    // the unauthenticated property — the one that mattered — was never once exercised. Hence the bare
    // `fetch`: it is the only call in this file that proves anything about a caller without a token.
    const { dir, sites } = twoSites();
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const bare = await fetch(`http://127.0.0.1:${started.port}/readyz`);
      assert.equal(bare.status, 401, "an unauthenticated caller could make this process fork git");
      const wrong = await fetch(`http://127.0.0.1:${started.port}/readyz`, {
        headers: { authorization: "Bearer not-the-token" },
      });
      assert.equal(wrong.status, 401);
      // The gate is the point, but it must not have gated the answer away from a real caller.
      assert.equal((await fetchAt(started.port, "/readyz")).status, 200);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("answers from the tree as it is now, not from how it was at startup", async () => {
    // ## The property the route argues for at length and nothing checked
    //
    // Both other tests break their modules *before* `start()`, so the startup answer and the live
    // answer are identical and a snapshot frozen at boot would satisfy them. That matters because a
    // site is fixed — or broken — by a git-sync every two minutes, and an answer remembered from
    // startup would be the past wearing the present's clothes.
    //
    // The memo window is deliberately short for the same reason, so this also pins that it is a
    // window and not a lifetime: the second reading has to arrive after it lapses.
    const { dir, sites, beta } = twoSites();
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      assert.deepEqual(
        await readinessOf(await fetchAt(started.port, "/readyz")),
        { ok: true, degraded: false, serving: 2, total: 2, faults: 0 },
      );
      // Break it after the process is up, and move the mtime so the stamp changes — `utimesSync`
      // because two writes inside one millisecond are indistinguishable to the stamp.
      writeFileSync(beta, "throw new Error('beta broke after startup');\n");
      const later = new Date(Date.now() + 5_000);
      utimesSync(beta, later, later);
      await new Promise((r) => setTimeout(r, 2_100)); // the memo window, plus a margin
      assert.deepEqual(
        await readinessOf(await fetchAt(started.port, "/readyz")),
        { ok: true, degraded: true, serving: 1, total: 2, faults: 0 },
        "the answer was remembered from startup instead of read from the tree",
      );
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("reports a worker gone as soon as it exits, not when its grace ends", { timeout: 30_000 }, async () => {
    // `workers` is the number #117's cap is to be chosen from, so it has to be threads alive now. A
    // module with no open handle finishes a few ms after answering; the grace window is 1 s. Read at
    // 400 ms — after the exit, inside the grace — this was 1 before the fix (measured) and must be 0.
    //
    // ⚠️ Single site and no `/readyz` until the read that matters: a `/readyz` that has to evaluate
    // starts a worker of its own and would be counted. The startup evaluation is the only one.
    const { dir } = twoSites();
    const only = join(dir, "alpha.ts");
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(`alpha=${only}`));
      await new Promise((r) => setTimeout(r, 400));
      const ready = (await (await fetchAt(started.port, "/readyz")).json()) as { workers?: number };
      // This /readyz evaluated nothing: the startup answer is cached under an unchanged stamp.
      assert.equal(ready.workers, 0, "a worker that had exited was still counted during its grace window");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("does not count its own reclaim of a worker as a fault", { timeout: 30_000 }, async () => {
    // A module that answers correctly and keeps a handle open (`setInterval`) outlives its grace, and
    // the renderer terminates it. `terminate()` makes a worker exit **1**, and the exit handler counts a
    // non-zero exit after an answer as a late fault — so without telling the two apart, every module
    // with an open timer would raise `faults` once per evaluation, and the one signal the grace window
    // exists to carry would mean nothing. Measured: removing the distinction gives `faults: 1` here.
    //
    // ⚠️ The neighbouring "answers from the tree as it is now" does not reach this: its beta throws at
    // the top level, which is an evaluation failure and gets no grace at all.
    const { dir, sites, alpha } = twoSites();
    writeFileSync(alpha, `setInterval(() => {}, 1000);\n${readFileSync(alpha, "utf8")}`);
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200);
      await new Promise((r) => setTimeout(r, 3_100)); // the grace window, then the memo window
      const ready = (await (await fetchAt(started.port, "/readyz")).json()) as { faults?: number; serving?: number };
      assert.equal(ready.serving, 2, "alpha stopped being served when its worker was reclaimed");
      assert.equal(ready.faults, 0, "the renderer counted its own termination as the module's fault");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("shares an evaluation that outlives the memo window instead of starting a rival", { timeout: 30_000 }, async () => {
    // ## The memo could not memoise the one case it exists for
    //
    // The window was stamped when the evaluation *started*, so anything slower than the window was
    // stale the moment it settled and was served to nobody. Measured against a never-settling site:
    // a caller at +2.5s found the memo expired and began its own full five-second evaluation, so the
    // process carried two and then three concurrent evaluations — each opening with two synchronous
    // `git` calls per site — for an answer already in flight.
    //
    // An in-flight answer is now shared regardless of age; the window applies to a *settled* one,
    // which is the only kind that can be stale.
    //
    // 🔴 **Counted, not timed, and the timed version of this test was green against the bug.** With
    // a rival evaluation the second caller reaches the same `import()` specifier — same path, same
    // stamp — and Node's module loader hands back the *same* pending promise, so both finish at the
    // same instant however many callers there are. Wall-clock cannot see the duplication at all.
    // What it costs is real and is not time: another `sourceStamp` (two synchronous `git` forks per
    // site) and another trip through `currentSource`, which is what the log line below records.
    const { dir, sites, alpha } = twoSites();
    writeFileSync(alpha, `await new Promise((r) => setTimeout(r, 3000));\n${readFileSync(alpha, "utf8")}`);
    let started: Started | undefined;
    try {
      started = await start(dir, { ...MULTI(sites), HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: "10000" });
      // Move the stamp so the request path actually has an evaluation to share. Startup already
      // cached alpha, and without this both callers are cache hits and there is nothing slow in
      // flight — the first version of this test asserted against that and failed either way, which
      // is the "green against the bug" it was written to avoid, arriving from the other side.
      const later = new Date(Date.now() + 5_000);
      utimesSync(alpha, later, later);
      // Attached after `start()` resolves, so the startup verification's own evaluations — which
      // happen before "listening" is printed — are not in the count.
      // Accumulated, then matched once. Counting per `data` event would miscount if a chunk ever
      // split inside the marker — and the direction it would miscount is 2 → 1, a green run against
      // the bug, which is exactly what this test was rewritten to stop doing. Two short writes are
      // nowhere near the stream's watermark today, so this is insurance rather than a fix.
      let out = "";
      started.proc.stdout?.on("data", (b: Buffer) => { out += b.toString(); });
      const first = fetchAt(started.port, "/readyz");
      await new Promise((r) => setTimeout(r, 2_500)); // past the memo window, inside the evaluation
      const second = await fetchAt(started.port, "/readyz");
      await first;
      await new Promise((r) => setTimeout(r, 200)); // let the last line reach the pipe
      const evaluations = (out.match(/evaluated alpha /g) ?? []).length;
      assert.equal(second.status, 200);
      assert.equal(
        evaluations, 1,
        `alpha was evaluated ${evaluations} times — the second caller started its own evaluation ` +
          `instead of sharing the one already in flight`,
      );
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  // ## Why the abort below, and not just a test timeout
  //
  // Without the route's budget this does not fail, it **hangs** — and a hang in CI is a job timeout
  // with no failing test name, which reads as infrastructure rather than as this defect. A
  // `{ timeout }` on the test is not enough: measured here, it marks the test failed and the runner
  // still does not exit, because the held socket keeps the server's loop alive and `finally` never
  // reaches `stop()`. Aborting the request is what lets the failure land *and* the process end.
  it("answers even when a site module never settles", { timeout: 20_000 }, async () => {
    // ## The state this route exists to report, arriving as silence
    //
    // A policy module is attacker-reachable code that runs at import (see this file's header on the
    // C1 finding). `await new Promise(() => {})` at its top level never settles, and the first draft
    // of this route had no bound: `Promise.all` never resolved, `send` was never called, and the
    // socket stayed open. A review reproduced 80 held sockets from 40 requests, with `/healthz` green
    // throughout — "up but serving nothing" reported as a hang, which a monitor cannot tell from a
    // network fault and which is strictly less informative than the 503 the route was built to send.
    //
    // A site that cannot answer inside its budget is not serving. That is not an approximation.
    // 🔴 And it takes the process down harder at startup than at request time. Unbounded, the
    // verification loop's own `await` never returns, `server.listen` is never reached, and the
    // renderer answers *nothing* — not even `/healthz`. That is what this test found first: it failed
    // with "the renderer exited with 13 before listening", which was the bug and not the test. The
    // startup budget is lowered here only so this does not cost thirty seconds.
    const { dir, sites, beta } = twoSites();
    writeFileSync(beta, "await new Promise(() => {});\nexport const site = { cfg: {}, hosts: [] };\n");
    let started: Started | undefined;
    try {
      started = await start(dir, { ...MULTI(sites), HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: "1500" });
      const res = await fetch(`http://127.0.0.1:${started.port}/readyz`, {
        headers: { authorization: "Bearer test-bearer" },
        // Longer than the 5s per-site budget the route is supposed to honour, short enough that a
        // route which honours nothing fails here instead of outliving the suite.
        signal: AbortSignal.timeout(10_000),
      });
      assert.equal(res.status, 200, "alpha was serving, so this must be up and degraded");
      assert.deepEqual(await readinessOf(res), { ok: true, degraded: true, serving: 1, total: 2, faults: 0 });
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("reports unready only when it can serve nothing, and stays alive saying so", async () => {
    // The state the endpoint exists for. Both modules throw, so there is no policy to serve at all
    // — and `/healthz` must still answer 200, because it is this pod's **liveness** probe: a policy
    // tree that will not load does not become loadable by restarting the process, it becomes a
    // crashloop. The split between the two endpoints is the point, so it is asserted together.
    const { dir, sites, alpha, beta } = twoSites();
    writeFileSync(alpha, "throw new Error('alpha does not load');\n");
    writeFileSync(beta, "throw new Error('beta does not load');\n");
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const res = await fetchAt(started.port, "/readyz");
      assert.equal(res.status, 503, "a renderer serving nothing reported itself ready");
      assert.deepEqual(await readinessOf(res), { ok: false, degraded: true, serving: 0, total: 2, faults: 0 });
      assert.equal(
        (await fetchAt(started.port, "/healthz")).status, 200,
        "/healthz went strict — that restarts the pod for a policy fault",
      );
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("answers /source with its own sentence when a module hangs, before the manager gives up", { timeout: 30_000 }, async () => {
    // ## The route the sentence is for, and it took two tries to actually deliver it
    //
    // `/source`'s 503 carries "the policy module could not be evaluated: …", which the console shows
    // instead of an empty page — and the file says an empty page there reads as "no policy", a
    // different and much worse claim. Unbounded, a module that never settles produced exactly that
    // empty page. Bounded at the *same* number as the manager's own `AbortSignal.timeout`
    // (`HELIOPAUSE_RELAY_TIMEOUT_MS`, default 5000), the client's clock still started first and won
    // every time — measured at 5005ms against a 7s module, with this side logging afterwards to an
    // abandoned socket. The budget has to be strictly shorter, which is what `SOURCE_SITE_BUDGET_MS`
    // derives.
    //
    // 🔴 This is one of two changes in `ebba030` that deleted clean — reverting `/source` to an
    // unbounded `currentSource` left all 26 tests green. The commit that shipped it said, one
    // paragraph earlier, "a name is not a check".
    const { dir, sites, beta } = twoSites();
    writeFileSync(beta, "await new Promise(() => {});\nexport const site = { cfg: {}, hosts: [] };\n");
    let started: Started | undefined;
    try {
      started = await start(dir, { ...MULTI(sites), HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: "1000" });
      // Both numbers derived, so widening the renderer's budget or narrowing the caller's goes red
      // here rather than silently removing the margin.
      const clientAbort = ENV_BOUNDS.HELIOPAUSE_RELAY_TIMEOUT_MS.fallback;
      const budget = ENV_BOUNDS.HELIOPAUSE_POLICY_SOURCE_BUDGET_MS.fallback;
      assert.ok(budget < clientAbort, `the renderer's ${budget}ms budget is not under the caller's ${clientAbort}ms`);
      const began = Date.now();
      // The manager's default abort, applied the way `fetchPolicySource` applies it. The renderer has
      // to answer inside this or the sentence never reaches anyone.
      const res = await fetch(`http://127.0.0.1:${started.port}/source?site=beta`, {
        headers: { authorization: "Bearer test-bearer" },
        signal: AbortSignal.timeout(clientAbort),
      });
      const took = Date.now() - began;
      assert.equal(res.status, 503, "a hanging module produced something other than the 503");
      assert.match(
        String(((await res.json()) as { error?: string }).error),
        /the policy module could not be evaluated/,
        "it answered without the sentence the console shows in place of an empty page",
      );
      // ⚠️ The margin, not the fact of answering. `took < clientAbort` cannot fail: reaching this line
      // at all means `fetch` resolved, and `AbortSignal.timeout` guarantees that happened under the
      // abort — so the old assertion had no detection power and one flake mode. Halfway between the
      // budget and the abort is a threshold a 4999ms budget would miss and this one catches.
      assert.ok(
        took < (budget + clientAbort) / 2,
        `answered at ${took}ms against a ${budget}ms budget and a ${clientAbort}ms caller — the margin is gone`,
      );
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

describe("a policy module is evaluated in a worker of its own", () => {
  // The claims `src/policy-eval-worker.ts` and `evaluateInWorker` make, each driven through the real
  // renderer. The forgery shapes are §3-b ①②③ of `docs/policy-evaluation-realm-design.md`, which
  // were measured in a synthetic harness; these run them through the code that ships.
  //
  // Every forgery module posts a well-formed fake result **and then fails**. If the forgery reached
  // the parent, the parent would accept it and beta would answer 200 with the forged payload; a 503
  // is the module's own failure arriving instead. The `forged` marker is asserted absent from the
  // body as well, so a 200 that happened for some other reason cannot pass as a block.
  // The marker is inside `site`, the half the parent keeps from the worker. A top-level marker would be
  // dropped by the parent even when the forgery got through, so the absence of the marker would prove
  // nothing — the assertion has to sit where a forgery that reached the parent would be visible.
  const FORGED = `{"site":{"cfg":{},"hosts":[{"id":"h1.beta","stage":"canary","items":[],"notes":"FORGED"}]},"services":{}}`;
  const forging = (how: string) =>
    `const wt = await import("node:worker_threads");\n${how}\n` +
    `await new Promise((r) => setTimeout(r, 50));\nthrow new Error("the module failed on its own");\n`;

  const shapes: { name: string; body: string }[] = [
    {
      // ① `parentPort` is a channel the module can reach directly.
      name: "posts on parentPort",
      body: forging(`wt.parentPort.postMessage({ ok: true, wire: ${JSON.stringify(FORGED)} });`),
    },
    {
      // ② `workerData` is readable; if the port were there, the module would post on it.
      name: "posts on anything workerData holds",
      body: forging(
        `for (const v of Object.values(wt.workerData ?? {})) {\n` +
          `  if (v && typeof v.postMessage === "function") v.postMessage({ ok: true, wire: ${JSON.stringify(FORGED)} });\n` +
          `}`,
      ),
    },
    {
      // ② again: the handover message, if it were still waiting, would hand the module the port.
      name: "takes the next message on parentPort",
      body: forging(
        `wt.parentPort.once("message", (m) => m?.reply?.postMessage?.({ ok: true, wire: ${JSON.stringify(FORGED)} }));`,
      ),
    },
    {
      // ③ The send method is looked up on the prototype unless it was captured first.
      name: "rewrites MessagePort.prototype.postMessage",
      body: forging(
        `const real = wt.MessagePort.prototype.postMessage;\n` +
          `wt.MessagePort.prototype.postMessage = function () { return real.call(this, { ok: true, wire: ${JSON.stringify(FORGED)} }); };`,
      ),
    },
    {
      // ③ again, one lookup further out. The first version captured `postMessage` and called it with
      // `send.call(…)`, and `.call` is looked up on `Function.prototype` at call time — measured, a
      // complete forged payload was served with a 200. Found by an independent review.
      name: "replaces Function.prototype.call",
      body: forging(
        `const send = wt.MessagePort.prototype.postMessage;\n` +
          `const realCall = Function.prototype.call;\nconst apply = Reflect.apply;\n` +
          `Function.prototype.call = function (...args) {\n` +
          `  if (this === send) return apply(send, args[0], [{ ok: true, wire: ${JSON.stringify(FORGED)} }]);\n` +
          `  return apply(realCall, this, args);\n};`,
      ),
    },
    {
      // And the one that would replace `Reflect.apply` itself, since that is what the fix calls.
      name: "replaces Reflect.apply",
      body: forging(
        `const send = wt.MessagePort.prototype.postMessage;\nconst realApply = Reflect.apply;\n` +
          `Reflect.apply = function (f, self, args) {\n` +
          `  if (f === send) return realApply(send, self, [{ ok: true, wire: ${JSON.stringify(FORGED)} }]);\n` +
          `  return realApply(f, self, args);\n};`,
      ),
    },
  ];
  for (const shape of shapes) {
    it(`does not accept a result from a module that ${shape.name}`, { timeout: 30_000 }, async () => {
      const { dir, sites, beta } = twoSites();
      writeFileSync(beta, shape.body);
      let started: Started | undefined;
      try {
        started = await start(dir, MULTI(sites));
        const res = await fetchAt(started.port, "/source?site=beta", { signal: AbortSignal.timeout(10_000) });
        const text = await res.text();
        assert.doesNotMatch(text, /FORGED/, `${shape.name}: the forged payload reached a response`);
        assert.equal(res.status, 503, `${shape.name}: beta was served although its module failed`);
        assert.match(text, /the module failed on its own/, `${shape.name}: the 503 is not the module's own failure`);
        assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200);
      } finally {
        started?.stop();
        rmSync(join(dir, ".."), { recursive: true, force: true });
      }
    });
  }

  it("does not take anything but the module's own half from the worker", { timeout: 30_000 }, async () => {
    // ## 🔑 What the parent selects from the worker's message, with a forgery that actually arrives
    //
    // Capturing is a patch on measured routes (AGENTS.md's own words), so this test does not rely on
    // the captures failing: it uses a route that goes **through** them. `JSON.stringify` — captured —
    // still calls a `toJSON` it finds on the value, inherited ones included, so a module that defines
    // `Object.prototype.toJSON` chooses the whole serialised message without touching the send at all.
    // Found and measured by an independent review.
    //
    // The forged message carries a `site` the module chose (marked `module-chosen`) and a complete set
    // of renderer-owned fields marked `FORGED`. What must hold:
    //
    //   · it **arrives** — the `module-chosen` site is served, so the test is not passing because
    //     nothing reached the parent (the first version of this test could not tell those apart);
    //   · nothing marked `FORGED` is served — `label`, `siteName`, `build`, `head`, `repo`, `files` are
    //     read by the parent from its configuration and the checkout.
    //
    // ⚠️ The module choosing `site` is not something this test says is prevented. It is the module's to
    // say anyway — a policy commit can write those rules directly — and it is recorded as the residue
    // in `docs/policy-eval-worker-notes.md` §7.
    const { dir, sites, beta } = twoSites();
    const forged = {
      site: { cfg: {}, hosts: [{ id: "h1.beta", stage: "canary", items: [], notes: "module-chosen" }] },
      services: {},
      label: "FORGED-label", siteName: "FORGED-name", build: "FORGEDbuild0", schemaVersion: 999,
      head: { sha: "f".repeat(40), dirty: false },
      repo: { probes: [], commits: [], generation: "FORGED-generation" },
      files: { "policies.json": "FORGED-file" },
      unrelated: "FORGED-extra",
    };
    // Only the outermost object answers with the forgery; everything nested serialises normally, so
    // the module's own collection still works and the forged object is what reaches the wire.
    writeFileSync(beta, `const forged = ${JSON.stringify(forged)};
Object.defineProperty(Object.prototype, "toJSON", {
  configurable: true,
  value(key) { return key === "" && "site" in this && "services" in this ? forged : this; },
});
export const site = { cfg: {}, hosts: [{ id: "h1.beta", stage: "canary", items: [] }] };
`);
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const res = await fetchAt(started.port, "/source?site=beta", { signal: AbortSignal.timeout(10_000) });
      const text = await res.text();
      assert.equal(res.status, 200, `the forged message was not served at all, so nothing was tested:\n${text.slice(0, 300)}`);
      assert.match(text, /module-chosen/, "the forgery did not reach the parent, so nothing was tested");
      assert.doesNotMatch(text, /FORGED/, `a renderer-owned field was taken from the worker:\n${text.slice(0, 400)}`);
      const body = JSON.parse(text) as {
        label?: string; siteName?: string; schemaVersion?: number; files?: Record<string, string>;
      };
      assert.equal(body.siteName, "beta");
      assert.equal(body.label, "beta");
      assert.equal(body.schemaVersion, 1);
      assert.equal(body.files?.["policies.json"], readFileSync(join(dir, "policies.json"), "utf8"));
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("a module that spins forever fails only its own site", { timeout: 30_000 }, async () => {
    // The one hole the in-process renderer could not close: a timer cannot preempt synchronous code,
    // so `while (true) {}` at a module's top level held the whole process. A worker is terminated.
    const { dir, sites, beta } = twoSites();
    writeFileSync(beta, "while (true) {}\n");
    let started: Started | undefined;
    try {
      started = await start(dir, {
        ...MULTI(sites),
        HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: "1000",
        HELIOPAUSE_POLICY_SOURCE_BUDGET_MS: "1000",
      });
      assert.match(started.startupLog, /beta did not evaluate at startup .*did not finish within/);
      const deadline = (): RequestInit => ({ signal: AbortSignal.timeout(10_000) });
      assert.equal((await fetchAt(started.port, "/healthz", deadline())).status, 200);
      assert.equal((await fetchAt(started.port, "/source?site=alpha", deadline())).status, 200);
      assert.equal((await fetchAt(started.port, "/source?site=beta", deadline())).status, 503);
      // The answers above are the same whether or not the spinning thread was terminated — the budget
      // rejects either way. What differs is that an unterminated spin is still burning a core, so the
      // thread count is the assertion that the hole is closed and not merely answered around.
      //
      // ⚠️ Read with the readiness memo **warm**. A `/readyz` that has to re-evaluate starts beta's
      // spinning worker again, and that thread is alive at the moment the count is taken — measured:
      // 1 on a cold read, 0 on a warm one, with nothing left over. So the first read pays for the
      // evaluation and waits out its budget, and the second, inside the memo window, reports what
      // is still running without starting anything. With the budget not terminating, this reads 3.
      await fetchAt(started.port, "/readyz", deadline());
      await new Promise((r) => setTimeout(r, 1_100)); // past beta's 1 s budget, inside the 2 s memo
      const ready = (await (await fetchAt(started.port, "/readyz", deadline())).json()) as { workers?: number };
      assert.equal(ready.workers, 0, "a spinning worker was left running after its budget");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("counts a fault that arrives inside the grace window without changing the answer", { timeout: 30_000 }, async () => {
    // The grace window exists to keep what the in-process handlers gave: a module that answers and
    // then throws from a timer is counted in `faults`, and the answer it gave stands.
    const { dir, sites, alpha } = twoSites();
    writeFileSync(alpha, `setTimeout(() => { throw new Error("late"); }, 200);\n${readFileSync(alpha, "utf8")}`);
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200);
      await new Promise((r) => setTimeout(r, 2_500)); // past the 200 ms throw and the memo window
      const ready = (await (await fetchAt(started.port, "/readyz")).json()) as { faults?: number; serving?: number };
      // Exactly 1, and the number comes from `da80b7b`, not from this code: the same module run against
      // the in-process renderer reads `faults: 1`. The first version of this asserted `> 0` and a worker
      // that counted the throw twice (as `error` and then as the `exit 1` that follows it) passed.
      assert.equal(ready.faults, 1, "one late throw was not counted exactly once");
      assert.equal(ready.serving, 2, "a late fault changed the answer already given");
      assert.equal((await fetchAt(started.port, "/source?site=alpha")).status, 200);
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("a changed file the module imports is read on the next evaluation", { timeout: 30_000 }, async () => {
    // There is no `?v=` and no child-version hook any more: each evaluation has a fresh registry. This
    // is the property the hook existed for (#59) — the stamp moves and the imported data must move too.
    const { dir, sites, alpha } = twoSites();
    writeFileSync(join(dir, "helper.json"), '{"mark":"first"}\n');
    writeFileSync(
      alpha,
      `import h from "./helper.json" with { type: "json" };\n` +
        `export const site = { cfg: {}, hosts: [{ id: "h1.alpha", stage: "canary", items: [], notes: h.mark }] };\n`,
    );
    let started: Started | undefined;
    try {
      started = await start(dir, MULTI(sites));
      const first = await (await fetchAt(started.port, "/source?site=alpha")).text();
      assert.match(first, /"notes":"first"/, "the fixture did not reach the answer");
      writeFileSync(join(dir, "helper.json"), '{"mark":"second"}\n');
      const later = new Date(Date.now() + 5_000);
      utimesSync(join(dir, "helper.json"), later, later);
      const second = await (await fetchAt(started.port, "/source?site=alpha")).text();
      assert.match(second, /"notes":"second"/, "the imported file was served from an earlier evaluation");
    } finally {
      started?.stop();
      rmSync(join(dir, ".."), { recursive: true, force: true });
    }
  });
});
