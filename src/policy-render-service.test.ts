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
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync }
  from "node:fs";
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

  it("says the declared-name check did not run, whichever way the module failed", { timeout: 30_000 }, async () => {
    // ## The caveat, and the predicate that only covered half of what needed it
    //
    // A site whose module never evaluated was never zone-checked, and the startup block treats a
    // name/module mismatch as the fault that cannot heal itself. So the line has to say which check
    // did not run — otherwise its silence is read as a pass.
    //
    // 🔴 That caveat was selected by `why.includes("did not finish within")`, which is wrong on both
    // sides. The zone check runs **after** the import, so it is skipped by every failure at or before
    // it — and a module that *throws* is the common half, which kept the plain line and left the hole
    // open on the other path. And the string is `evaluateWithin`'s own wording, so a policy module
    // could throw that text and choose which sentence an operator reads. The condition is now
    // `error instanceof ZoneCheckedError` — a class a module cannot reach — and it is driven by
    // "does not blame the declared name when the check ran and the content failed" below.
    //
    // Both halves are driven here: one site hangs past its budget, the other throws at import, and
    // both must carry the caveat. Neither had a test at all — mutating the branch to `if (false)`
    // left every test green.
    const { dir, sites, alpha, beta } = twoSites();
    writeFileSync(alpha, "await new Promise(() => {});\nexport const site = { cfg: {}, hosts: [] };\n");
    writeFileSync(beta, "throw new Error('beta will not import');\n");
    let started: Started | undefined;
    try {
      started = await start(dir, { ...MULTI(sites), HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: "1000" });
      const said = started.startupLog;
      const caveat = /the declared-name check did not run for it/g;
      assert.equal(
        (said.match(caveat) ?? []).length, 2,
        `both failures must carry the caveat — the timeout and the throw:\n${said}`,
      );
      assert.match(said, /alpha did not evaluate at startup — the declared-name check did not run/);
      assert.match(said, /beta did not evaluate at startup — the declared-name check did not run/);
      // And it did come up, which is the other half: neither failure may be fatal.
      assert.equal((await fetchAt(started.port, "/healthz")).status, 200);
    } finally {
      started?.stop();
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
      assert.match(
        said, /alpha is the site it is declared as, but did not evaluate at startup/,
        `a content fault past the zone check was reported as a possible naming fault:\n${said}`,
      );
      assert.doesNotMatch(
        said, /alpha did not evaluate at startup — the declared-name check did not run/,
        "it blamed the declared name for a failure that happened after the name was checked",
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
      assert.match(
        said, /beta is the site it is declared as, but did not evaluate/,
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
    for (const thrown of ["null", "undefined", "42", '"a string"', "{}"]) {
      const { dir, sites, beta } = twoSites();
      writeFileSync(beta, `throw ${thrown};\n`);
      let started: Started | undefined;
      try {
        started = await start(dir, MULTI(sites));
        const said = started.startupLog;
        assert.match(said, /beta .*did not evaluate at startup/, `throw ${thrown}: no report`);
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
      assert.deepEqual(await res.json(), { ok: true, degraded: true, serving: 1, total: 2 });
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
        await (await fetchAt(started.port, "/readyz")).json(),
        { ok: true, degraded: false, serving: 2, total: 2 },
      );
      // Break it after the process is up, and move the mtime so the stamp changes — `utimesSync`
      // because two writes inside one millisecond are indistinguishable to the stamp.
      writeFileSync(beta, "throw new Error('beta broke after startup');\n");
      const later = new Date(Date.now() + 5_000);
      utimesSync(beta, later, later);
      await new Promise((r) => setTimeout(r, 2_100)); // the memo window, plus a margin
      assert.deepEqual(
        await (await fetchAt(started.port, "/readyz")).json(),
        { ok: true, degraded: true, serving: 1, total: 2 },
        "the answer was remembered from startup instead of read from the tree",
      );
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
      assert.deepEqual(await res.json(), { ok: true, degraded: true, serving: 1, total: 2 });
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
      assert.deepEqual(await res.json(), { ok: false, degraded: true, serving: 0, total: 2 });
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
