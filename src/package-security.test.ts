import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

describe("published package attack surface", () => {
  it("does not import Hono or Svelte from src/", () => {
    // The workspace manager/web packages may. The published library may not — `npm install
    // heliopause` must stay at zero runtime dependencies.
    const root = resolve(import.meta.dirname);
    const files = readdirSync(root).filter((f) => f.endsWith(".ts"));
    for (const file of files) {
      const text = readFileSync(resolve(root, file), "utf8");
      assert.equal(/from ["']hono/.test(text), false, `${file} imports hono`);
      assert.equal(/from ["']@hono\//.test(text), false, `${file} imports @hono/*`);
      assert.equal(/from ["']svelte/.test(text), false, `${file} imports svelte`);
    }
  });

  it("does not ship or export the retired HTTP bearer push agent", () => {
    const root = resolve(import.meta.dirname, "..");
    const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as { files?: string[] };
    const index = readFileSync(resolve(root, "src/index.ts"), "utf8");

    assert.equal(existsSync(resolve(root, "src/agent.ts")), false);
    assert.equal(existsSync(resolve(root, "agent/heliopause-agent.py")), false);
    assert.equal(index.includes('from "./agent.ts"'), false);
    assert.equal(pkg.files?.includes("agent"), false, "the package must allowlist safe agent entry points");
    assert.ok(pkg.files?.includes("agent/heliopause-pull.py"));
    assert.ok(pkg.files?.includes("agent/heliopause-enroll.py"));
  });

  it("does not accept the Cloudflare API token through the process environment", () => {
    const root = resolve(import.meta.dirname, "..");
    const result = spawnSync(
      process.execPath,
      ["bin/heliopause-devices.ts", "missing-site.ts", "--account", "test-account"],
      {
        cwd: root,
        encoding: "utf8",
        env: { ...process.env, HELIOPAUSE_CF_TOKEN: "must-not-be-consumed", HELIOPAUSE_CF_TOKEN_FILE: "" },
      },
    );
    assert.equal(result.status, 64);
    assert.match(result.stderr, /no token file/);
    assert.equal(result.stderr.includes("must-not-be-consumed"), false);
  });

  it("drops every Linux capability from the root enrollment helper", () => {
    const root = resolve(import.meta.dirname, "..");
    const unit = readFileSync(resolve(root, "packaging/systemd/heliopause-enroll.service"), "utf8");
    assert.match(unit, /^User=root$/m);
    assert.match(unit, /^CapabilityBoundingSet=$/m);
    assert.match(unit, /^AmbientCapabilities=$/m);
    assert.match(unit, /^NoNewPrivileges=yes$/m);
  });

  it("pins third-party Actions and the manager base image to immutable digests", () => {
    const root = resolve(import.meta.dirname, "..");
    const workflows = ["ci.yml", "trusted-leaks.yml"]
      .map((name) => readFileSync(resolve(root, `.github/workflows/${name}`), "utf8"))
      .join("\n");
    const uses = [...workflows.matchAll(/^\s*-?\s*uses:\s*(\S+)/gm)].map((match) => match[1]!);
    assert.ok(uses.length > 0);
    for (const action of uses) assert.match(action, /@[0-9a-f]{40}$/);

    const dockerfile = readFileSync(resolve(root, "packaging/Dockerfile.manager"), "utf8");
    const froms = [...dockerfile.matchAll(/^FROM (\S+)/gm)].map((match) => match[1]!);
    assert.ok(froms.length >= 2, "the console build stage is missing");
    for (const image of froms) {
      assert.match(image, /^node:22-alpine@sha256:[0-9a-f]{64}$/);
    }
    // Entry points are named one by one; `bin/` wholesale would put every operator CLI — including
    // the ones that read private keys — inside the image that faces the network.
    assert.equal(
      /^COPY\s.*\sbin\/\s+\.\/bin\/$/m.test(dockerfile),
      false,
      "the image copies bin/ wholesale",
    );
  });
});

/**
 * Which entry points are in the manager image.
 *
 * ## Why this is a test and not a comment in the Dockerfile
 *
 * `heliopause-policy-render.ts` was written, reviewed, merged, built, tagged and rolled out
 * **without ever being in the image.** The `COPY` line names files one by one, so a new entry point
 * is invisible to it, and nothing downstream looks: the file was in the repository, the whole suite
 * passed, the build was green, the tag moved, flux applied it. The first sign was the pod
 * crash-looping on `Cannot find module '/opt/heliopause/bin/heliopause-policy-render.ts'`, in a
 * pod whose absence takes the policy console with it.
 *
 * ## Why it lists both halves
 *
 * Asserting only that the three known entry points are copied would pass forever while a *fourth*
 * one was forgotten — which is the failure, restated. So every file in `bin/` must be classified:
 * a new one fails this test until somebody says which side it is on. That is the whole mechanism.
 * Being made to choose is the point; the reasons below are for the reader, not for the assertion.
 */
describe("the manager image contains the entry points its deployment starts", () => {
  /** Runs inside the cluster, from this image. The deployment picks with `command:`. */
  const IN_IMAGE = [
    "heliopause-manager.ts",
    "heliopause-enrollment.ts",
    // Its own pod, holding no credential, so that a commit to the policy repository executes
    // somewhere with nothing to steal (audit C1). Absent from the image for one rollout.
    "heliopause-policy-render.ts",
  ];

  /**
   * Everything else, and why it is not in a network-facing image.
   *
   * The operator CLIs read `./pki` — an operator's own private keys — and the two host daemons run
   * under systemd on gateways, not in Kubernetes. Neither belongs in a container that answers
   * requests from the internet.
   */
  const NOT_IN_IMAGE = [
    "heliopause-approve.ts", "heliopause-coverage.ts", "heliopause-devices.ts",
    "heliopause-feed.ts", "heliopause-pki.ts", "heliopause-policy.ts",
    "heliopause-publish.ts", "heliopause-status.ts", "heliopause-ui.ts",
    "heliopause-relay.ts", "heliopause-revocation-writer.ts", "heliopause-revocations.ts",
  ];

  const root = resolve(import.meta.dirname, "..");

  it("classifies every entry point in bin/", () => {
    const present = readdirSync(resolve(root, "bin")).filter((f) => f.endsWith(".ts")).sort();
    const classified = [...IN_IMAGE, ...NOT_IN_IMAGE].sort();
    assert.deepEqual(
      present,
      classified,
      "a new entry point in bin/ — say whether the manager image runs it, then update the Dockerfile if it does",
    );
  });

  it("copies exactly the entry points that run in it", () => {
    const dockerfile = readFileSync(resolve(root, "packaging/Dockerfile.manager"), "utf8");
    // Comments out, line continuations joined, and then only `COPY`. The first version of this
    // matched `bin/heliopause-…\.ts` anywhere in the file and so counted the names in the comment
    // above the `COPY` and in the `ENTRYPOINT` below it — it would have reported an entry point as
    // shipped because somebody mentioned it. A name surviving in a comment has fooled a check in
    // this repository twice before.
    const copyLines = dockerfile
      .split("\n")
      .filter((line) => !/^\s*#/.test(line))
      .join("\n")
      .replace(/\\\n\s*/g, " ")
      .split("\n")
      .filter((line) => /^COPY\s/.test(line));
    const copied = copyLines
      .flatMap((line) => [...line.matchAll(/bin\/(heliopause-[\w-]+\.ts)/g)].map((m) => m[1]!))
      .sort();
    assert.deepEqual(
      copied,
      [...IN_IMAGE].sort(),
      "the Dockerfile's COPY list and the entry points this image runs have drifted apart",
    );
  });

  it("builds the console in a discarded stage and copies only the static files", () => {
    const dockerfile = readFileSync(resolve(root, "packaging/Dockerfile.manager"), "utf8");
    assert.match(dockerfile, /^FROM node:22-alpine@sha256:[0-9a-f]{64} AS web$/m);
    assert.match(dockerfile, /npm run build -w @heliopause\/web/);
    assert.match(dockerfile, /COPY --from=web.*packages\/web\/build/);
    const runtime = dockerfile.split(/^FROM node:22-alpine@sha256:[0-9a-f]{64}$/m).pop() ?? "";
    assert.equal(/npm ci/.test(runtime), false, "runtime stage still runs npm ci");
    assert.equal(/node_modules/.test(runtime), false, "runtime stage copies node_modules");
  });

  it("does not dockerignore files the Dockerfile copies from the context", () => {
    // The first live build of the two-stage image died here: `.dockerignore` still
    // listed `package-lock.json` from the zero-npm-install era, and `COPY package.json
    // package-lock.json ./` became "/package-lock.json": not found. A comment in
    // either file would have survived that. The check is: every context source a
    // COPY names must still be visible to the builder.
    const dockerfile = readFileSync(resolve(root, "packaging/Dockerfile.manager"), "utf8");
    const ignored = readFileSync(resolve(root, ".dockerignore"), "utf8")
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));
    const copyLines = dockerfile
      .split("\n")
      .filter((line) => !/^\s*#/.test(line))
      .join("\n")
      .replace(/\\\n\s*/g, " ")
      .split("\n")
      .filter((line) => /^COPY\s/.test(line) && !/--from=/.test(line));
    const sources = copyLines.flatMap((line) => {
      const tokens = line.replace(/^COPY\s+/, "").split(/\s+/).filter((t) => t && !t.startsWith("--"));
      return tokens.slice(0, -1);
    });
    assert.ok(sources.includes("package-lock.json"), "web stage lost its lockfile copy");
    for (const src of sources) {
      const exact = src.replace(/\/$/, "");
      assert.equal(
        ignored.includes(src) || ignored.includes(exact) || ignored.includes(`${exact}/`),
        false,
        `.dockerignore excludes ${src}, which Dockerfile.manager copies from the build context`,
      );
    }
  });
});

describe("what a worktree is given and what git is told to ignore", () => {
  // Two lists, in two files, that only work as a pair.
  //
  // `worktree.symlinkDirectories` decides what a new worktree gets as a symlink into the main tree.
  // `.gitignore` has to name each of them **without a trailing slash**, because git treats a symlink
  // as a file and `pki*/` does not match one. A name in the first and not the second is one
  // `git add -A` away from committing host-absolute paths and site material into a repository that
  // is meant to be published.
  //
  // The reverse gap is quieter and is the one that actually happened. `pki` and `pki-util` were in
  // neither list for as long as they existed, so a worktree session could not read the fleet at all:
  // `pki/` is the **dev** VPC and the manager verifies client certificates against that CA. The
  // symptom was `no client certificate and no session` — which reads as a broken client, not as a
  // missing directory, and cost an afternoon on 2026-08-18.
  //
  // Prose in both files already said they belong together. Prose is not a check.
  const root = resolve(import.meta.dirname, "..");
  const linked: string[] = JSON.parse(readFileSync(resolve(root, ".claude/settings.json"), "utf8"))
    .worktree.symlinkDirectories;
  const ignored = readFileSync(resolve(root, ".gitignore"), "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));

  it("ignores every directory a worktree gets as a symlink", () => {
    assert.ok(linked.length >= 5, `the settings list did not parse — read ${linked.length} entries`);
    for (const name of linked) {
      // A leading slash is not a misspelling. `policy` would also ignore
      // `packages/web/src/routes/policy/`, which is the Svelte console and must stay
      // tracked. `/policy` still matches the root symlink: git treats a symlink as a
      // file, so the thing that does not work is a trailing slash.
      assert.ok(
        ignored.includes(name) || ignored.includes(`/${name}`),
        `${name} is symlinked into every worktree and .gitignore does not name it without a ` +
          `trailing slash — git sees the symlink as a file and will offer it to 'git add -A'`,
      );
    }
  });

  it("gives a worktree the PKI a session needs to read the fleet", () => {
    // 🔑 Named, not derived. The check above is satisfied by an empty list, and by a list that
    // happens to omit exactly the entry whose absence is invisible: nothing fails, the fleet is
    // simply unreadable from a worktree. `pki` is the dev VPC and is the one the manager's
    // `HELIOPAUSE_CA_FILE` points at, so it is the key to `/api/site` for all three.
    for (const name of ["pki", "pki-prod", "pki-util"]) {
      assert.ok(linked.includes(name), `${name} is not linked into new worktrees`);
    }
  });
});
