// The generation id has to identify the rules it names.
//
// Everything downstream keys off it by design — the audit trail is "check out that commit and look".
// So an id that does not describe what was published does not merely lose information, it asserts
// something false, and nothing downstream can tell.
//
// These run the real CLI against throwaway repositories rather than testing a function in isolation,
// because both defects being pinned lived in the wiring: which directory git was asked about, and
// whether the policy file was in version control at all. A unit test of `generationId` would have
// passed throughout.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(fileURLToPath(import.meta.url), "../..");
const CLI = join(REPO, "bin/heliopause-publish.ts");

const git = (dir: string, ...a: string[]) =>
  execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: "pipe" });

/** A minimal site module that renders without needing anything from this repository's policy/. */
const SITE = `
import { defineConfig } from ${JSON.stringify(join(REPO, "src/config.ts"))};
import type { Policy } from ${JSON.stringify(join(REPO, "src/policy.ts"))};

export const site = {
  cfg: defineConfig({
    baseline: [{ desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: ["10.0.0.0/8"] }],
  }),
  hosts: [
    {
      id: "h-a",
      stage: "canary" as const,
      items: [
        {
          policy: {
            id: "P1", name: "test",
            src: { kind: "cidr", value: "10.1.0.0/16" },
            dst: { kind: "host", value: "h-a" },
            proto: "tcp", ports: "5432", action: "allow", denyMode: "drop",
            priority: 100, enabled: true, notes: "",
          } as Policy,
          dstCidrs: ["10.0.0.1"],
        },
      ],
    },
  ],
};
`;

/** A git repository holding a site module, optionally ignored. Returns its path. */
function siteRepo(opts: { ignored?: boolean } = {}): string {
  const dir = mkdtempSync(join(tmpdir(), "hp-cli-"));
  git(dir, "init", "-q");
  writeFileSync(join(dir, "site.ts"), SITE);
  if (opts.ignored) {
    writeFileSync(join(dir, ".gitignore"), "site.ts\n");
    git(dir, "add", ".gitignore");
  } else {
    git(dir, "add", "site.ts");
  }
  git(dir, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "policy");
  return dir;
}

/** Run the CLI. Returns combined output and whether it exited non-zero. */
function publish(siteDir: string, ...extra: string[]): { out: string; failed: boolean } {
  const out = join(siteDir, "artifacts");
  try {
    return {
      out: execFileSync("node", [CLI, join(siteDir, "site.ts"), out, "--dry-run", ...extra], {
        encoding: "utf8",
        stdio: "pipe",
        // Deliberately *not* the site's directory: the CLI must not depend on where it was invoked.
        cwd: REPO,
      }),
      failed: false,
    };
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string };
    return { out: `${err.stdout ?? ""}${err.stderr ?? ""}`, failed: true };
  }
}

describe("heliopause-publish — the generation id", () => {
  it("takes the id from the policy's repository, not the working directory", () => {
    // The org-clone model: library public, site policy in its own private repository. Run from the
    // library with the site elsewhere, the id used to describe the library's HEAD — a commit that
    // says nothing about the rules being shipped.
    const dir = siteRepo();
    try {
      const { out, failed } = publish(dir);
      assert.equal(failed, false, out);
      const id = /generation (\S+)/.exec(out)?.[1];
      assert.ok(id, `no generation line in:\n${out}`);
      assert.equal(id, git(dir, "rev-parse", "--short", "HEAD").trim());
      assert.notEqual(id, git(REPO, "rev-parse", "--short", "HEAD").trim());
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a site module its repository ignores", () => {
    // The regression that arrived with moving site policy out of version control: `git status` says
    // nothing about ignored files, so edits to the published policy left the tree reading clean and
    // two publishes claimed one id while shipping different rules.
    const dir = siteRepo({ ignored: true });
    try {
      const { out, failed } = publish(dir);
      assert.equal(failed, true, `expected a refusal, got:\n${out}`);
      assert.match(out, /is ignored by its repository/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("marks the id when --allow-dirty waives that refusal", () => {
    // The escape hatch has to leave evidence. Without the suffix the id is indistinguishable from a
    // reproducible one, which is the whole property being given up.
    const dir = siteRepo({ ignored: true });
    try {
      const { out, failed } = publish(dir, "--allow-dirty");
      assert.equal(failed, false, out);
      assert.match(out, /generation \S+-dirty/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("gives two different ignored policies two different ids", () => {
    // ## The regression this exists for
    //
    // The suffix used to be the literal string `-dirty`, so the id was `${head}-dirty` no matter what
    // the policy said. In the documented operating model — the library public, `policy/` ignored —
    // `ignored` is permanently true and no policy edit moves HEAD, so *every* publish claimed one id.
    //
    // The agent skips an artifact whose generation it has already confirmed:
    //
    //     if wanted == st["generation"] and st["state"] == "confirmed": return
    //
    // So changed rules were accepted by the relay, reported as `confirmed` by every host, and never
    // applied. Measured on the live dev VPC: the fleet was running `8b59baf-dirty` and a publish that
    // added two hosts and opened a public port produced `8b59baf-dirty`.
    //
    // A firewall that reports the new rules as live while the kernel runs the old ones is worse than
    // one that fails, so this is a correctness test rather than a hygiene one.
    const dir = siteRepo({ ignored: true });
    try {
      const first = publish(dir, "--allow-dirty");
      assert.equal(first.failed, false, first.out);

      // A real change to the ignored policy: management narrowed to a different range.
      writeFileSync(join(dir, "site.ts"), SITE.replace('"10.0.0.0/8"', '"10.1.0.0/16"'));
      const second = publish(dir, "--allow-dirty");
      assert.equal(second.failed, false, second.out);

      const idOf = (out: string): string => {
        const m = /generation (\S+)/.exec(out);
        assert.ok(m, `no generation in:\n${out}`);
        return m[1]!;
      };
      assert.notEqual(
        idOf(first.out),
        idOf(second.out),
        "two different rulesets published under one id — agents would skip the second",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("gives one unchanged ignored policy one stable id", () => {
    // The other half. If the suffix moved on every invocation, a re-publish of identical policy would
    // look like a new generation and every host would re-apply a ruleset it is already running —
    // churn on the one operation that can cut the path used to fix it.
    const dir = siteRepo({ ignored: true });
    try {
      const a = publish(dir, "--allow-dirty");
      const b = publish(dir, "--allow-dirty");
      const idOf = (out: string): string => /generation (\S+)/.exec(out)![1]!;
      assert.equal(idOf(a.out), idOf(b.out));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses uncommitted changes to a tracked site module", () => {
    // The original check, still working. Kept because the fix above rewrote the function around it.
    const dir = siteRepo();
    try {
      appendFileSync(join(dir, "site.ts"), "\n// edited\n");
      const { out, failed } = publish(dir);
      assert.equal(failed, true, `expected a refusal, got:\n${out}`);
      assert.match(out, /uncommitted changes/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("publishes from a directory with no repository at all when --allow-dirty is given", () => {
    // `rollback-test.sh` builds a site module in a temporary directory on purpose — the thing under
    // test there is the kernel, not the audit trail. Refusing here anyway made `--allow-dirty` mean
    // different things in two situations that differ only in degree: a tree with uncommitted edits
    // versus one with no history to be uncommitted against.
    const dir = mkdtempSync(join(tmpdir(), "hp-nogit-"));
    writeFileSync(join(dir, "site.ts"), SITE);
    try {
      const { out, failed } = publish(dir, "--allow-dirty");
      assert.equal(failed, false, out);
      // Timestamped, so two throwaway publishes never claim one id. It cannot identify content —
      // nothing without a repository can — but it can stop two rulesets being indistinguishable.
      assert.match(out, /generation no-git-\d+/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("still refuses a directory with no repository when --allow-dirty is not given", () => {
    // The flag is the whole difference. Without it the id would silently describe nothing.
    const dir = mkdtempSync(join(tmpdir(), "hp-nogit-"));
    writeFileSync(join(dir, "site.ts"), SITE);
    try {
      const { out, failed } = publish(dir);
      assert.equal(failed, true, `expected a refusal, got:\n${out}`);
      assert.match(out, /not inside a git repository/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not refuse over unrelated ignored files", () => {
    // `status --ignored` was the first fix and it was wrong: it also refuses over node_modules/ and
    // pki/, which are ignored in every real checkout. A check that always fails is a blocker.
    const dir = siteRepo();
    try {
      writeFileSync(join(dir, ".gitignore"), "junk/\n");
      git(dir, "add", ".gitignore");
      git(dir, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "ignore junk");
      execFileSync("mkdir", ["-p", join(dir, "junk")]);
      writeFileSync(join(dir, "junk/x"), "x");
      const { out, failed } = publish(dir);
      assert.equal(failed, false, `an ignored directory must not block publishing:\n${out}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
