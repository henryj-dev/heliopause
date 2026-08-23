/**
 * A worked site module — the one a public clone can actually run.
 *
 * ## Why this exists, and why it is not `policy/example.ts`
 *
 * `.gitignore` promised a `policy/example.ts` for a long time and there was never one, so a public
 * clone got an empty `policy/` directory, no worked example, and a test suite that quietly ran
 * fewer tests than the count in the docs. The promise was right; the path was not.
 *
 * **`policy/` cannot hold a tracked file in this repository.** Operational checkouts symlink
 * `policy` at the private policy repository (`.claude/worktree-bootstrap.md`), and git will not
 * leave a symlink standing where it has to materialise a tracked path. Measured: with `policy` a
 * symlink and `policy/example.ts` tracked, `git checkout -- policy/example.ts` **replaces the
 * symlink with a real directory and exits 0** — no warning, no error. In a live checkout that
 * silently detaches 7 MB of real policy, and the first thing anyone would notice is `npm test`
 * reporting a smaller number while still printing green. That is the exact failure the split was
 * designed to avoid, arriving through an ordinary `git pull`.
 *
 * So the example lives here, where nothing symlinks over it.
 *
 * ## What it is for
 *
 * Two audiences, one file. A contributor reading it should see the shape a site module has to have;
 * `examples/site.test.ts` renders it and asserts the properties the README claims, so a public
 * clone's `npm test` exercises the renderer end to end rather than only its unit tests.
 *
 * ## Every address here is documentation-only
 *
 * RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`) and RFC 2606 (`example.com`). CONTRIBUTING requires
 * it of tests and examples, and the leak scanner enforces the address half on every commit. If you
 * copy this file as a starting point, the first thing to change is every address in it.
 */
import { defineConfig } from "../src/config.ts";
import type { Policy } from "../src/policy.ts";
import type { PublishHost } from "../src/publish.ts";
import type { Config } from "../src/config.ts";

/** The management network this deployment administers its hosts from. Documentation range. */
const MANAGEMENT = "192.0.2.0/24";
/** Where the example's application hosts live. Documentation range. */
const INTERNAL = "198.51.100.0/24";

/**
 * `defineConfig` fills in defaults and refuses the combinations that are certainly wrong — an
 * input hook that drops with an empty baseline is the loud one, because it is a host that answers
 * nothing including the way in to fix it.
 */
export const exampleConfig: Config = defineConfig({
  tableName: "heliopause",

  /**
   * What counts as "inside" for this deployment. Egress rules render `ip daddr != <supernet>` for
   * an internet destination, so this has to be a real supernet rather than a convenience.
   */
  internalSupernet: "198.51.100.0/24",

  /**
   * Inbound closes, outbound stays open. That is the shape most fleets want: the interesting
   * decision is which ports to open, and leaving egress unrestricted keeps this example about
   * one thing.
   */
  hookPolicy: { input: "drop", output: "accept" },

  /**
   * 🔴 **The baseline is not decoration and it is not removable.**
   *
   * These render ahead of every policy rule, and a policy that would overlap them is refused with
   * a reason rather than silently neutralised. The reason is the failure this project is named
   * for: a broad deny that lands before the management path is a host nobody can reach, including
   * to undo it. `established,related` comes first of all — without it a deny drops the replies to
   * connections the host itself opened, and SSH dies mid-session while the rule looks correct.
   */
  baseline: [
    {
      desc: "management SSH — the way back in",
      proto: "tcp",
      ports: "22",
      srcCidrs: [MANAGEMENT],
    },
    {
      desc: "ICMP (path MTU discovery) — a black hole here reads as 'the app is flaky'",
      proto: "icmp",
      ports: "",
      srcCidrs: [],
    },
  ],
});

/**
 * One policy. The fields that carry meaning beyond their names:
 *
 * - `action: "allow"` with a dropping input hook is what opens a port. In an allow-only layer a
 *   `deny` renders nothing and is reported as skipped — never silently dropped, because a skipped
 *   deny is an open port.
 * - `priority` only matters once the chain default is deny, which it is here.
 * - `enabled: false` renders nothing and says so; it is not the same as deleting the entry, and
 *   the difference is visible in the plan.
 */
const publicWeb: Policy = {
  id: "example-web",
  name: "public web",
  src: { kind: "internet" },
  dst: { kind: "cidr", value: INTERNAL },
  proto: "tcp",
  ports: "80,443",
  action: "allow",
  denyMode: "drop",
  priority: 100,
  enabled: true,
  notes: "Serves example.com. Every address in this file is a documentation range.",
};

/**
 * A second policy, narrower, to show that source matters: the metrics port is open to the
 * management network and to nothing else. Written as a separate entry rather than extra ports on
 * the rule above, because "who may reach it" is the part a reviewer has to see.
 */
const metricsFromManagement: Policy = {
  id: "example-metrics",
  name: "metrics scrape",
  src: { kind: "cidr", value: MANAGEMENT },
  dst: { kind: "cidr", value: INTERNAL },
  proto: "tcp",
  ports: "9100",
  action: "allow",
  denyMode: "drop",
  priority: 200,
  enabled: true,
};

/**
 * Two hosts, and the rollout stage is the point of having two.
 *
 * `canary` applies first and has to report healthy before `general` opens. `planPublish` refuses a
 * generation with no canary — with every host in one stage the first bad ruleset reaches all of
 * them at once, which is the failure staged rollout exists to prevent.
 *
 * `srcCidrs`/`dstCidrs` are already resolved here. In a real deployment a resolver turns endpoint
 * references into addresses; this example states them directly so it runs with no inventory.
 */
export const exampleHosts: PublishHost[] = [
  {
    id: "web-01.example.com",
    stage: "canary",
    items: [
      { policy: publicWeb, srcCidrs: [], dstCidrs: [INTERNAL] },
      { policy: metricsFromManagement, srcCidrs: [MANAGEMENT], dstCidrs: [INTERNAL] },
    ],
  },
  {
    id: "web-02.example.com",
    stage: "general",
    items: [
      { policy: publicWeb, srcCidrs: [], dstCidrs: [INTERNAL] },
      { policy: metricsFromManagement, srcCidrs: [MANAGEMENT], dstCidrs: [INTERNAL] },
    ],
  },
];

/**
 * The shape `heliopause-publish` expects. A real site module exports this as `site`; the type is
 * declared in `bin/heliopause-publish.ts`, which imports from `src/`, so it is not imported here —
 * this file stays importable from a test without pulling in a CLI entry point that reads
 * `process.argv` at module load.
 */
export const exampleSite = {
  cfg: exampleConfig,
  hosts: exampleHosts,
};
