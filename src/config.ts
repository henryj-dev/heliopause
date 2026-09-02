// Deployment-specific configuration.
//
// Everything in here was a hardcoded constant in the system this was extracted from. They are
// the only things that were site-specific — the policy model, the renderer and the agent
// protocol are not. Keeping them in one place is what makes the rest reusable.

/**
 * A management path that policy must never be able to sever.
 *
 * Baseline rules are rendered **before** policy-derived rules, so they win. On top of that,
 * a policy whose match could overlap a baseline entry is rejected outright (see
 * `baselineConflict`) rather than being silently neutralised by rule order — a user who
 * writes a rule that quietly does nothing is worse off than one who gets an error.
 */
export interface BaselineRule {
  /** Shown in the rejection reason and in the rendered rule comment. */
  desc: string;
  /**
   * `icmp`/`icmpv6` carry no ports and must leave `ports` empty.
   *
   * ICMPv6 is not optional once the input hook drops by default: NDP runs over it, and without
   * neighbour discovery IPv6 on the link stops working entirely — including the path you would
   * use to undo the change.
   */
  proto: "tcp" | "udp" | "icmp" | "icmpv6";
  /** Single port (`"22"`) or an inclusive range (`"9000:9100"`). Empty for icmp/icmpv6. */
  ports: string;
  /**
   * Sources this protection applies to. **Empty means every source, in both families.**
   *
   * That difference is load-bearing under default-deny. A rule with no source renders without a
   * family qualifier and so covers IPv4 and IPv6 alike; adding a source pins it to that source's
   * family, and the other family is then subject to the chain policy. Measured, not assumed.
   */
  srcCidrs: readonly string[];
}

/** What a base chain does with a packet no rule accepted. */
export type HookPolicy = "accept" | "drop";

/**
 * What to do with routed traffic.
 *
 * Deliberately not a `HookPolicy`. `accept`/`drop` is the right shape for a chain that decides
 * about this host, where "everything not named" is a set the policy author can enumerate. Forward
 * is not that: the set includes container networking, virtual machines, and whatever the host
 * routes tomorrow, none of which appears in a policy file. A default-deny forward chain would be a
 * firewall for traffic nobody described.
 *
 * So the shape is a named guard instead — one property, one stated failure it prevents.
 */
export interface ForwardConfig {
  /**
   * Refuse to route a packet into `internalSupernet` unless it came from there.
   *
   * This is the absorbed form of what firewalld expressed as `iifname public oifname vpc reject`.
   * Addresses rather than interface names, because interface names are per-host facts that a site
   * policy has no reliable way to know, and because the property being protected is about networks:
   * the internal ranges are reachable from inside and must not become reachable from outside.
   *
   * ## What it deliberately does not do
   *
   * The chain policy stays `accept`. Traffic *out* of the internal ranges, container traffic, and
   * anything DNATed to a published port keep flowing untouched. Turning forward into default-deny
   * is a much larger change — see the note on `ForwardConfig` — and bundling it here would mean a
   * firewall retirement also silently became a routing change.
   *
   * ## The spoofing gap, stated
   *
   * A packet arriving on the public interface *claiming* an internal source address passes this
   * rule, because the rule cannot see which interface a packet arrived on. What stops it is the
   * kernel's reverse-path filter, measured strict (`net.ipv4.conf.<public-if>.rp_filter = 1`) on
   * every gateway this was written for. Interface-based rules do not need that dependency; this one
   * does, and it is recorded here rather than assumed. **If rp_filter is ever relaxed on a routing
   * host, this guard weakens with it.**
   */
  guardInternal: boolean;

  /**
   * Which hosts get the chain. Regular-expression sources matched against the host name, the same
   * shape as `protectedHosts`.
   *
   * **Not optional, and not defaulted to every host.** A site is a mix: gateways route, mail hosts
   * do not, and a Kubernetes node routes traffic that no policy file describes. Rendering this
   * everywhere would put a forward chain on the cluster node, where pod traffic is handled in eBPF
   * and the parts that are not are handled by kube-proxy — a drop rule there breaks pods, which is
   * invisible from the node's own reachability checks and from every test in this repository.
   *
   * So the blast radius is named explicitly. `["^gw-01\\."]` is the intended value: the hosts that
   * were measured to route, and that had another firewall doing this job before.
   */
  hosts: readonly string[];
}

/**
 * "On these hosts, these other tables are known and accounted for."
 *
 * Host patterns are regular-expression sources matched against the host name, the same shape as
 * `protectedHosts` and `ForwardConfig.hosts`. Table names are `family name` as nft reports them —
 * `"inet netavark"`, `"ip filter"` — because a bare name is ambiguous across families.
 */
export interface FilterAllowance {
  hosts: readonly string[];
  tables: readonly string[];
}

export interface Config {
  /**
   * nftables table name. The table is created in the `inet` family as `inet <tableName>`.
   *
   * The agent will refuse any submitted ruleset that mentions a different table, so this must
   * match the agent's `HELIOPAUSE_TABLE`.
   */
  tableName: string;

  /**
   * The address space considered "internal".
   *
   * Used to render egress rules whose destination is "the public internet": they become
   * `ip daddr != <internalSupernet>`, which cannot match internal destinations. Get this wrong
   * and an egress deny aimed at the internet will also cut internal traffic — DNS, database,
   * control plane.
   */
  internalSupernet: string;

  /** Management paths that policy cannot override. */
  baseline: readonly BaselineRule[];

  /**
   * Default verdict per hook. This is what turns the layer from deny-only into default-deny.
   *
   * The two are deliberately separate, and the asymmetry is the migration plan: **input drops,
   * output keeps accepting.** Closing inbound is the actual goal — it is what shuts 6443, 10250
   * and the rest. Closing outbound in the same change would also cut the agent's heartbeat to its
   * relay, and the heartbeat is what confirms an apply and what carries the instruction to undo
   * one. Restricting egress is a separate objective with separate risk; tying it to this one buys
   * nothing and can cost the way back.
   *
   * Both default to `accept`, so an existing config keeps rendering exactly what it rendered
   * before.
   */
  hookPolicy: { input: HookPolicy; output: HookPolicy };

  /**
   * Routed traffic — the packets this host passes through rather than terminates.
   *
   * **Null by default, and null means the forward hook is not touched at all.** That was the only
   * behaviour until 2026-08-02 and it is still the right default: a host that does not route has
   * nothing to filter here, and a host that does route is carrying somebody else's traffic, so
   * getting it wrong breaks things that are not on this host and cannot be diagnosed from it.
   *
   * ## Why it exists
   *
   * Because "heliopause is the only firewall" is false on a router until it is set.
   *
   * Measured 2026-08-02 on three gateways: firewalld's forward chain was rejecting
   * `public interface → VPC` and `public interface → wireguard`, and heliopause was not filtering
   * forward at all. Retiring firewalld there would have opened a route from the provider's shared
   * public segment into the VPC and into the mesh that carries every VPC's management traffic. The
   * hosts' `input` rules would have been untouched and correct, and the exposure would have been
   * one hop upstream of anything they could see.
   *
   * So this is not a general forward-filtering feature. It is the specific thing that has to exist
   * before another firewall can be removed from a router.
   */
  forward: ForwardConfig | null;

  /**
   * Other nftables tables allowed to filter on a host, keyed by host pattern.
   *
   * Read by the publisher into `Artifact.expectFilters`; the agent reports what it actually sees and
   * the difference becomes a problem. See that field for why this is an allowlist rather than a
   * blanket "any foreign table is wrong".
   *
   * Defaults to `[]`, which means every host expects to be alone. That is the strict default on
   * purpose: a host that quietly gained a second firewall is the case worth hearing about, and a
   * default that stayed silent would make the feature opt-in for exactly the people who do not know
   * they need it.
   */
  expectedFilters: readonly FilterAllowance[];

  /**
   * Hosts that require an explicit opt-in before any apply.
   *
   * Regular-expression sources matched against the host name. Intended for infrastructure whose
   * failure takes out more than itself — routers, gateways, DNS/DHCP servers. Applying to these
   * is refused unless the caller passes `allowProtected`, so an automated batch that forgets the
   * flag skips them instead of breaking the network it runs on.
   *
   * Note that **rollback is never gated** — blocking the way back would lock you out during the
   * exact incident you need it.
   */
  protectedHosts: readonly string[];

  /**
   * TCP port the agent listens on.
   *
   * Only used by the **push** transport, which is being retired. Under the pull transport the
   * agent listens on nothing at all — see `relay`. Kept because prod and util keep running push
   * until they are rebuilt, and a config that cannot describe them is a config that cannot
   * describe the migration.
   */
  agentPort: number;

  /** Seconds the agent waits for a confirm before rolling back the **nftables** half. */
  confirmTimeoutSec: number;

  /**
   * Workload-layer settings. `null` on a site with no cluster, and on hosts outside one.
   *
   * Null is not "render host-only and carry on": a policy naming a pod destination is the workload
   * layer's sole responsibility (evaluation rule 8), so with this unset such a policy has nowhere to
   * go. The publisher refuses it rather than quietly dropping to the host half.
   */
  workload: WorkloadConfig | null;

  /** Where rendered artifacts land, and where the relay serves them from. */
  artifactStore: ArtifactStore;

  /**
   * Pull-transport settings. `null` disables it — the host is driven by push instead.
   *
   * Both transports can coexist across a fleet during migration, but not on a single host: two
   * things arming rollback timers against one ruleset would race.
   */
  relay: RelayConfig | null;

  /** Mutual-TLS material for the pull transport. `null` only when `relay` is also null. */
  tls: TlsConfig | null;
}

/**
 * The workload layer — which node applies CiliumNetworkPolicy, and what that cluster can express.
 */
export interface WorkloadConfig {
  /** Cluster identifier. Goes into CRD names so two clusters' objects never collide. */
  cluster: string;
  /**
   * Host id of the node that applies the CRDs (H17).
   *
   * One node, not "whichever gets there first": CiliumNetworkPolicy is cluster-scoped, so several
   * agents writing one object means API contention and flapping. Must be a host the publisher is
   * publishing for, or the assignment names nobody.
   */
  applier: string;
  /**
   * Cilium's minor version, as `[major, minor]`.
   *
   * Not defaulted, because one rendering decision turns on it and both guesses fail: Cilium refuses
   * `toServices` combined with `toPorts` before 1.17, so guessing high produces a CRD rejected at
   * apply (where the error no longer names the policy) and guessing low silently drops the port
   * condition from every such rule. Read it off the cluster:
   *
   *     kubectl -n kube-system get ds cilium \
   *       -o jsonpath='{.spec.template.spec.containers[0].image}'
   */
  ciliumVersion: readonly [number, number];
  /**
   * Namespaces the applier holds a RoleBinding in — `HELIOPAUSE_K8S_NAMESPACES` on that node.
   *
   * Optional, and its absence changes nothing about what renders. Given, it moves two refusals from
   * the applier to the publisher: an object addressed outside the list is refused while the policy
   * id is still in hand, and a workload-to-workload allow whose destination lives outside it renders
   * the sender's half alone instead of a document the agent throws away whole. See
   * `CiliumRenderInput.applierNamespaces` for why the second one is what makes a closed egress
   * posture expressible at all.
   *
   * It is a *copy* of the node's environment, not the source of it, so it can be wrong in the
   * harmless direction (listing fewer namespaces than the node allows) and in the loud one (listing
   * more — the agent still refuses, exactly as before this field existed).
   */
  applierNamespaces?: readonly string[];
  /**
   * Seconds before the workload half rolls back (H20). Longer than `confirmTimeoutSec` by design.
   *
   * The two layers fail differently. A bad nftables ruleset takes SSH and the relay with it, so that
   * timer is short. A bad CiliumNetworkPolicy breaks app traffic but leaves node access up, and
   * Cilium needs time to converge — identity cache and eBPF maps do not settle the moment the API
   * server returns 200. Reusing the 60s host figure would roll back healthy policy mid-convergence.
   */
  confirmTimeoutSec: number;
}

// ## `PolicyStore` was removed here (2026-08-05)
//
// It declared `{ repo, ref, path }` — "the source of truth for policy" — and **nothing read it.**
// Three site configs set it, `config.test.ts` asserted its default, and no code path consulted any
// of the three fields. `heliopause-publish` parsed no matching flag either, while two of its error
// messages told the operator to "point --policyStore at it": advice that could not be followed.
//
// Unused would have been merely wasteful. It had become **wrong**: `repo: null` documents itself as
// "policy lives in this repository" and `path` as a subdirectory, and once policy moved to its own
// repository both statements were false in every config that carried them.
//
// The capability it described is real and already works, by a different mechanism — `generationId`
// runs every `git` call against `dirname(sitePath)`, so publishing from inside the policy repository
// makes the generation id that repository's HEAD. There was nothing to configure, only somewhere to
// stand. A field that names a real need while doing nothing about it is worse than its absence: it
// answers the question that would otherwise get asked.

export interface ArtifactStore {
  /**
   * Directory the manager writes renders to and the relay serves from.
   *
   * Artifacts are derived — they can always be re-rendered from a commit — so this does not need
   * to be durable, and losing it costs a re-render rather than a recovery.
   */
  dir: string;
}

export interface RelayConfig {
  /** Base URL of the relay on this host's own gateway. */
  url: string;

  /**
   * Seconds between heartbeats.
   *
   * This sets how long a change waits before it starts, and how quickly a lockout is detected.
   * It is bounded against `confirmTimeoutSec` at construction — see `defineConfig`.
   */
  heartbeatIntervalSec: number;
}

/**
 * Mutual TLS between agent and relay.
 *
 * Both directions authenticate: the relay must know which host is reporting, and the agent must
 * know it is not being fed a ruleset by something impersonating its gateway. One-way TLS would
 * secure the second half only, and the second half is not the dangerous one.
 */
export interface TlsConfig {
  certFile: string;
  keyFile: string;

  /**
   * Trust anchor used to verify the relay. **Required** — there is no unverified mode.
   *
   * A self-signed relay certificate is its own anchor: point this at that certificate and the
   * normal verification path applies to it. That is why "no CA" is not a separate case here —
   * treating it as one would mean disabling verification and re-implementing it by hand, at the
   * exact boundary where a hand-rolled check is most expensive to get wrong.
   */
  caFile: string;

  /**
   * Optional extra constraint on the relay: base64 SHA-256 of its certificate in DER form.
   *
   * Empty accepts any certificate the anchor vouches for, which is what you want with a private
   * CA. Pin when the anchor is broad enough to sign things that are not this relay.
   *
   * These are **certificate** digests, not public-key digests — renewal changes them even if the
   * key is reused, so a pinned deployment has to update pins as part of renewal.
   */
  pins: readonly string[];
}

/**
 * Pull-agent receiver floor. Its timer starts before the kernel transaction, so the window covers
 * two bounded nft operations (apply + verified snapshot), an immediate confirmation request, and
 * one failed request followed by the agent's bounded retry. Keep this aligned with
 * `NFT_CONFIRM_MIN_SEC` in agent/heliopause-pull.py.
 */
export const MIN_PULL_CONFIRM_TIMEOUT_SEC = 90;

export const DEFAULT_CONFIG: Config = {
  tableName: "heliopause",
  internalSupernet: "10.0.0.0/8",
  baseline: [],
  hookPolicy: { input: "accept", output: "accept" },
  forward: null,
  expectedFilters: [],
  protectedHosts: [],
  agentPort: 8099,
  confirmTimeoutSec: MIN_PULL_CONFIRM_TIMEOUT_SEC,
  artifactStore: { dir: ".heliopause/artifacts" },
  relay: null,
  tls: null,
  // Null by default, like `relay`. A site with no cluster should not have to say so, and there is no
  // safe guess for the applier or the Cilium version — see `WorkloadConfig`.
  workload: null,
};

/**
 * Build a config, filling anything unset from the defaults.
 *
 * `baseline` defaults to **empty**, which means no management path is protected. That is
 * deliberate — there is no safe guess for which port your access arrives on, and a wrong guess
 * is worse than none. Set it before you enable anything that denies broadly.
 */
export function defineConfig(partial: Partial<Config> = {}): Config {
  const cfg = { ...DEFAULT_CONFIG, ...partial };
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(cfg.tableName)) {
    throw new Error(
      `tableName must be a valid nftables identifier (letters, digits, underscore; not starting with a digit) — got "${cfg.tableName}"`,
    );
  }
  if (cfg.agentPort < 1 || cfg.agentPort > 65535) {
    throw new Error(`agentPort out of range: ${cfg.agentPort}`);
  }
  if (cfg.hookPolicy.input === "drop" && cfg.baseline.length === 0) {
    // The one configuration that is certainly wrong. A dropping input hook with nothing to accept
    // first is a host that answers nothing — including the way in to fix it. There is no useful
    // default to fill in here either, because the right answer depends on how *you* reach the box.
    throw new Error(
      "hookPolicy.input is 'drop' with an empty baseline — this locks every host out of itself. " +
        "Define the management paths in `baseline` first.",
    );
  }
  if (cfg.relay) {
    // The confirm window has to be long enough for a heartbeat to land in it — the heartbeat is
    // what confirms. Set it too tight and every apply rolls back on schedule no matter how
    // healthy the host is, which reads as "heliopause is broken" rather than "this number is
    // wrong". Two intervals leaves room for exactly one lost beat.
    const floor = Math.max(
      MIN_PULL_CONFIRM_TIMEOUT_SEC,
      cfg.relay.heartbeatIntervalSec * 2,
    );
    if (cfg.relay.heartbeatIntervalSec < 1) {
      throw new Error(
        `relay.heartbeatIntervalSec must be at least 1 — got ${cfg.relay.heartbeatIntervalSec}`,
      );
    }
    if (cfg.confirmTimeoutSec < floor) {
      throw new Error(
        `confirmTimeoutSec (${cfg.confirmTimeoutSec}s) must be at least ${floor}s: the greater of ` +
          `the pull agent's ${MIN_PULL_CONFIRM_TIMEOUT_SEC}s bounded apply/HTTP safety floor and twice ` +
          `relay.heartbeatIntervalSec (${cfg.relay.heartbeatIntervalSec}s) — otherwise the rollback ` +
          `timer can fire before a healthy apply is confirmed`,
      );
    }
    if (!cfg.tls) {
      throw new Error("relay requires tls — the pull transport is mutually authenticated");
    }
  }
  if (cfg.workload) {
    const w = cfg.workload;
    if (!w.cluster) throw new Error("workload.cluster is empty — CRD names are derived from it");
    if (!w.applier) {
      throw new Error(
        "workload.applier is empty — CiliumNetworkPolicy is cluster-scoped and needs one designated " +
          "node to apply it, or every node's agent writes the same object",
      );
    }
    const [maj, min] = w.ciliumVersion ?? [];
    if (!Number.isInteger(maj) || !Number.isInteger(min) || maj! < 1 || min! < 0) {
      throw new Error(
        `workload.ciliumVersion must be [major, minor] integers — got ${JSON.stringify(w.ciliumVersion)}. ` +
          "Whether toServices may carry toPorts depends on it (1.16 refuses, 1.17 allows), and both " +
          "guesses fail: one is rejected at apply, the other silently drops the port condition. Read " +
          "it with: kubectl -n kube-system get ds cilium " +
          "-o jsonpath='{.spec.template.spec.containers[0].image}'",
      );
    }
    if (w.applierNamespaces) {
      const seen = new Set<string>();
      for (const ns of w.applierNamespaces) {
        if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(ns)) {
          throw new Error(
            `workload.applierNamespaces contains ${JSON.stringify(ns)}, which is not a lowercase ` +
              "DNS-1123 label — it cannot name a Kubernetes namespace, so every check against it " +
              "would refuse an object that is in fact fine",
          );
        }
        if (seen.has(ns)) throw new Error(`workload.applierNamespaces lists ${JSON.stringify(ns)} twice`);
        seen.add(ns);
      }
      if (seen.size === 0) {
        // An empty array is not "no restriction" — it would refuse every workload object, which is
        // the opposite of what omitting the field means. Say so rather than render nothing.
        throw new Error(
          "workload.applierNamespaces is empty — that would refuse every workload object. Omit the " +
            "field to render without the check, or list the namespaces the applier can write to",
        );
      }
    }
    // The workload timer has to clear the host timer, not merely be positive. Cilium converges after
    // the API server returns, so a window at or below the nftables figure rolls back policy that was
    // on its way to healthy — and the rollback then reads as "the policy was bad".
    if (w.confirmTimeoutSec <= cfg.confirmTimeoutSec) {
      throw new Error(
        `workload.confirmTimeoutSec (${w.confirmTimeoutSec}s) must exceed confirmTimeoutSec ` +
          `(${cfg.confirmTimeoutSec}s) — the workload layer needs longer, because Cilium's identity ` +
          `cache and eBPF maps converge after the apply returns, and a shorter window rolls back ` +
          `healthy policy mid-convergence (H20)`,
      );
    }
  }
  if (cfg.tls && !cfg.tls.caFile) {
    // Without an anchor TLS degrades to encryption against an unverified peer — which is
    // precisely the attacker who would like to hand this host a ruleset.
    throw new Error("tls.caFile is required — a self-signed relay certificate is its own anchor");
  }
  return cfg;
}

/** `inet <tableName>` — the form used in every nft statement. */
export function tableRef(cfg: Config): string {
  return `inet ${cfg.tableName}`;
}

/** Does this host require an explicit opt-in to apply? */
export function isProtectedHost(cfg: Config, host: string): boolean {
  return cfg.protectedHosts.some((p) => new RegExp(p).test(host));
}
