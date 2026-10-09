// What each host's input chain says, and which of its rules an edit adds or removes.
//
// A preview, not a gate: nothing here refuses anything. The gates are the zone check and the
// approval path.
//
// It reads the planned ruleset (`planHostRuleset`), not the policy catalogue, because the source a
// host matches on is `srcCidrs`, which a site module computes per host — a catalogue entry can say
// one range while the host renders another.
//
// It compares the input chain's rules and its default verdict, not reachability. Removing a deny
// shows as a removed deny rule; it does not compute which addresses that leaves open, because that
// is first-match evaluation over the whole chain. @see src/preview-diff.test.ts
//
// Not visible here: an edit that only reorders rules (which changes first-match behaviour), and any
// change to the output or forward chain.

import { defineConfig, type Config } from "./config.ts";
import { planHostRuleset, type Match, type PlannedRule } from "./nft.ts";
import type { ScreenSite } from "./policy-screen.ts";

/** One input rule, reduced to what decides which packets it matches and what happens to them. */
export interface InputRule {
  verdict: string;
  /** `""` when the rule names no protocol. */
  proto: string;
  /** Port list as written; `""` when the rule names no ports. */
  ports: string;
  /** Sorted. Empty means any source. */
  sources: string[];
  /** Sorted; a `!` prefix is a negated destination. Empty means any destination. */
  destinations: string[];
  /** `"ip"`, `"ip6"`, or `""` when the rule names no address. */
  family: string;
}

export interface HostRules {
  host: string;
  /** The input chain's default verdict for whatever no rule matched. */
  inputPolicy: string;
  rules: InputRule[];
}

export interface HostDiff {
  host: string;
  /**
   * Present when the edit changes the input chain's default verdict, and always when the host is
   * added or removed — `null` is the side the host is not on.
   */
  inputPolicy?: { before: string | null; after: string | null };
  added: InputRule[];
  removed: InputRule[];
}

/** Rules the renderer adds to every chain that are not a policy: replies, invalid, DNAT, loopback. */
const INFRASTRUCTURE: ReadonlySet<Match["kind"]> = new Set(["ct-established", "ct-invalid", "ct-dnat", "iif"]);

/** The input rules of a planned ruleset, infrastructure excluded, in a form two plans can compare. */
export function inputRulesOf(input: readonly PlannedRule[]): InputRule[] {
  const out: InputRule[] = [];
  for (const rule of input) {
    if (rule.matches.some((m) => INFRASTRUCTURE.has(m.kind))) continue;
    const r: InputRule = { verdict: rule.verdict, proto: "", ports: "", sources: [], destinations: [], family: "" };
    for (const m of rule.matches) {
      switch (m.kind) {
        case "dport":
          r.proto = m.proto;
          r.ports = m.ports.join(",");
          break;
        case "l4proto":
          r.proto ||= m.proto;
          break;
        case "saddr":
          r.sources.push(...m.cidrs);
          r.family = m.family;
          break;
        case "daddr":
          r.destinations.push(...m.cidrs);
          r.family = m.family;
          break;
        case "daddr-not":
          r.destinations.push(`!${m.cidr}`);
          r.family = m.family;
          break;
        case "saddr-not":
          r.sources.push(`!${m.cidr}`);
          r.family = m.family;
          break;
      }
    }
    r.sources = [...new Set(r.sources)].sort();
    r.destinations = [...new Set(r.destinations)].sort();
    out.push(r);
  }
  return out;
}

const keyOf = (r: InputRule): string =>
  [r.verdict, r.family, r.proto, r.ports, r.sources.join(","), r.destinations.join(",")].join("|");

/** Every host's input rules for one site, as the agent would apply them. */
export function siteRules(site: ScreenSite): HostRules[] {
  const cfg: Config = defineConfig(site.cfg as Partial<Config>);
  const hosts = (site.hosts ?? []) as readonly {
    id: string;
    items?: Parameters<typeof planHostRuleset>[2];
    egress?: Parameters<typeof planHostRuleset>[3];
  }[];
  return hosts.map((h) => ({
    host: h.id,
    inputPolicy: cfg.hookPolicy.input,
    rules: inputRulesOf(planHostRuleset(cfg, h.id, h.items ?? [], h.egress ?? []).input),
  }));
}

/**
 * Per host, the rules the edited site has that the current one does not, and the reverse.
 *
 * Compared as multisets, so a duplicated rule appearing or disappearing is a change too.
 */
export function diffRules(current: readonly HostRules[], edited: readonly HostRules[]): HostDiff[] {
  const count = (rules: readonly InputRule[]) => {
    const m = new Map<string, { rule: InputRule; n: number }>();
    for (const rule of rules) {
      const k = keyOf(rule);
      const e = m.get(k);
      if (e) e.n += 1;
      else m.set(k, { rule, n: 1 });
    }
    return m;
  };
  const before = new Map(current.map((h) => [h.host, h]));
  const after = new Map(edited.map((h) => [h.host, h]));
  const out: HostDiff[] = [];
  for (const host of [...new Set([...before.keys(), ...after.keys()])].sort()) {
    const hb = before.get(host);
    const ha = after.get(host);
    const b = count(hb?.rules ?? []);
    const a = count(ha?.rules ?? []);
    const surplus = (x: typeof b, y: typeof b): InputRule[] =>
      [...x].flatMap(([k, { rule, n }]) => Array(Math.max(0, n - (y.get(k)?.n ?? 0))).fill(rule) as InputRule[]);
    const added = surplus(a, b);
    const removed = surplus(b, a);
    const policyBefore = hb?.inputPolicy ?? null;
    const policyAfter = ha?.inputPolicy ?? null;
    if (added.length || removed.length || policyBefore !== policyAfter) {
      out.push({
        host,
        ...(policyBefore !== policyAfter ? { inputPolicy: { before: policyBefore, after: policyAfter } } : {}),
        added,
        removed,
      });
    }
  }
  return out;
}
