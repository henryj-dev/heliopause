// Emits the nft **JSON** form of a ruleset plan. This is what the agent actually applies.
//
// ── Why the artifact is JSON and not nft text ─────────────────────────────────
// The agent has to decide whether a ruleset is safe to apply, and the only safe answer comes from
// inspecting its structure. Doing that on nft text means writing a parser for nft's grammar, and
// the previous attempt — line-anchored regexes — was measured to let all of the following through:
//
//     table inet heliopause {}
//     add rule ip filter INPUT drop            ← never examined; the check only looked at
//                                                statements beginning with `table`
//     table inet heliopause {} ; flush ruleset ← `;` puts it off the line start, so `^\s*flush`
//                                                never matched
//
// JSON has no such ambiguity. Every element is an object naming its own family and table, so
// "does this touch anything but ours" is a field comparison rather than an exercise in
// out-guessing a tokeniser. The whole class of separator and quoting tricks stops existing.
//
// This is not the only defence — the agent also diffs the full ruleset after applying and reverts
// if anything outside its table moved. Structure validation is what makes that the second line
// rather than the first.

import { tableRef, type Config } from "./config.ts";
import {
  planHostRuleset,
  RenderError,
  type EgressItem,
  type InputItem,
  type Match,
  type PlannedRule,
  type RulesetPlan,
  type Verdict,
} from "./nft.ts";

/** nft's JSON is loosely typed by nature; this is a marker, not a schema. */
export type NftJsonValue = unknown;

export interface JsonRuleset {
  /** `nft -j -f` input, serialised. */
  json: string;
  ruleCount: number;
  skipped: RulesetPlan["skipped"];
  /** Rule comments the agent must find in the kernel before it confirms. */
  assertions: string[];
  /** Addresses the rules target, for the agent to check against its own interfaces. */
  expectAddrs: string[];
}

// ── Expression building ───────────────────────────────────────────────────────

/**
 * Guard against a non-number reaching the document.
 *
 * `JSON.stringify` turns `NaN` into `null`, so a bad parse here does not fail — it produces a
 * structurally valid document whose meaning is nothing. That is strictly worse than the text
 * emitter's behaviour, which at least yields something nft rejects. `planHostRuleset` validates
 * its inputs so this should be unreachable; it exists because the failure it catches is silent.
 */
function num(value: string, what: string): number {
  const n = Number(value);
  if (!Number.isInteger(n)) {
    throw new RenderError(`${what}: ${JSON.stringify(value)} is not an integer`);
  }
  return n;
}

/**
 * An address literal.
 *
 * A bare address stays a string; anything with a prefix length becomes nft's `prefix` object.
 * Passing `"10.0.0.0/8"` through as a string is accepted by nft in some positions and silently
 * misread in others, so the split is made explicitly here rather than left to nft's leniency.
 */
function addr(cidr: string): NftJsonValue {
  const slash = cidr.indexOf("/");
  if (slash === -1) return cidr;
  return {
    prefix: { addr: cidr.slice(0, slash), len: num(cidr.slice(slash + 1), "prefix length") },
  };
}

function addrValue(cidrs: string[]): NftJsonValue {
  return cidrs.length === 1 ? addr(cidrs[0]!) : { set: cidrs.map(addr) };
}

/** `"22"` becomes a number; `"9000:9100"` becomes nft's inclusive range. */
function port(spec: string): NftJsonValue {
  const colon = spec.indexOf(":");
  if (colon === -1) return num(spec, "port");
  return { range: [num(spec.slice(0, colon), "port range start"), num(spec.slice(colon + 1), "port range end")] };
}

function portValue(ports: string[]): NftJsonValue {
  return ports.length === 1 ? port(ports[0]!) : { set: ports.map(port) };
}

function payload(protocol: string, field: string): NftJsonValue {
  return { payload: { protocol, field } };
}

function matchJson(m: Match): NftJsonValue {
  switch (m.kind) {
    case "saddr":
      return { match: { op: "==", left: payload(m.family, "saddr"), right: addrValue(m.cidrs) } };
    case "daddr":
      return { match: { op: "==", left: payload(m.family, "daddr"), right: addrValue(m.cidrs) } };
    case "daddr-not":
      return { match: { op: "!=", left: payload(m.family, "daddr"), right: addr(m.cidr) } };
    case "l4proto":
      return { match: { op: "==", left: { meta: { key: "l4proto" } }, right: m.proto } };
    case "dport":
      return { match: { op: "==", left: payload(m.proto, "dport"), right: portValue(m.ports) } };
    case "ct-established":
      return {
        match: { op: "in", left: { ct: { key: "state" } }, right: ["established", "related"] },
      };
    case "iif":
      return { match: { op: "==", left: { meta: { key: "iif" } }, right: m.name } };
    case "saddr-not":
      return { match: { op: "!=", left: payload(m.family, "saddr"), right: addr(m.cidr) } };
    case "ct-dnat":
      return { match: { op: "in", left: { ct: { key: "status" } }, right: "dnat" } };
    case "ct-invalid":
      return { match: { op: "in", left: { ct: { key: "state" } }, right: "invalid" } };
  }
}

const VERDICT_JSON: Record<Verdict, NftJsonValue> = {
  accept: { accept: null },
  drop: { drop: null },
  reject: { reject: null },
  // TCP gets an RST so the client fails at once instead of waiting out a timeout.
  "reject-tcp-reset": { reject: { type: "tcp reset" } },
};

function ruleJson(cfg: Config, chain: string, r: PlannedRule): NftJsonValue {
  return {
    add: {
      rule: {
        family: "inet",
        table: cfg.tableName,
        chain,
        expr: [...r.matches.map(matchJson), VERDICT_JSON[r.verdict]],
        // Carried as a rule property rather than an expression. Comments are how a rendered rule
        // is traced back to the policy that produced it, so they are not decoration.
        comment: comment(r.comment),
      },
    },
  };
}

/**
 * nft stores comments as a bounded string.
 *
 * Control characters are stripped even though JSON would carry them safely: the comment reappears
 * in `nft list` output, in the stateless dump the drift digest is taken over, and in operator
 * terminals. A newline in any of those turns one rule into what looks like two.
 */
function comment(s: string): string {
  return s.replace(/[\r\n\t]/g, " ").slice(0, 80);
}

// ── Emitter ───────────────────────────────────────────────────────────────────

function chainJson(cfg: Config, hook: "input" | "output" | "forward"): NftJsonValue {
  return {
    add: {
      chain: {
        family: "inet",
        table: cfg.tableName,
        name: hook,
        type: "filter",
        hook,
        prio: 0,
        // The forward chain always accepts by default; only `input` and `output` are configurable.
        // See `ForwardConfig` for why forward is not a default-deny surface.
        policy: hook === "forward" ? "accept" : cfg.hookPolicy[hook],
      },
    },
  };
}

/**
 * Build the `nft -j -f` document for one host.
 *
 * The table is added, deleted, then added again. The first add is what makes the delete safe on a
 * host that has nothing yet, and the delete is what makes re-applying idempotent instead of
 * appending a second copy of every rule.
 */
export function renderHostRulesetJson(
  cfg: Config,
  host: string,
  items: InputItem[],
  egress: EgressItem[] = [],
): JsonRuleset {
  const plan = planHostRuleset(cfg, host, items, egress);
  const table = { family: "inet", name: cfg.tableName };

  const commands: NftJsonValue[] = [
    { add: { table } },
    { delete: { table } },
    { add: { table } },
    chainJson(cfg, "input"),
    chainJson(cfg, "output"),
    ...(plan.forward ? [chainJson(cfg, "forward")] : []),
    ...plan.input.map((r) => ruleJson(cfg, "input", r)),
    ...plan.output.map((r) => ruleJson(cfg, "output", r)),
    ...(plan.forward ?? []).map((r) => ruleJson(cfg, "forward", r)),
  ];

  return {
    json: JSON.stringify({ nftables: commands }, null, 2) + "\n",
    ruleCount: plan.ruleCount,
    skipped: plan.skipped,
    assertions: plan.assertions,
    expectAddrs: plan.expectAddrs,
  };
}

