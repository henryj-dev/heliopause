// What the agent applies must mean what the plan said.
//
// ## The gap this closes
//
// `nft.ts` declares the arrangement in its own header: the decisions are made once, in
// `planHostRuleset`, and "both emitters are dumb formatters over the result". Everything downstream
// rests on that. `publish.ts` ships `renderHostRulesetJson`'s output to the fleet; the text form is
// what an operator reads in review. If they disagree, what was reviewed is not what lands.
//
// 🔴 **Nothing checked the JSON's meaning.** Measured by mutating the emitter and re-running the
// whole suite — 1,835 tests, and every one of these survived:
//
//     nft-json.ts  op "!=" → "=="                 the egress "to the internet" guard, inverted
//     nft-json.ts  payload field saddr → daddr    source match becomes a destination match
//     nft-json.ts  {drop: null} → {accept: null}  **every deny in the fleet becomes an allow**
//     nft-json.ts  payload field dport → sport    port match against the wrong end
//
// The existing checks could not have caught them. `nft.test.ts` asserts JSON structure in one place
// (a forward-chain rule *count*), the comment-parity test compares comment sets only, and the
// agent's own post-apply verification (`missing_assertions`) reads comments and addresses. A
// ruleset that accepts everything carries exactly the right comments.
//
// ## How this is not a tautology
//
// The decoder below reads **nft's JSON schema** — `{match: {op, left: {payload: {protocol, field}},
// right}}` and friends — and rebuilds a canonical form. It does not mirror `matchJson`; it is the
// other direction, written from what nft documents. So a change in the emitter that is not also a
// change in nft's schema shows up here as a disagreement with the plan.
//
// The `MATCH_KINDS` check at the bottom is what keeps that honest over time: add a `Match` variant
// and this file fails until the fixture exercises it, rather than silently covering nine of ten.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { defineConfig, type Config } from "./config.ts";
import { planHostRuleset, type EgressItem, type InputItem, type Match, type PlannedRule, type Verdict } from "./nft.ts";
import { renderHostRulesetJson } from "./nft-json.ts";
import type { Policy } from "./policy.ts";

// ── Canonical form, from the plan ─────────────────────────────────────────────

function canonicalMatch(m: Match): string {
  switch (m.kind) {
    case "saddr":
      return `saddr ${m.family} ${m.cidrs.join(",")}`;
    case "daddr":
      return `daddr ${m.family} ${m.cidrs.join(",")}`;
    case "daddr-not":
      return `daddr! ${m.family} ${m.cidr}`;
    case "saddr-not":
      return `saddr! ${m.family} ${m.cidr}`;
    case "l4proto":
      return `l4proto ${m.proto}`;
    case "dport":
      return `dport ${m.proto} ${m.ports.join(",")}`;
    case "ct-established":
      return "ct-established";
    case "ct-dnat":
      return "ct-dnat";
    case "ct-invalid":
      return "ct-invalid";
    case "iif":
      return `iif ${m.name}`;
  }
}

const canonicalRule = (r: PlannedRule) => `${r.matches.map(canonicalMatch).join(" | ")} => ${r.verdict}`;

// ── Canonical form, decoded back out of nft's JSON ────────────────────────────

type Json = Record<string, any>;

/** `{prefix: {addr, len}}` → `addr/len`; a bare string stays itself; `{set: [...]}` joins. */
function decodeAddr(right: unknown): string {
  if (typeof right === "string") return right;
  const r = right as Json;
  if (r.prefix) return `${r.prefix.addr}/${r.prefix.len}`;
  if (r.set) return (r.set as unknown[]).map(decodeAddr).join(",");
  throw new Error(`unrecognised address value: ${JSON.stringify(right)}`);
}

/** A number is a port; `{range: [lo, hi]}` is the model's `lo:hi`; `{set: [...]}` joins. */
function decodePort(right: unknown): string {
  if (typeof right === "number") return String(right);
  const r = right as Json;
  if (r.range) return `${r.range[0]}:${r.range[1]}`;
  if (r.set) return (r.set as unknown[]).map(decodePort).join(",");
  throw new Error(`unrecognised port value: ${JSON.stringify(right)}`);
}

function decodeMatch(expr: Json): string {
  const m = expr.match as Json | undefined;
  if (!m) throw new Error(`expression is not a match: ${JSON.stringify(expr)}`);
  const { op, left, right } = m;

  if (left?.payload) {
    const { protocol, field } = left.payload as { protocol: string; field: string };
    if (field === "saddr" || field === "daddr") {
      // `!=` is a different rule from `==`, and the difference is the whole meaning of the egress
      // "to the internet" guard. It is carried into the canonical form, not normalised away.
      const bang = op === "!=" ? "!" : "";
      if (op !== "==" && op !== "!=") throw new Error(`unexpected address op: ${op}`);
      return `${field}${bang} ${protocol} ${decodeAddr(right)}`;
    }
    if (field === "dport") {
      assert.equal(op, "==", "a port match is an equality");
      return `dport ${protocol} ${decodePort(right)}`;
    }
    throw new Error(`unexpected payload field: ${field}`);
  }

  if (left?.meta) {
    const key = (left.meta as { key: string }).key;
    if (key === "l4proto") return `l4proto ${right}`;
    if (key === "iif") return `iif ${right}`;
    throw new Error(`unexpected meta key: ${key}`);
  }

  if (left?.ct) {
    const key = (left.ct as { key: string }).key;
    if (key === "state" && Array.isArray(right)) {
      assert.deepEqual([...right].sort(), ["established", "related"]);
      return "ct-established";
    }
    if (key === "state" && right === "invalid") return "ct-invalid";
    if (key === "status" && right === "dnat") return "ct-dnat";
    throw new Error(`unexpected ct match: ${key} ${JSON.stringify(right)}`);
  }

  throw new Error(`unrecognised match: ${JSON.stringify(expr)}`);
}

function decodeVerdict(expr: Json): Verdict {
  if ("accept" in expr) return "accept";
  if ("drop" in expr) return "drop";
  if ("reject" in expr) {
    const r = expr.reject as null | { type?: string };
    if (r && r.type === "tcp reset") return "reject-tcp-reset";
    if (r === null) return "reject";
    throw new Error(`unrecognised reject: ${JSON.stringify(r)}`);
  }
  throw new Error(`unrecognised verdict: ${JSON.stringify(expr)}`);
}

/** Every rule the document adds, per chain, in order, as `matches => verdict`. */
function decodeRules(json: string): Record<string, string[]> {
  const doc = JSON.parse(json) as { nftables: Json[] };
  const out: Record<string, string[]> = { input: [], output: [], forward: [] };
  for (const command of doc.nftables) {
    const rule = command.add?.rule as Json | undefined;
    if (!rule) continue;
    const exprs = rule.expr as Json[];
    const verdict = decodeVerdict(exprs[exprs.length - 1]!);
    const matches = exprs.slice(0, -1).map(decodeMatch);
    (out[rule.chain as string] ??= []).push(`${matches.join(" | ")} => ${verdict}`);
  }
  return out;
}

// ── A fixture that reaches every match kind and every verdict ─────────────────

const MGMT = ["10.254.0.0/16"];

const cfg: Config = defineConfig({
  tableName: "heliopause",
  internalSupernet: "10.0.0.0/8",
  // `drop` is what puts the loopback rule (`iif`) in the plan at all.
  hookPolicy: { input: "drop", output: "accept" },
  baseline: [
    { desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: MGMT },
    // No ports: the `l4proto` form. Two source families: two rules, one per family.
    { desc: "mesh", proto: "udp", ports: "", srcCidrs: ["10.254.0.0/16", "fd10::/48"] },
    // A port list and a range together, so `set` and `range` both appear.
    { desc: "metrics", proto: "tcp", ports: "9100,9200:9300", srcCidrs: [] },
  ],
  // Gives the forward chain: ct-established, ct-dnat, ct-invalid and the saddr!/daddr! guard.
  forward: { guardInternal: true, hosts: ["^gw-"] },
});

const policy = (over: Partial<Policy> = {}): Policy => ({
  id: "p1",
  name: "test policy",
  src: { kind: "cidr", value: "10.1.0.0/16" },
  dst: { kind: "host", value: "db-01" },
  proto: "tcp",
  ports: "5432",
  action: "deny",
  denyMode: "drop",
  priority: 100,
  enabled: true,
  notes: "",
  ...over,
});

const items: InputItem[] = [
  // drop
  { policy: policy({ id: "d1" }), srcCidrs: ["10.1.0.5/32"], dstCidrs: ["10.2.0.7/32"] },
  // reject-tcp-reset
  { policy: policy({ id: "d2", denyMode: "reject" }), srcCidrs: ["10.3.0.0/16"], dstCidrs: ["10.2.0.7/32"] },
  // reject (not tcp reset — udp cannot carry an RST)
  { policy: policy({ id: "d3", proto: "udp", ports: "5353", denyMode: "reject" }), srcCidrs: [], dstCidrs: ["10.2.0.7/32"] },
  // accept, and an IPv6 pair so both families are rendered
  { policy: policy({ id: "a1", action: "allow", ports: "6443" }), srcCidrs: ["fd10::5/128"], dstCidrs: ["fd10::7/128"] },
];

// `dstCidrs: null` is the "to the internet" form — the `daddr!` guard.
const egress: EgressItem[] = [
  { policy: policy({ id: "e1", name: "smtp out", ports: "25" }), dstCidrs: null },
];

describe("the JSON the fleet applies says what the plan said", () => {
  // ⚠️ Both of these are called **inside** each `it`, not in the describe body. The decoder throws
  // on an expression it does not recognise — which is how it catches a field being renamed — and a
  // throw during collection is reported by `node --test` as a suite error with `fail 0`. This
  // repository has been bitten by a count that did not move often enough to accept that: a failure
  // has to arrive as a failed test, with the number to match.
  const planOf = () => planHostRuleset(cfg, "gw-01", items, egress);
  const decodedOf = () => decodeRules(renderHostRulesetJson(cfg, "gw-01", items, egress).json);

  for (const chain of ["input", "output", "forward"] as const) {
    it(`${chain}: every rule, in order, with its matches and its verdict`, () => {
      const plan = planOf();
      const planned = (chain === "forward" ? plan.forward ?? [] : plan[chain]).map(canonicalRule);
      assert.ok(planned.length > 0, `the fixture must produce ${chain} rules to compare`);
      assert.deepEqual(decodedOf()[chain], planned);
    });
  }

  // The count check that used to stand alone. Kept, because "the same number of rules" and "the
  // same rules" are different claims and a decoder bug could satisfy the second while losing one.
  it("adds no rule the plan does not contain, and drops none", () => {
    const plan = planOf();
    const plannedTotal = plan.input.length + plan.output.length + (plan.forward?.length ?? 0);
    const decodedTotal = Object.values(decodedOf()).reduce((n, rules) => n + rules.length, 0);
    assert.equal(decodedTotal, plannedTotal);
  });
});

// 🔴 A parity test that covers nine of ten match kinds is a parity test with a hole in it, and the
// hole is invisible — the assertions above pass just as happily. This makes the fixture's coverage
// an assertion of its own, so adding a `Match` variant fails here until it is exercised.
describe("the parity fixture reaches every shape the emitters can produce", () => {
  const plan = planHostRuleset(cfg, "gw-01", items, egress);
  const all = [...plan.input, ...plan.output, ...(plan.forward ?? [])];

  const MATCH_KINDS: ReadonlyArray<Match["kind"]> = [
    "saddr", "daddr", "daddr-not", "saddr-not", "l4proto", "dport",
    "ct-established", "ct-dnat", "ct-invalid", "iif",
  ];
  const VERDICTS: ReadonlyArray<Verdict> = ["accept", "drop", "reject", "reject-tcp-reset"];

  it("exercises every match kind", () => {
    const seen = new Set(all.flatMap((r) => r.matches.map((m) => m.kind)));
    assert.deepEqual([...MATCH_KINDS].filter((k) => !seen.has(k)), []);
  });

  it("exercises every verdict", () => {
    const seen = new Set(all.map((r) => r.verdict));
    assert.deepEqual([...VERDICTS].filter((v) => !seen.has(v)), []);
  });

  it("reaches both address families, a port set and a port range", () => {
    const canon = all.map(canonicalRule).join("\n");
    assert.match(canon, /\bip6\b/);
    assert.match(canon, / ip /);
    assert.match(canon, /dport tcp 9100,9200:9300/);
  });
});
