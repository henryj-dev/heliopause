// Renders policies into an `nft -f` ruleset. Pure — no I/O, no environment.
//
// ── Two modes, chosen per hook ────────────────────────────────────────────────
// `hookPolicy` decides what a chain does with a packet no rule matched.
//
//   accept (default)  Only explicit denies are rendered. Composes with whatever else is on the
//                     host — `drop` is terminal but `accept` is chain-local, so this layer can
//                     coexist with firewalld without either one having to know about the other.
//                     `allow` policies are no-ops here and are reported as skipped.
//   drop              Default-deny. `allow` policies become real rules and anything unlisted is
//                     refused. This is the configuration that closes ports, and the one that
//                     locks you out if the baseline is wrong.
//
// The intended migration is asymmetric — **input drops, output keeps accepting**. Closing inbound
// is the goal; closing outbound in the same change would cut the agent's heartbeat, which is what
// confirms an apply and what carries the instruction to undo one.
//
// ── Safety invariants ─────────────────────────────────────────────────────────
//   · Only ever touches its own table. firewalld / existing iptables rules are untouched.
//   · Creates `input` and `output` hooks only. `forward` is never touched, so routed traffic
//     and container/VM networking are unaffected.
//   · Baseline rules render before policy rules, and a policy that could overlap one is
//     rejected with a reason (see `baselineConflict`).
//   · `ct state established,related accept` is the first rule in both chains. Without it a
//     broad deny drops replies to connections this host opened, killing live SSH sessions.
//   · Under `policy drop`, `iif lo accept` is prepended and is not optional. Measured: without it
//     127.0.0.1 is unreachable and every service that talks to localhost over TCP breaks.
//   · A rule with no address match carries no family qualifier and covers IPv4 and IPv6 alike.
//     Adding a source pins the rule to that source's family — so a mixed-family list becomes two
//     rules, and a source-restricted baseline leaves the other family to the chain policy.
import type { BaselineRule, Config, HookPolicy } from "./config.ts";
import { tableRef } from "./config.ts";
import { isPortsRef, type Policy } from "./policy.ts";

/** An inbound policy: this host is the destination. */
export interface InputItem {
  policy: Policy;
  /** Resolved source CIDRs. Empty means "any source". */
  srcCidrs: string[];
  /** Resolved destination CIDRs — must cover this host, or the item is skipped. */
  dstCidrs: string[];
}

/**
 * An egress policy: this host is the source.
 *
 * No source match is rendered — anything traversing the output hook originates here by
 * definition. The caller is responsible for only passing items whose source covers this host.
 */
export interface EgressItem {
  policy: Policy;
  /**
   * Resolved destination CIDRs. **`null` means "the public internet"**, rendered as
   * `ip daddr != <internalSupernet>`. An empty array is rejected rather than rendered, because
   * "no destination match" would silently become "drop all outbound".
   */
  dstCidrs: string[] | null;
}

export interface Skipped {
  policyId: string;
  name: string;
  reason: string;
  hook: "input" | "output";
}

/**
 * The renderer was handed input it cannot turn into a rule.
 *
 * Distinct from `Skipped`, and the distinction is the whole point of having both. A skip means the
 * policy was understood and deliberately produced no rule — it is disabled, it is an allow in a
 * deny-only layer, its destination is not this host. An **error** means the input could not be
 * understood at all: an unresolved object reference, a malformed address. That indicates the
 * pipeline feeding the renderer is broken.
 *
 * Those two must not share a channel, because a skipped *deny* is an open port. If a resolver
 * returns garbage and the renderer quietly drops the rule that depended on it, the host ends up
 * open while every dashboard reports it closed — the exact failure this project exists to prevent.
 *
 * Failing the whole render is the safe direction. The agent keeps the ruleset it already has and
 * the rollout stalls where an operator can see it, rather than applying a ruleset with a hole.
 */
export class RenderError extends Error {
  readonly statusCode = 500;
}

export interface Ruleset {
  /** Complete table definition, applied atomically with `nft -f`. */
  ruleset: string;
  /** Number of rendered deny rules across both hooks. */
  ruleCount: number;
  /** Policies that produced no rule, and why. Never silently dropped. */
  skipped: Skipped[];
}

// ── The plan ─────────────────────────────────────────────────────────────────
//
// Rendering happens in two steps: decide what rules exist, then format them. The step exists
// because there are two output formats — nft text for humans to read in the GUI, and nft JSON for
// the agent to apply — and **they must never disagree**. A preview that shows one thing while a
// different thing reaches the kernel is the worst failure mode a firewall tool has, and two
// independent emitters over the same inputs would drift into exactly that.
//
// So the decisions (which policies render, which are skipped and why, what each rule matches) are
// made once, here, and both emitters are dumb formatters over the result.

/**
 * Address family of a match.
 *
 * `inet` tables carry both, and the qualifier decides which. This matters most in its absence: a
 * rule with **no** address match has no family qualifier and therefore covers IPv4 and IPv6 alike,
 * while adding a source pins the rule to that source's family and leaves the other family to the
 * chain policy. Under `policy drop` that is the difference between "SSH is open" and "SSH is open
 * over IPv4 and silently dead over IPv6".
 */
export type Family = "ip" | "ip6";

/** One match condition. Deliberately closed — an emitter must handle every case or fail to build. */
export type Match =
  | { kind: "saddr"; family: Family; cidrs: string[] }
  | { kind: "daddr"; family: Family; cidrs: string[] }
  /** `ip daddr != <cidr>` — the "public internet" form. */
  | { kind: "daddr-not"; family: Family; cidr: string }
  | { kind: "l4proto"; proto: string }
  /** Port list; entries are `"22"` or the inclusive range `"9000:9100"`. */
  | { kind: "dport"; proto: string; ports: string[] }
  | { kind: "ct-established" }
  /**
   * `iif "lo"` — traffic the host sent to itself.
   *
   * Rendered automatically whenever the input hook drops, and not optional. Measured: with
   * `policy drop` and no loopback rule, `127.0.0.1:22` is unreachable. Every service that talks to
   * localhost over TCP breaks, which on these hosts includes the very pattern the design
   * recommends — bind to `127.0.0.1` and put a reverse proxy in front.
   */
  | { kind: "iif"; name: string }
  /** `ip saddr != <cidr>` — the counterpart of `daddr-not`, used by the forward guard. */
  | { kind: "saddr-not"; family: Family; cidr: string }
  /**
   * `ct status dnat` — a packet whose destination was rewritten on the way in.
   *
   * Needed by the forward guard and easy to leave out. A published container port arrives from the
   * public side and is DNATed to a container address, which on these hosts is *inside* the internal
   * supernet — so the guard would drop exactly the traffic the publish exists to allow. firewalld
   * carries the same rule for the same reason, second in its forward chain; that is where this was
   * read rather than guessed.
   */
  | { kind: "ct-dnat" }
  /** `ct state invalid` — packets conntrack cannot place in any flow. */
  | { kind: "ct-invalid" };

export type Verdict = "accept" | "drop" | "reject" | "reject-tcp-reset";

export interface PlannedRule {
  matches: Match[];
  verdict: Verdict;
  comment: string;
}

export interface RulesetPlan {
  host: string;
  input: PlannedRule[];
  output: PlannedRule[];
  /**
   * The forward chain, or `null` when `cfg.forward` is null.
   *
   * `null` and `[]` are different answers and the emitters treat them so: `null` means do not
   * create the chain at all — the hook stays untouched, which is what every host that does not
   * route wants. An empty array would mean "create a chain that does nothing", and an empty chain
   * with `policy accept` is indistinguishable in a dump from one whose rules were lost.
   */
  forward: PlannedRule[] | null;
  skipped: Skipped[];
  /** Deny rules only — baseline and conntrack rules are not policy and are not counted. */
  ruleCount: number;
  /**
   * Rule comments that must exist in the table once this is applied.
   *
   * The agent checks these against what the kernel actually holds, before it confirms. Its own
   * heartbeat already proves the path *to the relay* survived — it is the evidence that arrives by
   * arriving. It proves nothing about SSH. A ruleset that keeps the relay reachable while dropping
   * the management baseline would confirm cleanly and take the host away from you.
   *
   * ## What independence this does and does not give
   *
   * These are built straight from `cfg.baseline`, not from the assembled rules. That makes them a
   * real check on rule *assembly* — the family split dropping one half, an ordering mistake, a
   * filter that removes too much are all failure modes seen in this codebase already, and none of
   * them would touch this list.
   *
   * It is **not** a check on the baseline itself. If the configured baseline is wrong, the rules
   * and the assertions are wrong together and agree. Nothing inside the host can catch that;
   * verifying reachability from outside is a separate job (H29).
   */
  assertions: string[];

  /**
   * Single addresses the inbound rules target — for the agent to check it actually holds one.
   *
   * Distinct from `assertions`: that asks whether the rules reached the kernel, this asks whether
   * they name the right machine. Both can pass while the other fails, and the combination that
   * bites is `assertions` passing on a host whose address moved — see `Artifact.expectAddrs`.
   *
   * Read back out of the assembled rules, so it describes what was rendered rather than what the
   * caller meant. Prefixes and the broadcast address are excluded: neither identifies one host.
   */
  expectAddrs: string[];
}

// ── CIDR / port overlap (needed for baseline protection) ──────────────────────

function ipToInt(ip: string): bigint | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256n + BigInt(v);
  }
  return n;
}

/**
 * An IPv6 address as a 128-bit integer.
 *
 * `bigint` because 128 bits does not fit a double, which is the reason this did not exist and every
 * caller of `cidrsOverlap` treated IPv6 as unparseable. Embedded IPv4 (`::ffff:10.0.0.1`) is refused
 * rather than expanded — `familyOf` refuses it on the render path and `geofeed.ts` refuses it in a
 * feed, both because an address that belongs to the other family must not be reasoned about as
 * though it were in this one.
 */
function ip6ToInt(value: string): bigint | null {
  if (value.includes(".")) return null;
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0]!.split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1]!.split(":") : [];
  if (halves.length === 1 && head.length !== 8) return null;
  if (halves.length === 2 && head.length + tail.length > 7) return null;
  const groups = halves.length === 1
    ? head
    : [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

/** The address span a CIDR covers, as integers, with the family it belongs to. */
export interface CidrRange {
  first: bigint;
  last: bigint;
  family: Family;
  bits: number;
}

/**
 * Parse a CIDR into the span of addresses it covers, or `null` if it is not one.
 *
 * The canonical answer to "what does this CIDR cover" for the whole repository — `zones.ts` and
 * `where-used.ts` read it too. It existed three times in three shapes before, which is how
 * `Zone.cidrs6` came to be declared and never read.
 *
 * **The base is masked to the prefix.** `10.17.0.5/16` covers `10.17.0.0`–`10.17.255.255`, not the
 * 65,536 addresses starting at `.0.5`. Nothing in this repository writes a CIDR that way on purpose,
 * which is exactly why an unmasked reading would be wrong somewhere nobody was looking.
 */
export function cidrRange(cidr: string): CidrRange | null {
  const slash = cidr.indexOf("/");
  const base = (slash === -1 ? cidr : cidr.slice(0, slash)).trim();
  if (!base) return null;
  const family: Family = base.includes(":") ? "ip6" : "ip";
  const width = family === "ip6" ? 128 : 32;
  const bits = slash === -1 ? width : Number(cidr.slice(slash + 1));
  if (!Number.isInteger(bits) || bits < 0 || bits > width) return null;
  const addr = family === "ip6" ? ip6ToInt(base) : ipToInt(base);
  if (addr === null) return null;
  const size = 1n << BigInt(width - bits);
  const first = (addr / size) * size;
  return { first, last: first + size - 1n, family, bits };
}

/**
 * Do two CIDRs share any address?
 *
 * **Undecidable input counts as overlapping.** If this returned "no overlap" for anything it
 * failed to parse, baseline protection would be bypassed by exactly the inputs it could not reason
 * about.
 *
 * ## IPv6 used to land in that bucket, and it was the wrong bucket
 *
 * `ipToInt` returned `null` for anything with a colon — "IPv6 out of scope for overlap checks" —
 * so every IPv6 CIDR was undecidable and every comparison involving one answered `true`. Measured
 * 2026-08-24: `cidrsOverlap("2001:db8::/32", "10.17.0.0/17")` was `true`, and so was the comparison
 * of two *disjoint* IPv6 prefixes.
 *
 * On the render path that is not conservative, it is inverted. `baselineConflict` **rejects** the
 * policy it finds a conflict for, so an over-broad `true` does not protect a management path — it
 * throws away the operator's rule and gives a reason that is false. Every IPv6 deny whose
 * protocol and ports touched any baseline entry was dropped from the ruleset with
 * "could block a protected path", on a fleet where every host has a public IPv6 address.
 *
 * **Different families cannot overlap.** An `ip6 saddr` rule matches no IPv4 packet and an
 * `ip saddr` rule matches no IPv6 packet — that is why `groupByFamily` exists twenty lines down.
 * Answering `false` here is not a relaxation; it is the same statement the renderer already makes.
 */
export function cidrsOverlap(a: string, b: string): boolean {
  const pa = cidrRange(a);
  const pb = cidrRange(b);
  if (!pa || !pb) return true;
  if (pa.family !== pb.family) return false;
  return pa.first <= pb.last && pb.first <= pa.last;
}

/**
 * Do two port specs overlap? An empty policy spec means "all ports" and overlaps everything.
 *
 * **Undecidable input counts as overlapping**, the same rule `cidrsOverlap` follows and for the same
 * reason: this decides whether a policy could take away a protected management path, so anything it
 * cannot reason about must not come back as "no conflict".
 *
 * It did. `Number("@web")` is `NaN`, every comparison against `NaN` is false, and the function
 * returned `false` — "these do not overlap" — for exactly the inputs whose meaning is unknown. On
 * the render path `assertPorts` throws before that matters, so the fleet was never at risk; but
 * `baselineConflict` is also read by the policy screen and the coverage table, and there an
 * unresolved reference produced a confident "does not conflict with the baseline".
 */
export function portsOverlap(policyPorts: string, baselinePorts: string): boolean {
  if (!policyPorts) return true;
  let undecidable = false;
  const ranges = (spec: string): Array<[number, number]> =>
    spec
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean)
      .map((x) => {
        const [lo, hi] = x.split(":");
        const l = Number(lo);
        const h = hi === undefined ? l : Number(hi);
        if (!Number.isFinite(l) || !Number.isFinite(h)) undecidable = true;
        return [l, h] as [number, number];
      });
  const A = ranges(policyPorts);
  const B = ranges(baselinePorts);
  if (undecidable) return true;
  return A.some(([a1, a2]) => B.some(([b1, b2]) => a1 <= b2 && b1 <= a2));
}

/**
 * Would this policy be able to block a protected management path?
 *
 * If so the policy is **rejected**. Baseline rules render first so it would not actually take
 * effect — but then the user has a rule that silently does nothing, which is worse than an
 * explicit error.
 */
export function baselineConflict(cfg: Config, p: Policy, srcCidrs: string[]): BaselineRule | null {
  for (const b of cfg.baseline) {
    if (p.proto !== "any" && p.proto !== b.proto) continue;
    if (!portsOverlap(p.ports, b.ports)) continue;
    const srcHits =
      srcCidrs.length === 0 ||
      b.srcCidrs.length === 0 ||
      srcCidrs.some((s) => b.srcCidrs.some((bs) => cidrsOverlap(s, bs)));
    if (srcHits) return b;
  }
  return null;
}

// ── Rendering ────────────────────────────────────────────────────────────────

function nftSet(cidrs: string[]): string {
  return cidrs.length === 1 ? cidrs[0]! : `{ ${cidrs.join(", ")} }`;
}

/**
 * The exact string a rule comment is, everywhere.
 *
 * ⚠️ **This must run at plan time, not at emit time.** It used to run in each emitter, and the two
 * emitters stripped different characters (`"` and `\` in the text form, `\t` in the JSON form)
 * while `assertions` was built from the raw `desc` and never truncated at all. So three strings
 * claimed to be one:
 *
 *     assertion   [83] baseline: ICMP (path MTU discovery) — a black hole here reads as 'the app is flaky'
 *     kernel      [80] baseline: ICMP (path MTU discovery) — a black hole here reads as 'the app is fla
 *
 * The agent compares them with **set membership** (`heliopause-pull.py`, `missing_assertions`), so
 * an assertion that is one character longer than the comment is simply absent. Every host would
 * report the baseline missing and auto-rollback every generation, and the symptom reads as a bad
 * ruleset rather than as a string length. Measured against `examples/site.ts` as shipped — the
 * second baseline entry's `desc` is 73 characters, which is already over the line.
 *
 * Normalising once, here, is what makes `assertions ⊆ comments` true by construction rather than
 * by two functions happening to agree. `nft-json.ts` imports this one rather than keeping its own.
 */
export function nftComment(s: string): string {
  return s.replace(/[\r\n\t"\\]/g, " ").slice(0, COMMENT_MAX);
}

/** nft stores a rule comment as a bounded string; longer text is silently cut, not refused. */
export const COMMENT_MAX = 80;

/** nft writes ranges as `lo-hi`; the policy model uses `lo:hi`. */
function portExpr(proto: string, ports: string): string {
  const exprs = ports
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .map((p) => (p.includes(":") ? p.replace(":", "-") : p));
  // A port match over nothing is not a rule with no opinion about ports — it is `tcp dport {  }`,
  // which nft refuses, and whose JSON counterpart is a rule matching port zero. Neither is what any
  // caller meant, so no caller is allowed to ask. "All ports of this protocol" is `l4proto`.
  if (exprs.length === 0) {
    throw new RenderError(`${proto} port match has no ports — use a protocol match for "all ports"`);
  }
  return `${proto} dport ${exprs.length === 1 ? exprs[0] : `{ ${exprs.join(", ")} }`}`;
}

/**
 * The verdict for a deny.
 *
 * TCP uses `reject with tcp reset` so the client fails immediately on the RST. Everything else
 * uses a plain `reject`, which in the inet family is an ICMP/ICMPv6 port-unreachable.
 * **`proto=any` must not use tcp reset** — TCP is not guaranteed, nft rejects it, and it would
 * be wrong anyway.
 */
function denyVerdict(p: Policy): Verdict {
  if (p.denyMode !== "reject") return "drop";
  return p.proto === "tcp" ? "reject-tcp-reset" : "reject";
}

// ── Input validation ─────────────────────────────────────────────────────────
//
// Everything reaching a rule is checked here, at the boundary, rather than trusted because of
// where it came from. Resolver output in particular is not validated anywhere else — the policy
// model checks the *reference* (`@web`, a host name), never what the resolver hands back for it.

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/;

/** Host names reach rule comments and the artifact path. Same shape the relay will serve. */
const HOST_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/;

/**
 * Which family does this address belong to? Throws if it is neither.
 *
 * Doubles as the validator, because "what family is this" and "is this an address at all" are the
 * same question and answering them separately invites the two to disagree.
 */
export function familyOf(value: string, where = "address"): Family {
  const v4 = IPV4.exec(value);
  if (v4) {
    for (const octet of v4.slice(1, 5)) {
      if (Number(octet) > 255) {
        throw new RenderError(`${where}: ${JSON.stringify(value)} has an octet above 255`);
      }
    }
    const bits = v4[5];
    if (bits !== undefined && Number(bits) > 32) {
      throw new RenderError(`${where}: ${JSON.stringify(value)} has a prefix length above 32`);
    }
    return "ip";
  }
  if (value.includes(":")) {
    assertIpv6(value, where);
    return "ip6";
  }
  throw new RenderError(`${where}: ${JSON.stringify(value)} is not an IP address or CIDR`);
}

/**
 * Whether this names exactly one machine: a bare address, or one with a full-length prefix.
 *
 * The distinction matters because `expectAddrs` is how an agent notices a ruleset was written for a
 * different host, and a check that quietly excludes half the ways of writing "one address" is a check
 * that quietly does not run.
 *
 * `10.17.0.1` and `10.17.0.1/32` are the same machine; `10.17.0.0/16` is any machine on the VPC. The
 * naive test — "contains no slash" — gets the first pair wrong in the dangerous direction, treating a
 * `/32` as though it were a subnet and dropping it. Measured 2026-08-03: three gateway addresses in
 * `/32` form produced an empty `expectAddrs`, disabling the address check for that generation.
 *
 * The family decides the full length: /32 for IPv4, /128 for IPv6. An IPv6 address has colons and no
 * slash, so it must not be mistaken for a prefix either.
 */
export function isSingleAddress(value: string): boolean {
  const slash = value.indexOf("/");
  if (slash === -1) return true;
  const bits = Number(value.slice(slash + 1));
  if (!Number.isInteger(bits)) return false;
  return bits === (value.slice(0, slash).includes(":") ? 128 : 32);
}

function assertIpv6(value: string, where: string): void {
  const slash = value.indexOf("/");
  const addr = slash === -1 ? value : value.slice(0, slash);
  if (slash !== -1) {
    const bits = Number(value.slice(slash + 1));
    if (!Number.isInteger(bits) || bits < 0 || bits > 128) {
      throw new RenderError(`${where}: ${JSON.stringify(value)} has a prefix length outside 0-128`);
    }
  }
  const halves = addr.split("::");
  if (halves.length > 2) {
    throw new RenderError(`${where}: ${JSON.stringify(value)} has more than one "::"`);
  }
  const groups = halves.flatMap((h) => (h === "" ? [] : h.split(":")));
  for (const g of groups) {
    if (!/^[0-9A-Fa-f]{1,4}$/.test(g)) {
      // Embedded IPv4 (`::ffff:10.0.0.1`) is deliberately refused rather than half-handled. It
      // would have to render as one family while reading as the other.
      throw new RenderError(`${where}: ${JSON.stringify(value)} has an invalid group ${JSON.stringify(g)}`);
    }
  }
  const max = halves.length === 2 ? 7 : 8;
  if (groups.length > max || (halves.length === 1 && groups.length !== 8)) {
    throw new RenderError(`${where}: ${JSON.stringify(value)} is not a well-formed IPv6 address`);
  }
}

function assertCidrs(values: readonly string[], where: string): void {
  for (const v of values) familyOf(v, where);
}

/**
 * Split addresses by family, preserving order within each.
 *
 * A single nft rule cannot mix families in one address set, so a policy resolving to both becomes
 * **two rules**. Rendering only the first family would silently drop half the intent, and under
 * `policy drop` the half that vanishes is the half that stays blocked.
 */
export function groupByFamily(cidrs: readonly string[], where: string): Array<[Family, string[]]> {
  const v4: string[] = [];
  const v6: string[] = [];
  for (const c of cidrs) (familyOf(c, where) === "ip" ? v4 : v6).push(c);
  const out: Array<[Family, string[]]> = [];
  if (v4.length) out.push(["ip", v4]);
  if (v6.length) out.push(["ip6", v6]);
  return out;
}

/**
 * Check a port spec is resolved and well formed.
 *
 * An unresolved `@web` is the dangerous case, and not because it fails. In nft text `@web` is
 * valid syntax — it is a **named set reference** — so the rule renders, and then either matches
 * some unrelated set that happens to exist or fails at apply. In JSON it becomes `NaN`, which
 * `JSON.stringify` turns into `null`, producing a structurally valid document that means nothing.
 * Neither failure announces itself.
 */
function assertPorts(spec: string, where: string): void {
  if (isPortsRef(spec)) {
    throw new RenderError(
      `${where}: unresolved service-object reference ${JSON.stringify(spec)} — ` +
        `the resolver did not run, or did not know this object`,
    );
  }
  for (const entry of spec.split(",").map((x) => x.trim()).filter(Boolean)) {
    const m = /^(\d{1,5})(?::(\d{1,5}))?$/.exec(entry);
    if (!m) throw new RenderError(`${where}: ${JSON.stringify(entry)} is not a port or port range`);
    const lo = Number(m[1]);
    const hi = m[2] === undefined ? lo : Number(m[2]);
    if (lo < 1 || hi > 65535) {
      throw new RenderError(`${where}: port ${JSON.stringify(entry)} is outside 1-65535`);
    }
    if (hi < lo) throw new RenderError(`${where}: port range ${JSON.stringify(entry)} runs backwards`);
  }
}

function assertHostName(host: string): void {
  // Refused rather than escaped. A host name carrying newlines forges the text preview — it can
  // display rules that are not in the ruleset — and escaping would silently rewrite an identifier
  // that something upstream is wrong about. The name is an identifier; if it is not shaped like
  // one, that is worth stopping for.
  if (!HOST_NAME.test(host)) {
    throw new RenderError(
      `host name ${JSON.stringify(host)} is not a plain identifier ` +
        `(letters, digits, dot, dash, underscore; must not start with a separator)`,
    );
  }
}

function portList(ports: string): string[] {
  return ports
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

/**
 * Can this layer express the policy's protocol and ports at all?
 *
 * ⚠️ `proto: "any"` with a port spec cannot be rendered here: nft's port match is
 * protocol-qualified, so there is no rule meaning "port 8080 of whatever protocol this is". **The
 * old code answered by dropping the ports**, and that is not a narrower rule but a wider one.
 * Measured — `{proto: "any", ports: "8080", action: "deny", src: internet}` rendered as:
 *
 *     ip saddr 0.0.0.0/0 ip daddr <host> drop
 *
 * Every port, every protocol, a black hole. `baselineConflict` could not catch it either: that
 * function reads `p.ports`, so it went on reasoning about the port the rule no longer carried and
 * reported no conflict with the management baseline the rule was about to swallow. `skipped`
 * stayed empty, so nothing said a word.
 *
 * **Skipped rather than refused**, and the reason is `cilium.ts` — it skips a policy whose
 * endpoints are not workloads with "belongs to the host layer only" rather than failing the
 * render. The two renderers read one policy list and each drops what it cannot express; a policy
 * that is `any`-plus-ports between two workloads is legitimate for Cilium, and failing the whole
 * host publish over it would turn one unrenderable row into a fleet-wide publish outage. That is
 * also what `RenderError`'s own doc says: an error is input that could not be **understood**. This
 * is understood perfectly and has no nft spelling, which is the definition of a skip.
 */
function unrenderable(p: Policy): string | null {
  if (p.proto === "any" && p.ports) {
    return (
      `proto "any" cannot carry ports ${JSON.stringify(p.ports)} on the host layer — ` +
      `nft's port match is protocol-qualified. Name the protocol, or clear the ports.`
    );
  }
  return null;
}

function protoMatches(p: Policy): Match[] {
  if (p.proto === "any") return [];
  const out: Match[] = [{ kind: "l4proto", proto: p.proto }];
  // ICMP has no ports. Rendering a dport match for it produces a rule nft rejects.
  if (p.proto !== "icmp" && p.ports) out.push({ kind: "dport", proto: p.proto, ports: portList(p.ports) });
  return out;
}

/**
 * Build the rules for one inbound item — one per (source family × destination family) pair that
 * actually occurs, because a single nft rule cannot mix families in an address match.
 */
function inputRules(p: Policy, it: InputItem, verdict: Verdict): PlannedRule[] {
  const at = `policy ${p.id}`;
  const dsts = groupByFamily(it.dstCidrs, `${at} destination`);
  const srcs = it.srcCidrs.length > 0 ? groupByFamily(it.srcCidrs, `${at} source`) : null;
  const proto = protoMatches(p);
  const comment = nftComment(`${p.id} ${p.name}`);

  const out: PlannedRule[] = [];
  for (const [dstFamily, dstCidrs] of dsts) {
    if (!srcs) {
      out.push({
        matches: [{ kind: "daddr", family: dstFamily, cidrs: dstCidrs }, ...proto],
        verdict,
        comment,
      });
      continue;
    }
    // Only same-family pairs can match: an IPv6 source never reaches an IPv4 destination.
    for (const [srcFamily, srcCidrs] of srcs) {
      if (srcFamily !== dstFamily) continue;
      out.push({
        matches: [
          { kind: "saddr", family: srcFamily, cidrs: srcCidrs },
          { kind: "daddr", family: dstFamily, cidrs: dstCidrs },
          ...proto,
        ],
        verdict,
        comment,
      });
    }
  }
  return out;
}

function egressRules(cfg: Config, p: Policy, it: EgressItem, verdict: Verdict): PlannedRule[] {
  const proto = protoMatches(p);
  const comment = nftComment(`${p.id} ${p.name}`);
  if (it.dstCidrs === null) {
    const family = familyOf(cfg.internalSupernet, "internalSupernet");
    // Note the reach of this rule: `ip daddr != <v4 supernet>` matches IPv4 only, so an egress
    // deny aimed at "the internet" does not touch IPv6. Recorded rather than silently papered
    // over — output is `accept` by default, so nothing depends on it yet.
    return [{ matches: [{ kind: "daddr-not", family, cidr: cfg.internalSupernet }, ...proto], verdict, comment }];
  }
  return groupByFamily(it.dstCidrs, `egress policy ${p.id} destination`).map(([family, cidrs]) => ({
    matches: [{ kind: "daddr", family, cidrs } as Match, ...proto],
    verdict,
    comment,
  }));
}

function baselineRules(b: BaselineRule): PlannedRule[] {
  // ICMP has no ports; the protocol match is the whole condition.
  //
  // An **empty** `ports` on tcp/udp means the same thing one level up: `portsOverlap` documents
  // that "an empty policy spec means all ports", and that is the only reading under which
  // `{proto: "tcp", ports: ""}` is a sensible way to write "all TCP from the management range".
  //
  // ⚠️ It used to be rendered as a port match over an empty list, and the two emitters then
  // disagreed about what that was. Text produced `tcp dport {  }`, which nft refuses — loud, and
  // therefore survivable. JSON produced `"right": 0`, a structurally valid rule matching **port
  // zero only**, and JSON is the form the fleet applies (`publish.ts`). So a management baseline
  // written this way applied cleanly and permitted nothing, while the text preview an operator
  // reviewed showed something else entirely. Emitting the protocol match is what both forms
  // already mean by "all ports of this protocol".
  const proto: Match[] =
    b.proto === "icmp" || b.proto === "icmpv6"
      ? [{ kind: "l4proto", proto: b.proto === "icmpv6" ? "icmpv6" : "icmp" }]
      : b.ports === ""
        ? [{ kind: "l4proto", proto: b.proto }]
        : // The protocol-qualified port match already implies the protocol, so no separate
          // `meta l4proto` is emitted for tcp/udp.
          [{ kind: "dport", proto: b.proto, ports: portList(b.ports) }];
  const comment = nftComment(`baseline: ${b.desc}`);

  if (b.srcCidrs.length === 0) {
    // No address match, so no family qualifier — this covers IPv4 and IPv6 together. That is the
    // safest shape for a management path and the reason an unrestricted baseline entry is the
    // recommended one.
    return [{ matches: proto, verdict: "accept", comment }];
  }
  return groupByFamily(b.srcCidrs, `baseline ${JSON.stringify(b.desc)} source`).map(
    ([family, cidrs]) => ({
      matches: [{ kind: "saddr", family, cidrs } as Match, ...proto],
      verdict: "accept" as Verdict,
      comment,
    }),
  );
}

// ── Text formatter ────────────────────────────────────────────────────────────

function matchText(m: Match): string {
  switch (m.kind) {
    case "saddr":
      return `${m.family} saddr ${nftSet(m.cidrs)}`;
    case "daddr":
      return `${m.family} daddr ${nftSet(m.cidrs)}`;
    case "daddr-not":
      return `${m.family} daddr != ${m.cidr}`;
    case "l4proto":
      return `meta l4proto ${m.proto}`;
    case "dport":
      return portExpr(m.proto, m.ports.join(","));
    case "ct-established":
      return "ct state established,related";
    case "iif":
      return `iif "${m.name}"`;
    case "saddr-not":
      return `${m.family} saddr != ${m.cidr}`;
    case "ct-dnat":
      return "ct status dnat";
    case "ct-invalid":
      return "ct state invalid";
  }
}

const VERDICT_TEXT: Record<Verdict, string> = {
  accept: "accept",
  drop: "drop",
  reject: "reject",
  "reject-tcp-reset": "reject with tcp reset",
};

function ruleText(r: PlannedRule): string {
  return [
    ...r.matches.map(matchText),
    VERDICT_TEXT[r.verdict],
    `comment "${nftComment(r.comment)}"`,
  ].join(" ");
}

/**
 * The forward chain.
 *
 * Order is the whole rule set here, because every line before the guard exists to stop the guard
 * from matching traffic it must not match:
 *
 *   1. `established,related`  Replies to flows that started inside. Their source is external and
 *                             their destination is internal, so without this the guard drops every
 *                             answer to every connection the VPC opens — the internet would appear
 *                             to be write-only.
 *   2. `ct status dnat`       Published container ports. The destination has already been rewritten
 *                             to an address inside the internal supernet, so the guard would refuse
 *                             the traffic the publish exists to admit.
 *   3. `ct state invalid`     Dropped, matching what firewalld did here. Not part of the guard, but
 *                             leaving it out would make retiring firewalld a behaviour change on a
 *                             router, and the point of this chain is that it is not one.
 *   4. the guard              Into the internal ranges, from outside them: refuse.
 *
 * Getting 1 or 2 wrong is not visible on the host that holds the rule — it breaks traffic belonging
 * to machines behind it. That is the argument for keeping this chain small and fixed rather than
 * policy-driven.
 */
/**
 * Does a configured host pattern match this host?
 *
 * Two things the bare `new RegExp(re).test(host)` did not do.
 *
 * **A malformed pattern becomes a `RenderError`.** `new RegExp("gw-(01")` throws a `SyntaxError`,
 * and that is not the channel this module's callers handle — see the note at the call site.
 *
 * **The pattern is not anchored, and that stays true.** `"gw-"` matching `k3s-gw-proxy` is the
 * documented behaviour of `protectedHosts` in `config.ts`, which points at this exact consequence;
 * anchoring here would silently change which hosts a site's existing config selects. What was
 * missing was not anchoring but a *readable failure* for the pattern that cannot compile at all.
 */
function matchesHost(pattern: string, host: string, where: string): boolean {
  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch (e) {
    throw new RenderError(
      `${where}: ${JSON.stringify(pattern)} is not a valid regular expression — ${(e as Error).message}`,
    );
  }
  return re.test(host);
}

function forwardRules(cfg: Config, host: string): PlannedRule[] | null {
  if (!cfg.forward) return null;
  // Not this host's job. `null` rather than an empty chain — see `RulesetPlan.forward`.
  //
  // ⚠️ **A bad pattern used to leave as a raw `SyntaxError`.** `new RegExp(re)` throws
  // `Invalid regular expression: /gw-(01/: Unterminated group`, which is not a `RenderError`, so it
  // walked straight past the channel every caller handles — measured: `instanceof RenderError` was
  // false and `statusCode` was undefined, so the manager answered 500 and `listen.ts`'s synchronous
  // path would have exited. `defineConfig` validates none of this; a typo in a site module is all
  // it takes.
  if (!cfg.forward.hosts.some((re) => matchesHost(re, host, "forward.hosts"))) return null;
  const rules: PlannedRule[] = [];
  if (cfg.forward.guardInternal) {
    // 🔴 `internalSupernet.includes(":")` was the whole family decision here, and it validated
    // nothing. The egress path asks `familyOf` (which rejects an octet above 255, a prefix length
    // out of range, and embedded IPv4); this one took a substring test and rendered whatever came
    // out. A malformed supernet therefore produced a *syntactically plausible* guard in the wrong
    // family — `ip6 saddr 10.0.0.0/8` matches no packet and `nft -f` refuses the file, so the
    // gateway reverts every generation it is given while the plan looks fine.
    const family: Family = familyOf(cfg.internalSupernet, "forward guard internalSupernet");
    rules.push(
      {
        matches: [{ kind: "ct-established" }],
        verdict: "accept",
        comment: nftComment("forward: established/related (replies to internally-originated flows)"),
      },
      {
        matches: [{ kind: "ct-dnat" }],
        verdict: "accept",
        comment: nftComment("forward: DNAT (published container/VM ports land inside the supernet)"),
      },
      {
        matches: [{ kind: "ct-invalid" }],
        verdict: "drop",
        comment: nftComment("forward: invalid"),
      },
      {
        matches: [
          { kind: "daddr", family, cidrs: [cfg.internalSupernet] },
          { kind: "saddr-not", family, cidr: cfg.internalSupernet },
        ],
        verdict: "drop",
        comment: nftComment(`forward: refuse routing into ${cfg.internalSupernet} from outside it`),
      },
    );
  }
  return rules;
}

/**
 * Decide one host's ruleset without formatting it.
 *
 * Pass only the items this host is an endpoint of — filtering is the caller's job, since only the
 * caller knows the inventory. Both emitters go through here, so a policy that is skipped is
 * skipped identically in the preview and in what the agent applies.
 */
export function planHostRuleset(
  cfg: Config,
  host: string,
  items: InputItem[],
  egress: EgressItem[] = [],
): RulesetPlan {
  assertHostName(host);
  for (const b of cfg.baseline) {
    // Baseline comes from config rather than from a policy author, so nothing has checked it. It
    // is also the one thing that must never be wrong: these are the rules that keep the host
    // reachable when a policy is trying to cut it off.
    assertPorts(b.ports, `baseline ${JSON.stringify(b.desc)}`);
    assertCidrs(b.srcCidrs, `baseline ${JSON.stringify(b.desc)} source`);
  }

  const skipped: Skipped[] = [];
  const denies: PlannedRule[] = [];
  // Allows are collected separately because they must render *after* the denies. Under a dropping
  // chain policy both are meaningful and first match wins, so a narrow deny placed before a broad
  // allow is the only way to express "open to this network except that host".
  const allows: PlannedRule[] = [];

  for (const it of items) {
    const p = it.policy;
    if (!p.enabled) {
      skipped.push({ policyId: p.id, name: p.name, reason: "policy is disabled", hook: "input" });
      continue;
    }
    if (p.action !== "deny" && cfg.hookPolicy.input !== "drop") {
      // With an accepting chain policy an allow rule changes nothing — the packet was already
      // going to be accepted. Reported rather than rendered, so nobody reads a no-op as enforcement.
      skipped.push({
        policyId: p.id,
        name: p.name,
        reason: "chain policy is accept — an allow policy has no effect; set hookPolicy.input to 'drop'",
        hook: "input",
      });
      continue;
    }
    if (it.dstCidrs.length === 0) {
      skipped.push({ policyId: p.id, name: p.name, reason: `destination does not resolve to ${host}`, hook: "input" });
      continue;
    }
    const cannot = unrenderable(p);
    if (cannot) {
      skipped.push({ policyId: p.id, name: p.name, reason: cannot, hook: "input" });
      continue;
    }
    // Only denies can collide with a protected path; an allow cannot take one away.
    const conflict = p.action === "deny" ? baselineConflict(cfg, p, it.srcCidrs) : null;
    if (conflict) {
      skipped.push({
        policyId: p.id,
        name: p.name,
        reason: `rejected — could block a protected path: ${conflict.desc} (${conflict.proto}/${conflict.ports})`,
        hook: "input",
      });
      continue;
    }
    // Validated only once the policy is known to produce a rule. A disabled policy carrying a
    // malformed CIDR should not fail the render — it was never going to be enforced.
    const at = `policy ${p.id} (${p.name})`;
    assertCidrs(it.srcCidrs, `${at} source`);
    assertCidrs(it.dstCidrs, `${at} destination`);
    if (p.proto !== "any" && p.proto !== "icmp" && p.ports) assertPorts(p.ports, at);
    const rules = inputRules(p, it, p.action === "deny" ? denyVerdict(p) : "accept");
    // `Skipped` is documented as "policies that produced no rule, and why. Never silently
    // dropped" — and this was the one path that broke it. A single nft rule cannot mix address
    // families, so `inputRules` pairs sources with destinations family by family and drops the
    // pairs that cannot match. When **no** pair matches — an IPv4-only source against a
    // destination that now resolves to AAAA only — the loop simply produced nothing: no rule, no
    // skip, no error. A deny evaporated, and every dashboard went on reporting the policy as
    // applied because `skipped` was empty and `RenderError` was never raised.
    //
    // Reported rather than refused: this is a resolver outcome, not malformed input. The policy
    // was understood; it is the addresses that stopped overlapping, and an operator reading the
    // skip list is exactly who can tell whether that is a mistake.
    if (rules.length === 0) {
      skipped.push({
        policyId: p.id,
        name: p.name,
        reason:
          `no rule renders — source (${it.srcCidrs.join(", ")}) and destination ` +
          `(${it.dstCidrs.join(", ")}) share no address family`,
        hook: "input",
      });
      continue;
    }
    (p.action === "deny" ? denies : allows).push(...rules);
  }

  // Egress is not checked against the baseline: protected management paths are inbound, and the
  // "to the internet" form (`!= internalSupernet`) cannot match an internal destination. Replies
  // to inbound sessions are protected by the output chain's conntrack rule.
  const egressDenies: PlannedRule[] = [];
  const egressAllows: PlannedRule[] = [];
  for (const it of egress) {
    const p = it.policy;
    if (!p.enabled) {
      skipped.push({ policyId: p.id, name: p.name, reason: "policy is disabled", hook: "output" });
      continue;
    }
    if (p.action !== "deny" && cfg.hookPolicy.output !== "drop") {
      skipped.push({
        policyId: p.id,
        name: p.name,
        reason: "chain policy is accept — an allow policy has no effect; set hookPolicy.output to 'drop'",
        hook: "output",
      });
      continue;
    }
    if (it.dstCidrs !== null && it.dstCidrs.length === 0) {
      // Rendering this would produce a rule with no destination match: drop all outbound.
      skipped.push({ policyId: p.id, name: p.name, reason: "destination does not resolve to any CIDR", hook: "output" });
      continue;
    }
    const cannotEgress = unrenderable(p);
    if (cannotEgress) {
      skipped.push({ policyId: p.id, name: p.name, reason: cannotEgress, hook: "output" });
      continue;
    }
    const at = `egress policy ${p.id} (${p.name})`;
    if (it.dstCidrs !== null) assertCidrs(it.dstCidrs, `${at} destination`);
    else familyOf(cfg.internalSupernet, `${at} internalSupernet`);
    if (p.proto !== "any" && p.proto !== "icmp" && p.ports) assertPorts(p.ports, at);
    const v: Verdict = p.action === "deny" ? denyVerdict(p) : "accept";
    const rules = egressRules(cfg, p, it, v);
    // Same invariant as the input loop above: a policy that produced no rule says so.
    if (rules.length === 0) {
      skipped.push({
        policyId: p.id,
        name: p.name,
        reason: `no rule renders — destination (${(it.dstCidrs ?? []).join(", ")}) resolved to no usable address family`,
        hook: "output",
      });
      continue;
    }
    (p.action === "deny" ? egressDenies : egressAllows).push(...rules);
  }

  // The conntrack rule is first in both chains and is not optional. Without it a broad deny drops
  // the replies to connections this host opened, which kills the live SSH session you are holding
  // while you apply it.
  const inConntrack: PlannedRule = {
    matches: [{ kind: "ct-established" }],
    verdict: "accept",
    comment: nftComment("baseline: established/related (protects replies to our own outbound)"),
  };
  const outConntrack: PlannedRule = {
    matches: [{ kind: "ct-established" }],
    verdict: "accept",
    comment: nftComment("baseline: established/related (protects replies to inbound sessions)"),
  };

  // Loopback first, and only when it is needed. Measured: with `policy drop` and no such rule,
  // 127.0.0.1 is unreachable and every service that talks to localhost over TCP breaks — including
  // the "bind to 127.0.0.1 behind a reverse proxy" arrangement this design recommends elsewhere.
  // It is prepended rather than left to the operator because forgetting it is silent and total.
  const loopback: PlannedRule[] =
    cfg.hookPolicy.input === "drop"
      ? [{ matches: [{ kind: "iif", name: "lo" }], verdict: "accept", comment: nftComment("baseline: loopback") }]
      : [];

  // Built from the configured baseline rather than from the rules assembled above, so a mistake
  // in assembly cannot produce a matching mistake here. See `RulesetPlan.assertions`.
  //
  // ⚠️ Through `nftComment`, and that is not cosmetic — see the warning on that function. The
  // independence this list is built for is independence from rule *assembly*, not from how nft
  // stores a comment. Skipping the normaliser here made every assertion over 80 characters
  // unsatisfiable, which is not a weaker check but a fleet that reverts everything it is given.
  const assertions = [
    ...(cfg.hookPolicy.input === "drop" ? [nftComment("baseline: loopback")] : []),
    ...cfg.baseline.map((b) => nftComment(`baseline: ${b.desc}`)),
  ];

  // See `isSingleAddress` for why the test is not "has no slash".
  //
  // Single addresses the inbound rules actually target, for the agent to check against its own
  // interfaces. Read back out of the assembled rules rather than from the caller's `dstCidrs`, so
  // this describes what was rendered rather than what was intended — the two diverging is exactly
  // the case this catches. See `Artifact.expectAddrs`.
  //
  // Wider prefixes are excluded: `10.17.0.0/16` is satisfied by any address on the VPC and would make
  // the check pass for a host that moved within it — which is the failure that prompted this. Only a
  // /32 or /128 identifies one machine.
  //
  // **A `/32` or `/128` suffix counts as a single address, and dropping it silently disabled this
  // check.** The filter was `!c.includes("/")`, which reads "no prefix length" as "one machine" — but
  // `10.17.0.1/32` is one machine written the other way, and it was discarded as though it were a
  // subnet. So a resolver that emits full-length CIDRs produced `expectAddrs: []`, the agent's
  // `wrong_addresses` returned early on the empty list, and every host accepted a ruleset written for
  // a different machine while reporting `confirmed`.
  //
  // Measured 2026-08-03 against three gateways' addresses in `/32` form: `expectAddrs` came back
  // empty, and the same addresses bare came back complete. The live fleet was unaffected only because
  // `policy/dev.ts` happens to write host addresses bare — an accident, not a safeguard, and
  // stardust's `makeResolveCidrs` returns `${ip}/32`.
  //
  // The all-ones broadcast address is excluded too: DHCP rules name it as a destination because a
  // client with no address yet can only send there, and no interface ever holds it.
  //
  // Normalised to bare form *before* de-duplicating, because the agent compares against the addresses
  // its interfaces hold — a `/32` suffix would make the comparison fail for every host, which is worse
  // than the check being off: a fleet that reverts every generation. Deduplicating afterwards also
  // collapses `10.17.0.1` and `10.17.0.1/32`, which are one address written two ways and would
  // otherwise both appear.
  const expectAddrs = [
    ...new Set(
      [...denies, ...allows]
        .flatMap((r) => r.matches.flatMap((m) => (m.kind === "daddr" ? m.cidrs : [])))
        .filter(isSingleAddress)
        .map((c) => c.replace(/\/(32|128)$/, ""))
        // After normalising, so `255.255.255.255/32` is excluded as well as the bare form. Dropped
        // this filter while rewriting the expression above and caught it by re-running the probe: a
        // host whose only inbound policy is DHCP would have had `expectAddrs: ["255.255.255.255"]`,
        // which no interface holds — turning the check from silently off into a host that reverts
        // every generation it is given.
        .filter((c) => c !== "255.255.255.255"),
    ),
  ];

  return {
    host,
    input: [...loopback, inConntrack, ...cfg.baseline.flatMap(baselineRules), ...denies, ...allows],
    output: [outConntrack, ...egressDenies, ...egressAllows],
    forward: forwardRules(cfg, host),
    skipped,
    ruleCount: denies.length + allows.length + egressDenies.length + egressAllows.length,
    assertions,
    expectAddrs,
  };
}

/**
 * Render one host's ruleset as `nft -f` text.
 *
 * This is the human-facing form — what the GUI shows and what an operator reads in review. The
 * agent applies the JSON form (`renderHostRulesetJson`); both are formatted from the same plan, so
 * what is reviewed here is what lands.
 *
 * The table is declared empty and deleted before being defined, so re-applying is idempotent and
 * the delete does not fail on a host that has nothing yet.
 */
export function renderHostRuleset(
  cfg: Config,
  host: string,
  items: InputItem[],
  egress: EgressItem[] = [],
): Ruleset {
  const plan = planHostRuleset(cfg, host, items, egress);
  const T = tableRef(cfg);
  const { input: inPolicy, output: outPolicy } = cfg.hookPolicy;

  // The section comments the earlier version emitted were positioned by counting rules, which
  // stopped being possible once one baseline entry can produce two rules (one per family) and a
  // loopback rule appears conditionally. Rules carry their own comments; a header that has to be
  // kept in sync with arithmetic is a header that will eventually lie.
  const chain = (name: "input" | "output" | "forward", policy: HookPolicy, rules: PlannedRule[]) => [
    `  chain ${name} {`,
    `    type filter hook ${name} priority filter; policy ${policy};`,
    ...rules.map((r) => `    ${ruleText(r)}`),
    `  }`,
  ];

  const ruleset = [
    `# Generated by heliopause for host: ${host}. Do not edit by hand.`,
    `# Only this table is managed — firewalld and existing iptables rules are untouched.`,
    ...(plan.forward
      ? [`# forward is filtered: routing into the internal supernet from outside it is refused.`]
      : [`# forward is not touched: routed traffic and container networking are unaffected.`]),
    inPolicy === "drop"
      ? `# input is default-deny: anything not accepted above is dropped.`
      : `# input policy is accept: this renders explicit denies only (not default-deny).`,
    `table ${T} {}`,
    `delete table ${T}`,
    `table ${T} {`,
    ...chain("input", inPolicy, plan.input),
    ...chain("output", outPolicy, plan.output),
    // `policy accept`, always. See `ForwardConfig` — this chain subtracts one specific route and is
    // not a default-deny for traffic nobody described.
    ...(plan.forward ? chain("forward", "accept", plan.forward) : []),
    `}`,
    ``,
  ].join("\n");

  return { ruleset, ruleCount: plan.ruleCount, skipped: plan.skipped };
}
