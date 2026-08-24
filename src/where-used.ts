// "Where is this address written down?"
//
// ## A different question from the lookup, deliberately kept apart
//
// `policy-lookup.ts` asks what would *decide* a flow — a semantic question, answered by containment
// and identity. This asks where a value is *written*, which is a textual question, and the two give
// different answers on purpose. An operator about to change `10.17.192.45` needs every rule that
// names it, including ones that would never match the flow they were thinking of; an operator
// debugging a connection needs the opposite. Merging them would give a list that is wrong for both.
//
// ## Why this repository needs it more than most
//
// Measured 2026-08-16: seventy-two policies, twenty-four endpoints written as literal CIDRs, and
// **one** named address object. Commercial firewalls make you name a thing before you can use it,
// and the reason is exactly this question — with names, "where is this used" is a lookup; with
// literals it is a grep that a person has to know to run and has to run against the right file.
//
// `repeatedLiterals` is the other half of that: it says which literals are worth a name, from the
// policy itself rather than from taste.
import { isWorkload, type Endpoint, type Policy } from "./policy.ts";
import { cidrRange, cidrsOverlap } from "./nft.ts";

export interface Usage {
  policyId: string;
  name: string;
  action: Policy["action"];
  enabled: boolean;
  layer: "host" | "workload";
  /** Which part of the rule mentions it. */
  where: "src" | "dst" | "ports";
  /** What the rule actually says there, so the reader sees the text rather than their own query. */
  text: string;
  /**
   * `exact` means the rule writes this value; `contains` means it writes a range that covers it.
   *
   * Separated rather than merged. Renaming a literal touches the `exact` set and nothing else, while
   * the `contains` set is what changes meaning when the address moves — two different jobs, and a
   * single list would serve whichever one the reader happened to assume.
   */
  match: "exact" | "contains";
}


function endpointText(e: Endpoint): string {
  return e.value ? `${e.kind} ${e.value}` : e.kind;
}

/** Does this endpoint mention `q` — as the same text, or as a range containing it? */
function endpointUse(e: Endpoint, q: string): "exact" | "contains" | null {
  if (!e.value) return null;
  // Exact first, and by string. A rule that writes `10.17.0.0/17` is found by searching for
  // `10.17.0.0/17`, whatever any containment test would also say about it.
  if (e.value === q) return "exact";
  // Objects and workload selectors are matched by name or by substring of the selector: those are
  // the texts a person greps for, and a selector is a comma-separated list they may quote part of.
  if (e.kind === "object" || isWorkload(e)) return e.value.includes(q) ? "exact" : null;
  if (e.kind !== "cidr") return null;
  // ## Both sides must parse before `cidrsOverlap` is asked
  //
  // That function answers `true` for anything it cannot read — the right default where it decides
  // whether a rule could take away a management path, and the wrong one behind a search box, where
  // it would report every CIDR rule in the policy as containing whatever the operator mistyped.
  //
  // The gate used to be an IPv4 regex, and that is a different mistake in the other direction:
  // an IPv6 query returned `null` here, which this function's caller reads as **"not written
  // there"**. Silently. `policy-lookup.ts` meets the same situation and says "undecidable, and
  // here is why"; this said nothing, in a tool whose entire purpose is answering "where is this
  // address written down" before somebody renumbers it. `cidrRange` reads both families now, so
  // the honest answer is available rather than merely reportable.
  const qr = cidrRange(q);
  const er = cidrRange(e.value);
  if (!qr || !er) return null;
  const asHost = q.includes("/") ? q : `${q}/${qr.family === "ip6" ? 128 : 32}`;
  return cidrsOverlap(asHost, e.value) ? "contains" : null;
}

/**
 * Every place a value is written in the policy.
 *
 * Disabled rules are included and marked. A disabled rule that names an address is still a place the
 * address is written, and someone renaming it has to change that line too — excluding it would leave
 * a stale literal behind exactly where nobody is looking.
 */
export function whereUsed(policies: readonly Policy[], query: string): Usage[] {
  const q = query.trim();
  if (!q) return [];
  const out: Usage[] = [];
  for (const p of policies) {
    const layer: "host" | "workload" = isWorkload(p.src) || isWorkload(p.dst) ? "workload" : "host";
    const base = { policyId: p.id, name: p.name, action: p.action, enabled: p.enabled, layer };
    for (const [where, e] of [["src", p.src], ["dst", p.dst]] as const) {
      const m = endpointUse(e, q);
      if (m) out.push({ ...base, where, text: endpointText(e), match: m });
    }
    // Ports are searched too. `@pg` and `5432` are both things a person types into this box, and a
    // port search that silently only looked at addresses would answer "nowhere" about a port that is
    // in six rules.
    if (p.ports && (p.ports === q || p.ports.split(",").map((s) => s.trim()).includes(q))) {
      out.push({ ...base, where: "ports", text: p.ports, match: "exact" });
    }
  }
  // Exact before contains, then by policy id. The reader is usually looking for the line they will
  // edit, and that line is an exact one.
  return out.sort((a, b) =>
    (a.match === b.match ? 0 : a.match === "exact" ? -1 : 1) || a.policyId.localeCompare(b.policyId)
  );
}

export interface RepeatedLiteral {
  value: string;
  count: number;
  policyIds: string[];
}

/**
 * Literal CIDRs written in more than one rule.
 *
 * The case for the object catalogue, made from the policy rather than from taste. A range that
 * appears once is a rule; a range that appears six times is a thing with a name nobody has written
 * down, and the day it changes somebody has to find all six.
 *
 * Only `cidr` endpoints, because those are the ones a name would replace. `any` and `internet` are
 * already names.
 */
export function repeatedLiterals(policies: readonly Policy[]): RepeatedLiteral[] {
  const seen = new Map<string, Set<string>>();
  for (const p of policies) {
    for (const e of [p.src, p.dst]) {
      if (e.kind !== "cidr" || !e.value) continue;
      const at = seen.get(e.value) ?? new Set<string>();
      at.add(p.id);
      seen.set(e.value, at);
    }
  }
  return [...seen.entries()]
    .filter(([, ids]) => ids.size > 1)
    .map(([value, ids]) => ({ value, count: ids.size, policyIds: [...ids].sort() }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}
