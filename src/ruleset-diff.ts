// What changed in a host's rules between two generations.
//
// ## Why the approval screen needs this and the policy diff is not it
//
// `/plans/<hash>/changes` compares the policy **source** between the deployed commit and the one
// being approved, which is the text a person wrote and the right thing to read first. It does not
// answer what the *rules* become: a one-line edit to an address object moves every rule that names
// it, and a rule can move without any line of policy changing at all — a resolver returning a
// different set, a Service selector that widened, a geofeed snapshot that grew.
//
// So an approver reading only the source diff is reading the intent and taking the rendering on
// trust. `nft.ts` calls its text renderer "the human-facing form — what the GUI shows and what an
// operator reads in review", and until now no screen called it for a *comparison*.
//
// ## Why this compares by rule comment rather than by text
//
// A textual diff of two nft JSON documents is a diff of a serialisation: reordering, a changed
// preamble, or a set that gained one member all move many lines and none of them says what an
// approver needs. Every rule this project renders carries `comment "<policy id> <policy name>"`
// (`nft.ts`), and the baseline rules carry `baseline: <desc>`. That comment is the identity of the
// rule as a person thinks about it, so it is what the comparison keys on.
//
// The result therefore says "P12 postgres was added", "P07 legacy was removed", "P03 ssh matches
// something different now" — three sentences an approver can act on, instead of a patch.
//
// ## Pure, and forgiving of a document it cannot read
//
// No I/O and no clock, like the renderer it describes. A document that will not parse yields
// `null` rather than throwing: this is a review aid, and refusing to draw an approval screen because
// one side is unreadable would remove the diff exactly when something is already wrong.

/** One rule, as this comparison identifies it. */
interface KeyedRule {
  /** The rule's own comment — its identity to a reader. */
  comment: string;
  /** The match/verdict expression, canonicalised for comparison only. */
  shape: string;
}

/** How one rule differs between the deployed generation and the proposed one. */
export interface RuleChange {
  comment: string;
  kind: "added" | "removed" | "changed";
}

export interface RulesetDiff {
  /** Ordered: removals first, then changes, then additions — see `diffRulesets`. */
  changes: RuleChange[];
  /** Rules present on both sides with the same shape. A count, because nobody reads that list. */
  unchanged: number;
  /** Rule count on each side, so "nothing changed" and "both are empty" are distinguishable. */
  before: number;
  after: number;
}

/**
 * Pull the rules out of an nft JSON document, keyed by comment.
 *
 * A rule with no comment is skipped rather than given a synthetic key. Every rule this project
 * renders has one, so an uncommented rule came from somewhere else — and inventing a key for it
 * would make it look like a policy change on whichever side it appeared.
 *
 * Duplicate comments keep the first and count the rest into its shape, so two rules from one policy
 * (the family split renders one policy as two rules) compare as one entry that changes when either
 * half does.
 */
function rulesOf(document: string): Map<string, KeyedRule> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(document);
  } catch {
    return null;
  }
  const commands = (parsed as { nftables?: unknown }).nftables;
  if (!Array.isArray(commands)) return null;

  const out = new Map<string, KeyedRule>();
  for (const command of commands) {
    if (!command || typeof command !== "object") continue;
    const add = (command as { add?: unknown }).add;
    const rule = add && typeof add === "object" ? (add as { rule?: unknown }).rule : undefined;
    if (!rule || typeof rule !== "object") continue;
    const comment = (rule as { comment?: unknown }).comment;
    if (typeof comment !== "string" || !comment) continue;
    const shape = JSON.stringify((rule as { expr?: unknown }).expr ?? null);
    const seen = out.get(comment);
    // Appended rather than replaced: one policy can render as two rules (the v4/v6 split), and a
    // change to either half has to show as a change to that policy.
    //
    // The separator is written as the `\u0000` escape and never as the byte itself. A raw NUL in a
    // tracked file makes git call this a binary blob, and `scan-public-history.mjs` refuses every
    // binary blob by design — it cannot prove an uninspectable blob carries no site data. That is
    // what happened: this line shipped with the raw byte in `8fdae68` and the leak scan went red on
    // `main` for a file with nothing wrong in it. The escape renders the identical string.
    out.set(comment, seen ? { comment, shape: `${seen.shape}\u0000${shape}` } : { comment, shape });
  }
  return out;
}

/**
 * Compare two rendered rulesets for one host.
 *
 * `null` when either document cannot be read as an nft JSON command list — the caller says so rather
 * than showing an empty diff, because "nothing changed" and "I could not compare" send an approver
 * to opposite conclusions.
 *
 * Order is what a reader wants rather than what a map iterates: **removals first**, because a rule
 * that disappeared is the one that opens a port and is the thing an approver is least likely to
 * notice on their own; then changes; then additions. Alphabetical within each group, so the same two
 * bundles always produce the same page.
 */
export function diffRulesets(before: string, after: string): RulesetDiff | null {
  const a = rulesOf(before);
  const b = rulesOf(after);
  if (!a || !b) return null;

  const changes: RuleChange[] = [];
  let unchanged = 0;
  for (const [comment, rule] of a) {
    const now = b.get(comment);
    if (!now) changes.push({ comment, kind: "removed" });
    else if (now.shape !== rule.shape) changes.push({ comment, kind: "changed" });
    else unchanged++;
  }
  for (const comment of b.keys()) {
    if (!a.has(comment)) changes.push({ comment, kind: "added" });
  }

  const rank: Record<RuleChange["kind"], number> = { removed: 0, changed: 1, added: 2 };
  changes.sort((x, y) => rank[x.kind] - rank[y.kind] || x.comment.localeCompare(y.comment));
  return { changes, unchanged, before: a.size, after: b.size };
}
