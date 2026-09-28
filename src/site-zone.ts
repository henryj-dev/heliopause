// Does a rendered site belong to the VPC a plan is addressed to?
//
// ## Why this file exists
//
// `env-spec.ts` states the invariant and nothing enforced it: "The name is the zone's whole
// identity — it keys the CA (`pkiDir`), the agent's `HELIOPAUSE_TARGET`, the site module, and **the
// last label of every host id under it**." A sentence in a comment is not a check, and on
// 2026-09-28 the gap was measured.
//
// The console's policy renderer serves one site, pinned at startup. The console's target selector
// offers every relay. An operator picking `prod-icn-vtr` got dev's policy rendered and proposed
// under prod's name, because nothing compared the two — `recordProposal` took the target from the
// request and the hosts from the render and never asked whether they were the same VPC. Three
// publishes went out that way. The agents refused them (`heliopause-pull.py` checks `payload.host`
// against its own `HOST_ID`), so no host applied another VPC's firewall — but `gw-01.prod-icn-vtr`
// and `gw-01.util-icn-vtr` received nothing at all, and both were already past their authorization
// expiry. One of them was serving SSH on a public address with no ruleset at the time.
//
// So the failure is not "a host got the wrong rules". It is "a host got nothing, and every screen
// said a generation had been published for it".
//
// ## What this is not
//
// **A misconfiguration gate, not a security boundary.** The boundaries are the two-person approval
// on the bundle hash and the agent's own `payload.host` check, and both still stand. This catches
// the operator error and the deployment error before they cost a round trip — which is the only
// reason it can afford to be lenient in the one case below.

/**
 * Thrown where a zone mismatch has to be told apart from any other failure.
 *
 * The renderer needs that distinction and cannot get it from the message: a wrong name is fatal
 * (somebody must edit the Deployment) while a module that fails to import is not (a later commit
 * fixes it). Matching on message text would make the difference depend on wording, which is the kind
 * of coupling that goes wrong the first time somebody improves a sentence.
 */
export class ZoneMismatchError extends Error {
  override readonly name = "ZoneMismatchError";
}

/**
 * The text after the last dot, or null when there is none.
 *
 * `gw-01.prod-icn-vtr` → `prod-icn-vtr`. `h1` → null.
 */
export function zoneLabelOf(hostId: string): string | null {
  const dot = hostId.lastIndexOf(".");
  if (dot < 0 || dot === hostId.length - 1) return null;
  return hostId.slice(dot + 1);
}

/** How many offending ids to name before falling back to the count. */
const NAMED = 3;

/**
 * Null when these hosts may be published to `target`; otherwise the sentence saying why not.
 *
 * ## The lenient case, which is deliberate
 *
 * When **no** host id carries a label at all — no dots anywhere — this returns null rather than
 * refusing. The convention is opt-in by the policy author's own host ids, and a site whose hosts are
 * named `h1` has not claimed a zone. Inventing one for it would mean this function deciding that
 * every fixture, every example and the real-kernel rollback harness are misconfigured, which is a
 * claim about them rather than an observation of them.
 *
 * Read that as a choice, not an oversight: the deployments this exists to protect name their hosts
 * `gw-01.prod-icn-vtr`, and for those the rule below applies in full. A single labelled id switches
 * the whole set into the strict case, so a real site cannot drift into leniency by adding a host.
 */
export function zoneMismatch(input: { target: string; hostIds: readonly string[] }): string | null {
  const { target, hostIds } = input;
  if (hostIds.length === 0) return null;
  // Not `.some(id => id.includes("."))` — a trailing dot is not a label, and `zoneLabelOf` is the
  // one place that decides what counts as one.
  if (!hostIds.some((id) => zoneLabelOf(id) !== null)) return null;

  // `endsWith("." + target)`, never `includes(target)` and never `endsWith(target)`. The first would
  // accept `gw-01.prod-icn-vtr-old` and the second would accept a host literally named
  // `prod-icn-vtr`, and both are exactly the shape a typo takes.
  // ## Exactly `<label>.<target>`, not "ends with the target somewhere"
  //
  // `SAFE_NAME` in `parsePolicySites` allows dots, so `icn` and `prod.icn` can both be valid zone
  // names. A plain `endsWith(".icn")` then accepts `gw.prod.icn` for target `icn`, even though that
  // host belongs to the more specific zone — a nested name walks straight through the gate. Copilot
  // found this on PR #55.
  //
  // Requiring the part before the suffix to carry no dot of its own settles it: a host is in a zone
  // when its id is one label followed by that zone's name. Every real host id is that shape
  // (`gw-01.dev-icn-vtr`), and `gw.prod.icn` is refused for `icn` because `gw.prod` is not one label.
  const suffix = `.${target}`;
  const outside = hostIds.filter((id) => {
    if (!id.endsWith(suffix)) return true;
    const prefix = id.slice(0, -suffix.length);
    return prefix.length === 0 || prefix.includes(".");
  });
  if (outside.length === 0) return null;

  const named = outside.slice(0, NAMED).join(", ");
  const rest = outside.length > NAMED ? `, and ${outside.length - NAMED} more` : "";
  return (
    `this plan is for ${target}, but ${outside.length} of its ${hostIds.length} hosts name another ` +
    `zone — ${named}${rest}. A host id's last label is its VPC (see HELIOPAUSE_RELAYS), so this is ` +
    `one VPC's policy addressed to another. Nothing was proposed.`
  );
}
