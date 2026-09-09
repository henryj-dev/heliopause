// Turning a verified OIDC identity into an authorisation decision.
//
// Separated from the routes because this is the part that decides whether somebody may change a
// firewall, and a decision worth testing is a decision worth having in one function with no I/O.
//
// ## Identity arrives here. Authority does not change shape.
//
// The manager already had two allowlists — `operatorCNs` may read, `writerCNs` may change — keyed by
// certificate subject. OIDC does not add a third model: it adds another way to arrive at a name in
// that same space. The site chose group claims as the source of truth for which of the two you get.
//
// ## The two-person rule is why names must collapse
//
// `approval.ts` refuses an approval with `plan.proposedBy === input.by` — a plain string comparison.
// One human arriving as `ops-alice` by certificate and as `jang@…` by OIDC is two strings, so that
// person could propose and approve alone. The rule would still be *there*, and would have stopped
// being a rule.
//
// So a writer must have a declared alias mapping their OIDC identity onto the certificate name they
// already have. Without one they may read, and writes are refused with a message saying exactly what
// to add. That is the safe direction and it matches what `writerCNs` already documents: the safe
// failure is "nobody can publish through the API", because publishing still works on each gateway.

import type { Identity } from "./oidc.ts";
import type { Principal } from "./session.ts";

export interface OidcAuthzConfig {
  /** Any of these group claims grants read access. Empty means OIDC grants nothing. */
  operatorGroups: readonly string[];
  /** Any of these additionally grants write — subject to having an alias. */
  writerGroups: readonly string[];
  /**
   * OIDC identity → certificate-space name.
   *
   * Keyed by email, `preferred_username` or `sub`; whichever matches first wins, in that order.
   * Email first because it is the one an operator can read off the IdP screen and type here without
   * looking anything up, and `sub` last because it is stable but opaque.
   */
  aliases: ReadonlyMap<string, string>;
}

export interface AuthzDecision {
  /** Null when this identity may not even read. */
  principal: Principal | null;
  /** Whether this identity may propose, approve and publish. */
  canWrite: boolean;
  /** Said in the refusal or the log. Never empty — a decision without a reason is not reviewable. */
  reason: string;
}

/**
 * Decide what a verified identity may do.
 *
 * Takes an already-verified `Identity`. Nothing here re-checks the token: mixing signature
 * verification with authorisation is how a code path ends up deciding permissions from claims it
 * never validated.
 */
export function authorize(id: Identity, cfg: OidcAuthzConfig): AuthzDecision {
  const groups = new Set(id.groups);
  const inAny = (list: readonly string[]) => list.some((g) => groups.has(g));

  if (!inAny(cfg.operatorGroups)) {
    // Named rather than generic. An operator debugging their own login needs to know whether the
    // claim was absent or merely not one of the accepted ones.
    return {
      principal: null,
      canWrite: false,
      reason:
        id.groups.length === 0
          ? "the IdP sent no group claims — check that the client requests the `groups` scope"
          : `none of [${id.groups.join(", ")}] is an operator group`,
    };
  }

  const alias = lookupAlias(id, cfg.aliases);
  const principal: Principal = {
    // Without an alias the name is the most human-readable identifier available. It is only ever
    // used for display and read-side logging, because writes are refused below.
    name: alias ?? id.email ?? id.username ?? id.sub,
    sub: id.sub,
    groups: id.groups,
    via: "oidc",
    // Set false here and raised only on the path that checks both the group and the alias. A
    // principal that defaults to writable would grant on every path this function forgets to close.
    canWrite: false,
  };

  if (!inAny(cfg.writerGroups)) {
    return { principal, canWrite: false, reason: "in an operator group, not a writer group" };
  }
  if (!alias) {
    // Say which of the two it is. "No alias is declared" and "an alias is declared but your issuer
    // has not verified the address it is keyed on" want completely different actions, and an
    // operator reading the first message while looking at a configuration line that plainly
    // contains their address would have no way to get from one to the other.
    if (blockedByUnverifiedEmail(id, cfg.aliases)) {
      return {
        principal,
        canWrite: false,
        reason:
          `${principal.name} has an alias declared for that email address, but the issuer did not ` +
          `send email_verified=true for it. An address the issuer has not verified may be one the ` +
          `user chose, and this alias decides both write access and the name the two-person ` +
          `approval rule compares — so it is not used. Verify the address at the IdP, or key the ` +
          `alias on the subject instead.`,
      };
    }
    return {
      principal,
      canWrite: false,
      reason:
        `${principal.name} is in a writer group but has no alias to a certificate name. ` +
        `Two identities for one person defeat the two-person approval rule, so writing is refused ` +
        `until the mapping is declared.`,
    };
  }
  return { principal: { ...principal, canWrite: true }, canWrite: true, reason: `writer as ${alias}` };
}

/**
 * Email, then preferred_username, then sub. First match wins.
 *
 * 🔴 **An unverified email is not a key.** The alias this returns raises `canWrite` and becomes the
 * name the two-person approval rule compares, so keying it on an address the issuer has not
 * verified would let one member of a writer group take a colleague's alias — and satisfy both
 * halves of the rule alone. Many IdPs let a user edit their own profile address; `email_verified`
 * is the claim OIDC defines to tell the two apart, and nothing in this repository read it.
 *
 * `preferred_username` and `sub` are not filtered: neither is user-settable in the deployments this
 * serves, and `sub` is the issuer's own identifier. Email is the one a person can choose.
 */
function lookupAlias(id: Identity, aliases: ReadonlyMap<string, string>): string | null {
  const email = id.emailVerified ? id.email : null;
  for (const key of [email, id.username, id.sub]) {
    if (!key) continue;
    const hit = aliases.get(key);
    if (hit) return hit;
  }
  return null;
}

/** Would this identity have matched an alias, but for the address being unverified? */
function blockedByUnverifiedEmail(id: Identity, aliases: ReadonlyMap<string, string>): boolean {
  return !id.emailVerified && id.email !== null && aliases.has(id.email);
}

/**
 * Parse `a@b=ops-alice,c@d=ops-other` into the alias map.
 *
 * Refuses malformed entries rather than skipping them. A typo that silently drops a mapping would
 * present as "my writes are refused and I do not know why", and the operator would be looking at a
 * configuration line that appears correct.
 */
export function parseAliases(spec: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const entry of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const eq = entry.indexOf("=");
    if (eq <= 0 || eq === entry.length - 1) {
      throw new Error(`malformed alias ${JSON.stringify(entry)} — expected <oidc-identity>=<certificate-name>`);
    }
    const from = entry.slice(0, eq).trim();
    const to = entry.slice(eq + 1).trim();
    if (!from || !to) throw new Error(`malformed alias ${JSON.stringify(entry)} — both sides are required`);
    if (out.has(from)) throw new Error(`alias ${JSON.stringify(from)} is declared twice`);
    out.set(from, to);
  }
  return out;
}
