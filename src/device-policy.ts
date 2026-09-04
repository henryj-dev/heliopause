// The approved device registry, read as policy addresses — the `cf-device` and `cf-user` expansion.
//
// ## Where this sits
//
// `cf-devices.ts` reads the **live** registry from Cloudflare. This file never talks to Cloudflare:
// it expands the registry a human **approved**, which lives in the site module and moves through git
// like every other policy edit. The two are compared on the device screen, and the comparison is the
// point — a rule must render from what was approved, not from whatever the API returned this morning.
//
// ## What the expansion is for
//
// The host layer has no concept of identity; it matches addresses. Identity policy is renderable
// there only because this fleet has no NAT and each device holds a fixed mesh address, so the address
// is a usable proxy for the device (design doc, `신원 기반 정책`). That proxy is exactly as strong as
// the device→address binding, which Cloudflare reassigns on re-registration — which is why the
// binding is approved in git and diffed against the live read rather than trusted.
//
// ## Every refusal here is a rule that would otherwise widen the firewall
//
// The site wiring hands these addresses to `srcCidrs`, and **an empty `srcCidrs` means "no source
// condition"** — the baseline entries in `policy/dev.ts` use `[]` for exactly that. So an expansion
// that quietly returned nothing would not render a rule matching nothing; it would render a rule
// matching *everyone*. That inversion is why the empty case throws instead of returning `[]`, and it
// is the same hazard `objects.ts` refuses empty groups for.
import { familyOf } from "./nft.ts";
import type { AddressObject, FirewallObject } from "./objects.ts";
import { PolicyError, type Endpoint } from "./policy.ts";

/** A device as the site module approved it. Site data — supplied by `policy/`, never hardcoded. */
export interface ApprovedDevice {
  deviceId: string;
  deviceName: string;
  userEmail: string;
  v4: string;
  v6: string;
  /** Why this device is in policy at all. Free text, rendered as-is. */
  notes?: string;
}

function bad(msg: string): PolicyError {
  return new PolicyError(msg);
}

/**
 * Turn one approved device into the addresses a rule can match on.
 *
 * A bare address becomes a single-host prefix (`/32`, `/128`); one that already carries a prefix
 * length is passed through and validated as written. Both forms appear in practice — the registry
 * holds bare addresses, and a site author copying from a rendered ruleset will write the prefix.
 *
 * **A blank address is skipped, not refused.** The API returns `null` addresses for registrations
 * that have never come up, and `cf-devices.ts` keeps those visible while never expanding them into
 * policy. Skipping keeps that rule: the device is simply not matched on the family it has no address
 * for. Whether *nothing at all* came out is the caller's check, and it is fatal there.
 */
function addressesOf(d: ApprovedDevice, at: string): string[] {
  const out: string[] = [];
  for (const [field, raw] of [["v4", d.v4], ["v6", d.v6]] as const) {
    const value = String(raw ?? "").trim();
    if (!value) continue;
    let family;
    try {
      // Validated with the renderer's own parser rather than a second one written here. "What family
      // is this" and "is this an address at all" are the same question, and two parsers answering it
      // separately drift — the note on `familyOf` says so, and this is the caller that would drift.
      // Re-thrown as a `PolicyError` for the reason `policy.ts` re-throws `parseSelector`: a caller
      // catching bad policy input must not see this one class of bad input as a render failure.
      family = familyOf(value, `${at}: ${d.deviceId} ${field}`);
    } catch (e) {
      throw bad(e instanceof Error ? e.message : String(e));
    }
    if (value.includes("/")) {
      out.push(value);
      continue;
    }
    out.push(`${value}/${family === "ip" ? 32 : 128}`);
  }
  return out;
}

/** Case-insensitive, whitespace-trimmed — the form both sides of a lookup are compared in. */
function key(value: string): string {
  return String(value ?? "").trim().toLowerCase();
}

/**
 * Refuse a registry that cannot answer a lookup unambiguously.
 *
 * Two entries sharing a device id, or two whose emails differ only by case, make a `cf-user` union
 * mean more than the screen shows — and a union that silently covers an extra device is wider than
 * what anyone approved. Refused here rather than resolved by a rule like "last one wins", because
 * every such rule picks a winner nobody chose.
 */
function assertUnambiguous(devices: readonly ApprovedDevice[]): void {
  const ids = new Map<string, string>();
  for (const d of devices) {
    const id = key(d.deviceId);
    if (!id) throw bad("approved registry has a device with no deviceId");
    const seen = ids.get(id);
    if (seen !== undefined) {
      throw bad(
        `approved registry lists device ${JSON.stringify(d.deviceId)} twice ` +
          `(${JSON.stringify(seen)} and ${JSON.stringify(d.deviceName)}) — ` +
          `a lookup cannot say which one a policy meant`,
      );
    }
    ids.set(id, d.deviceName);
  }

  const emails = new Map<string, string>();
  for (const d of devices) {
    const email = key(d.userEmail);
    if (!email) continue; // Reported by the screen; not this function's refusal to make.
    const seen = emails.get(email);
    if (seen !== undefined && seen !== d.userEmail) {
      throw bad(
        `approved registry spells one user two ways (${JSON.stringify(seen)} and ` +
          `${JSON.stringify(d.userEmail)}) — a cf-user policy would union both, which is wider ` +
          `than either row reads`,
      );
    }
    emails.set(email, d.userEmail);
  }
}

/**
 * Expand a `cf-device` or `cf-user` endpoint into the CIDRs the host layer matches on.
 *
 * A device becomes its own addresses; a user becomes the union of their devices' addresses. The
 * result is sorted and deduplicated for the reason `normalizePorts` sorts: two orderings of the same
 * addresses are the same rule, and leaving them distinct makes every hash that covers the rendered
 * ruleset report a change that did not happen.
 *
 * **This is a lookup, not a resolver.** It answers from the approved list it is handed and refuses
 * anything absent from it. An unknown device id is not "a device with no addresses yet" — it is a
 * policy naming something nobody approved, and approving a device means editing the site module.
 */
export function deviceCidrs(devices: readonly ApprovedDevice[], e: Endpoint): string[] {
  if (e.kind !== "cf-device" && e.kind !== "cf-user") {
    throw bad(`deviceCidrs expands cf-device and cf-user endpoints, not ${e.kind}`);
  }
  assertUnambiguous(devices);

  const at = e.kind;
  const wanted = key(e.value);
  const matched = devices.filter((d) => key(e.kind === "cf-device" ? d.deviceId : d.userEmail) === wanted);

  if (matched.length === 0) {
    throw bad(
      e.kind === "cf-device"
        ? `cf-device ${JSON.stringify(e.value)} is not in the approved registry — a policy cannot ` +
          `name a device nobody approved. Add it to the site module first.`
        : `cf-user ${JSON.stringify(e.value)} has no approved devices — the policy would render ` +
          `with no source condition, which matches every peer rather than none.`,
    );
  }

  const cidrs = matched.flatMap((d) => addressesOf(d, at));
  if (cidrs.length === 0) {
    // Reachable only when every matched device is addressless. The devices exist and were approved,
    // so this is not the "unknown name" case above — and it is fatal for the same reason: what would
    // be handed to `srcCidrs` is the empty list that means "from anywhere".
    throw bad(
      `${at} ${JSON.stringify(e.value)} matched ${matched.length} approved ` +
        `device${matched.length === 1 ? "" : "s"} but none of them has an address — ` +
        `an empty address list renders as a rule with no address condition`,
    );
  }
  return [...new Set(cidrs)].sort();
}

/**
 * Expand an `object` endpoint into the CIDRs the host layer matches on.
 *
 * The reason an object is worth having here rather than two policies: a group is the set that
 * outlives the rule. "The operators" changes when a person joins or leaves, and with a group that is
 * one edit to one member list; without it, the rule has to be split per user, and then the policy set
 * records how many identities an endpoint can hold instead of what the rule is for.
 *
 * ## `host` members are refused, not skipped
 *
 * Resolving a host name needs the resolver the site injects, which this function is not given. It
 * could skip those members and expand the rest, and the result would look like a working group — one
 * quietly missing whichever members it could not resolve. A narrower rule than the group says is
 * still a rule nobody wrote, so it refuses and names the member.
 */
export function objectCidrs(
  objects: readonly FirewallObject[],
  devices: readonly ApprovedDevice[],
  e: Endpoint,
): string[] {
  if (e.kind !== "object") throw bad(`objectCidrs expands object endpoints, not ${e.kind}`);

  const found = objects.filter((o): o is AddressObject => o.kind === "address" && (o.id === e.value || o.name === e.value));
  if (found.length === 0) {
    throw bad(`object ${JSON.stringify(e.value)} is not an address object in this site`);
  }
  if (found.length > 1) {
    // One name resolving to two groups is the ambiguity `assertUnambiguous` refuses one level down,
    // and it arrives here whenever an id happens to equal another object's name.
    throw bad(`object ${JSON.stringify(e.value)} matches ${found.length} address objects — ids and names must not collide`);
  }
  const object = found[0]!;

  const cidrs = object.members.flatMap((m) => {
    if (m.kind === "cidr") return [m.value];
    if (m.kind === "cf-device" || m.kind === "cf-user") return deviceCidrs(devices, m);
    throw bad(
      `object ${JSON.stringify(object.id)} has a ${m.kind} member (${JSON.stringify(m.value)}) that ` +
        `this expansion cannot resolve — it has no host resolver, and dropping the member would ` +
        `render a narrower rule than the group describes`,
    );
  });

  if (cidrs.length === 0) {
    // Empty means "from anywhere", not "from nobody" — the same inversion as above, which is why an
    // empty expansion has to be an error rather than an empty rule.
    //
    // ⚠️ This used to say "`normalizeObject` already refuses an empty member list, so this is the
    // case where every member expanded to nothing." **That premise does not hold.**
    // `normalizeObject` has no runtime caller anywhere in this repository — it is defined, re-
    // exported from `index.ts`, and named in this sentence, and nothing else. `site.objects` reaches
    // the renderer through `bin/heliopause-publish.ts` typed as `FirewallObject[]`, and
    // `policy-source.ts` checks only `Array.isArray`. So a declared-but-empty group arrives here
    // unvalidated, and this check is not a second line of defence — it is the only one.
    throw bad(`object ${JSON.stringify(object.id)} expanded to no addresses`);
  }
  return [...new Set(cidrs)].sort();
}
