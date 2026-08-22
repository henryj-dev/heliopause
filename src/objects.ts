// Reusable address and service objects — the address-group / service-object of commercial
// firewalls. Policies reference them by name:
//   · addresses: `src`/`dst` as `{ kind: "object", value: "<name>" }`
//   · ports:     `ports` as `"@<name>"`
//
// **Validation is the whole point of this module.** A group is reused across many policies, so a
// single wrongly-accepted member silently changes the meaning of all of them. The rejections
// below are therefore deliberate, not incidental:
//   · empty groups — produce no match condition, so the rule matches *everything*
//   · nested references — cycle detection and depth limits cost more than they are worth here
//   · `internet` / `any` members — one member would make the whole group mean "everything"
import { normalizeIdentityValue, normalizePorts, PolicyError, type Endpoint, type EndpointKind } from "./policy.ts";

export type ObjectKind = "address" | "service";

export interface AddressObject {
  id: string;
  kind: "address";
  name: string;
  members: Endpoint[];
  notes?: string;
}

export interface ServiceObject {
  id: string;
  kind: "service";
  name: string;
  /** Port specs — `"22"`, `"1000:2000"`. Protocol lives on the policy, not here. */
  members: string[];
  notes?: string;
}

export type FirewallObject = AddressObject | ServiceObject;

function bad(msg: string): PolicyError {
  return new PolicyError(msg);
}

/** Must match the character set accepted in a policy's `"@name"` reference. */
const NAME_RE = /^[A-Za-z0-9_.\- ]{1,60}$/;

// `cf-device` and `cf-user` are members for the reason the group exists at all: "the operators" is a
// set that outlives any one rule, and without it a policy naming two people has to be two policies —
// which makes the policy set describe how many users an endpoint can hold rather than what the rule
// is for. They are not the nesting this module refuses: an identity resolves against the approved
// registry (site data, like a host name), not against another object, so there is no cycle to chase.
const ADDRESS_MEMBER_KINDS = new Set<EndpointKind>(["host", "host-group", "cidr", "cf-device", "cf-user"]);

function normalizeAddressMember(raw: unknown, i: number): Endpoint {
  const o = (raw ?? {}) as Partial<Endpoint>;
  const kind = String(o.kind ?? "").trim() as EndpointKind;
  if (!ADDRESS_MEMBER_KINDS.has(kind)) {
    throw bad(
      `members[${i}].kind must be one of ${[...ADDRESS_MEMBER_KINDS].join("|")} (got "${kind}") — ` +
        `nested objects and internet/any are not allowed as members`,
    );
  }
  const value = String(o.value ?? "").trim();
  if (!value) throw bad(`members[${i}].value is required`);
  if (kind === "cidr" && !/^[0-9a-fA-F.:]+\/\d{1,3}$/.test(value)) {
    throw bad(`members[${i}].value must be a CIDR, e.g. 10.0.0.0/16`);
  }
  // Checked by the same function `normalizePolicy` uses, not by a copy of it. A member the policy
  // layer would accept and this one would not — or the reverse — is a group entry that resolves to
  // nothing while reading as a member.
  if (kind === "cf-device" || kind === "cf-user") {
    return { kind, value: normalizeIdentityValue(kind, value, `members[${i}]`) };
  }
  return { kind, value };
}

function normalizeServiceMember(raw: unknown, i: number): string {
  const v = String(raw ?? "").trim();
  if (!v) throw bad(`members[${i}] is empty`);
  // Lists and references inside a member recreate the nesting problem.
  if (v.includes(",")) throw bad(`members[${i}] must hold one port spec (use separate members for a list)`);
  if (v.startsWith("@")) throw bad(`members[${i}] cannot reference another service object (no nesting)`);
  // Protocol comes from the policy; validate shape only.
  return normalizePorts(v, "tcp");
}

export function normalizeObject(input: unknown, id: string): FirewallObject {
  const o = (input ?? {}) as Record<string, unknown>;
  const kind = String(o.kind ?? "").trim() as ObjectKind;
  if (kind !== "address" && kind !== "service") throw bad("kind must be address or service");

  const name = String(o.name ?? "").trim();
  if (!NAME_RE.test(name)) {
    throw bad("name must be 1-60 chars of letters, digits, underscore, dot, hyphen or space (same rule as @references)");
  }

  const raw = Array.isArray(o.members) ? o.members : [];
  if (raw.length === 0) {
    throw bad("members is empty — add at least one (an empty group matches all traffic)");
  }
  const notes = String(o.notes ?? "").trim();

  if (kind === "address") {
    const members = raw.map(normalizeAddressMember);
    // Duplicates carry no meaning and only perturb fingerprints.
    const seen = new Set<string>();
    const uniq = members.filter((m) => {
      const k = `${m.kind}:${m.value}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    return { id, kind, name, members: uniq, notes };
  }

  const members = [...new Set(raw.map(normalizeServiceMember))].sort(
    (a, b) => Number(a.split(":")[0]) - Number(b.split(":")[0]),
  );
  return { id, kind, name, members, notes };
}
