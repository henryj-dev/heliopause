import type { CiliumItem } from "./cilium.ts";
import type { PolicyDocument, PolicyPlacement } from "./policy-store.ts";
import type { PublishHost } from "./publish.ts";

export interface PolicyBearingSite {
  hosts: PublishHost[];
  workload?: CiliumItem[];
}

export class SitePolicyError extends Error {
  readonly statusCode = 400;
}

/** Return each embedded policy once, refusing inconsistent duplicate definitions. */
export function policiesFromSite(site: PolicyBearingSite) {
  const policies = new Map<string, PublishHost["items"][number]["policy"]>();
  const add = (policy: PublishHost["items"][number]["policy"]): void => {
    const previous = policies.get(policy.id);
    if (previous && JSON.stringify(previous) !== JSON.stringify(policy)) {
      throw new SitePolicyError(`site contains different definitions for policy ${JSON.stringify(policy.id)}`);
    }
    policies.set(policy.id, policy);
  };
  for (const host of site.hosts) {
    host.items.forEach((item) => add(item.policy));
    (host.egress ?? []).forEach((item) => add(item.policy));
  }
  (site.workload ?? []).forEach((item) => add(item.policy));
  return [...policies.values()];
}

export function placementsFromSite(site: PolicyBearingSite): PolicyPlacement[] {
  const placements: PolicyPlacement[] = [];
  for (const host of site.hosts) {
    for (const item of host.items) placements.push({ layer: "input", policyId: item.policy.id, host: host.id, srcCidrs: item.srcCidrs, dstCidrs: item.dstCidrs });
    for (const item of host.egress ?? []) placements.push({ layer: "egress", policyId: item.policy.id, host: host.id, dstCidrs: item.dstCidrs });
  }
  for (const item of site.workload ?? []) placements.push({ layer: "workload", policyId: item.policy.id, ...(item.srcCidrs ? { srcCidrs: item.srcCidrs } : {}), ...(item.dstCidrs ? { dstCidrs: item.dstCidrs } : {}) });
  return placements;
}

/**
 * Replace policy definitions while retaining the site's placement and resolution wiring.
 *
 * Exact id parity is required. Silently retaining an omitted policy or ignoring an unknown one
 * would make the editor show a document different from the generation that is actually rendered.
 */
export function applyPolicyDocument<T extends PolicyBearingSite>(site: T, document: PolicyDocument): T {
  if (document.schemaVersion === 2) {
    const placements = document.placements ?? [];
    const byId = new Map(document.policies.map((policy) => [policy.id, policy]));
    const hosts = new Map(site.hosts.map((host) => [host.id, { ...host, items: [], egress: [] } as PublishHost]));
    for (const policy of document.policies) {
      if (!placements.some((placement) => placement.policyId === policy.id)) throw new SitePolicyError(`policy ${policy.id} has no placement`);
    }
    for (const placement of placements) {
      const policy = byId.get(placement.policyId)!;
      if (placement.layer === "input") {
        const host = hosts.get(placement.host); if (!host) throw new SitePolicyError(`placement for ${policy.id} names unknown host ${placement.host}`);
        host.items.push({ policy, srcCidrs: placement.srcCidrs, dstCidrs: placement.dstCidrs });
      } else if (placement.layer === "egress") {
        const host = hosts.get(placement.host); if (!host) throw new SitePolicyError(`placement for ${policy.id} names unknown host ${placement.host}`);
        host.egress!.push({ policy, dstCidrs: placement.dstCidrs });
      }
    }
    const workload = placements.filter((placement): placement is Extract<PolicyPlacement, { layer: "workload" }> => placement.layer === "workload")
      .map((placement) => ({ policy: byId.get(placement.policyId)!, ...(placement.srcCidrs ? { srcCidrs: placement.srcCidrs } : {}), ...(placement.dstCidrs ? { dstCidrs: placement.dstCidrs } : {}) }));
    return { ...site, hosts: [...hosts.values()], ...(workload.length ? { workload } : {}) } as T;
  }
  const embedded = policiesFromSite(site);
  const siteIds = new Set(embedded.map((policy) => policy.id));
  const documentIds = new Set(document.policies.map((policy) => policy.id));
  const missing = [...siteIds].filter((id) => !documentIds.has(id)).sort();
  const unknown = [...documentIds].filter((id) => !siteIds.has(id)).sort();
  if (missing.length || unknown.length) {
    throw new SitePolicyError(
      [
        missing.length ? `document is missing site policies: ${missing.join(", ")}` : "",
        unknown.length ? `document contains policies with no site placement: ${unknown.join(", ")}` : "",
      ].filter(Boolean).join("; "),
    );
  }

  const byId = new Map(document.policies.map((policy) => [policy.id, policy]));
  return {
    ...site,
    hosts: site.hosts.map((host) => ({
      ...host,
      items: host.items.map((item) => ({ ...item, policy: byId.get(item.policy.id)! })),
      ...(host.egress
        ? { egress: host.egress.map((item) => ({ ...item, policy: byId.get(item.policy.id)! })) }
        : {}),
    })),
    ...(site.workload
      ? { workload: site.workload.map((item) => ({ ...item, policy: byId.get(item.policy.id)! })) }
      : {}),
  };
}
