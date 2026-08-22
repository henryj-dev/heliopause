import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { normalizePolicy, PolicyError, type Policy } from "./policy.ts";

export const POLICY_DOCUMENT_SCHEMA = 2 as const;

export type PolicyPlacement =
  | { layer: "input"; policyId: string; host: string; srcCidrs: string[]; dstCidrs: string[] }
  | { layer: "egress"; policyId: string; host: string; dstCidrs: string[] | null }
  | { layer: "workload"; policyId: string; srcCidrs?: string[]; dstCidrs?: string[] };

export interface PolicyDocument {
  schemaVersion: 1 | typeof POLICY_DOCUMENT_SCHEMA;
  policies: Policy[];
  placements?: PolicyPlacement[];
}

export class PolicyStoreError extends Error {
  readonly statusCode = 400;
}

function parseDocument(raw: unknown, source: string): PolicyDocument {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new PolicyStoreError(`${source}: policy document must be a JSON object`);
  }
  const input = raw as { schemaVersion?: unknown; policies?: unknown; placements?: unknown };
  if (input.schemaVersion !== 1 && input.schemaVersion !== POLICY_DOCUMENT_SCHEMA) {
    throw new PolicyStoreError(
      `${source}: schemaVersion must be 1 or ${POLICY_DOCUMENT_SCHEMA}, got ${String(input.schemaVersion)}`,
    );
  }
  if (!Array.isArray(input.policies)) {
    throw new PolicyStoreError(`${source}: policies must be an array`);
  }

  const seen = new Set<string>();
  const policies = input.policies.map((value, index) => {
    const id = String((value as { id?: unknown } | null)?.id ?? "").trim();
    if (!id) throw new PolicyStoreError(`${source}: policies[${index}].id is required`);
    if (seen.has(id)) throw new PolicyStoreError(`${source}: duplicate policy id ${JSON.stringify(id)}`);
    seen.add(id);
    try {
      return normalizePolicy(value, id);
    } catch (e) {
      if (e instanceof PolicyError) {
        throw new PolicyStoreError(`${source}: policy ${id}: ${e.message}`);
      }
      throw e;
    }
  });
  if (input.schemaVersion === 1) return { schemaVersion: 1, policies };
  if (!Array.isArray(input.placements)) throw new PolicyStoreError(`${source}: schema 2 placements must be an array`);
  const placements = input.placements.map((rawPlacement, index): PolicyPlacement => {
    if (!rawPlacement || typeof rawPlacement !== "object" || Array.isArray(rawPlacement)) throw new PolicyStoreError(`${source}: placements[${index}] must be an object`);
    const p = rawPlacement as Record<string, unknown>; const layer = p.layer; const policyId = String(p.policyId ?? "").trim();
    if (!policyId || !seen.has(policyId)) throw new PolicyStoreError(`${source}: placements[${index}] names unknown policy ${JSON.stringify(policyId)}`);
    const cidrs = (value: unknown, name: string): string[] => {
      if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) throw new PolicyStoreError(`${source}: placements[${index}].${name} must be a string array`);
      return [...new Set(value.map((item) => String(item).trim()).filter(Boolean))];
    };
    if (layer === "input") return { layer, policyId, host: String(p.host ?? "").trim(), srcCidrs: cidrs(p.srcCidrs, "srcCidrs"), dstCidrs: cidrs(p.dstCidrs, "dstCidrs") };
    if (layer === "egress") return { layer, policyId, host: String(p.host ?? "").trim(), dstCidrs: p.dstCidrs === null ? null : cidrs(p.dstCidrs, "dstCidrs") };
    if (layer === "workload") return { layer, policyId, ...(p.srcCidrs === undefined ? {} : { srcCidrs: cidrs(p.srcCidrs, "srcCidrs") }), ...(p.dstCidrs === undefined ? {} : { dstCidrs: cidrs(p.dstCidrs, "dstCidrs") }) };
    throw new PolicyStoreError(`${source}: placements[${index}].layer must be input, egress or workload`);
  });
  for (const [index, placement] of placements.entries()) if (placement.layer !== "workload" && !placement.host) throw new PolicyStoreError(`${source}: placements[${index}].host is required`);
  return { schemaVersion: POLICY_DOCUMENT_SCHEMA, policies, placements };
}

export function emptyPolicyDocument(): PolicyDocument {
  return { schemaVersion: POLICY_DOCUMENT_SCHEMA, policies: [], placements: [] };
}

export function loadPolicyDocument(path: string): PolicyDocument {
  const full = resolve(path);
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(full, "utf8"));
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    throw new PolicyStoreError(
      err.code === "ENOENT" ? `${full}: policy document does not exist` : `${full}: invalid JSON (${err.message})`,
    );
  }
  return parseDocument(parsed, full);
}

/** Atomic replacement: readers see the old complete document or the new complete document. */
export function savePolicyDocument(path: string, document: PolicyDocument): PolicyDocument {
  const full = resolve(path);
  const valid = parseDocument(document, full);
  mkdirSync(dirname(full), { recursive: true });
  const tmp = `${full}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(valid, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  renameSync(tmp, full);
  return valid;
}

export function putPolicy(document: PolicyDocument, policy: Policy): { document: PolicyDocument; created: boolean } {
  const valid = normalizePolicy(policy, policy.id);
  const index = document.policies.findIndex((p) => p.id === valid.id);
  if (index < 0) {
    return { document: parseDocument({ ...document, policies: [...document.policies, valid] }, "document"), created: true };
  }
  const policies = [...document.policies];
  policies[index] = valid;
  return { document: parseDocument({ ...document, policies }, "document"), created: false };
}

export function removePolicy(document: PolicyDocument, id: string): PolicyDocument {
  if (!document.policies.some((p) => p.id === id)) {
    throw new PolicyStoreError(`policy ${JSON.stringify(id)} does not exist`);
  }
  return parseDocument({ ...document, policies: document.policies.filter((p) => p.id !== id), ...(document.schemaVersion === 2 ? { placements: (document.placements ?? []).filter((p) => p.policyId !== id) } : {}) }, "document");
}

export function replacePolicyPlacements(document: PolicyDocument, policyId: string, placements: PolicyPlacement[]): PolicyDocument {
  if (document.schemaVersion !== 2) throw new PolicyStoreError("placements require a schema 2 policy document");
  if (!document.policies.some((policy) => policy.id === policyId)) throw new PolicyStoreError(`policy ${JSON.stringify(policyId)} does not exist`);
  if (placements.some((placement) => placement.policyId !== policyId)) throw new PolicyStoreError("every replacement placement must name the policy being replaced");
  return parseDocument({ ...document, placements: [...(document.placements ?? []).filter((placement) => placement.policyId !== policyId), ...placements] }, "document");
}
