// GET /api/plans, as this package is allowed to see it.
//
// Duplicated rather than imported from `heliopause`: the web package must not
// pull the library into a Vite bundle. The fields here are what the changes
// screen renders and what the write buttons are derived from.

export interface PlanHost {
  host: string;
  stage: string;
  ruleCount: number;
  rulesetHash: string;
}

export interface PlanRow {
  hash: string;
  generation: string;
  proposedBy: string;
  proposedAt: string;
  summary: { hosts: PlanHost[] };
  approval: { by: string; at: string; solo?: true } | null;
  publishedAt: string | null;
  /** VPC this plan was proposed for. Null when the manager no longer holds the mapping. */
  target: string | null;
}

export interface PlansView {
  plans: PlanRow[];
  limits: { ttlSec: number; maxPending: number | null };
  you: string;
  canWrite: boolean;
  maySoloApprove: boolean;
  targets: string[];
  csrf: string | null;
}

export type PlansRead =
  | { ok: true; view: PlansView }
  | { ok: false; reason: string };

export type PlanStage = "awaiting" | "approved" | "published";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readHost(value: unknown): PlanHost | null {
  if (!isRecord(value)) return null;
  if (typeof value.host !== "string" || typeof value.stage !== "string") return null;
  if (typeof value.ruleCount !== "number" || typeof value.rulesetHash !== "string") return null;
  return {
    host: value.host,
    stage: value.stage,
    ruleCount: value.ruleCount,
    rulesetHash: value.rulesetHash,
  };
}

function readApproval(value: unknown): PlanRow["approval"] {
  if (value === null || value === undefined) return null;
  if (!isRecord(value) || typeof value.by !== "string" || typeof value.at !== "string") return null;
  return { by: value.by, at: value.at, ...(value.solo === true ? { solo: true as const } : {}) };
}

function readPlan(value: unknown): PlanRow | null {
  if (!isRecord(value)) return null;
  if (typeof value.hash !== "string" || typeof value.generation !== "string") return null;
  if (typeof value.proposedBy !== "string" || typeof value.proposedAt !== "string") return null;
  if (!isRecord(value.summary) || !Array.isArray(value.summary.hosts)) return null;
  const hosts: PlanHost[] = [];
  for (const row of value.summary.hosts) {
    const host = readHost(row);
    if (!host) return null;
    hosts.push(host);
  }
  const approval = readApproval(value.approval);
  if (value.approval !== null && value.approval !== undefined && approval === null) return null;
  const publishedAt = value.publishedAt === null || value.publishedAt === undefined
    ? null
    : typeof value.publishedAt === "string" ? value.publishedAt : null;
  if (value.publishedAt !== null && value.publishedAt !== undefined && publishedAt === null) return null;
  return {
    hash: value.hash,
    generation: value.generation,
    proposedBy: value.proposedBy,
    proposedAt: value.proposedAt,
    summary: { hosts },
    approval,
    publishedAt,
    target: typeof value.target === "string" && value.target !== "" ? value.target : null,
  };
}

export function readPlansView(data: unknown): PlansRead {
  if (!isRecord(data)) return { ok: false, reason: "plans view is not an object" };
  if (typeof data.you !== "string") return { ok: false, reason: "plans view is missing you" };
  if (typeof data.canWrite !== "boolean") return { ok: false, reason: "plans view is missing canWrite" };
  if (!isRecord(data.limits) || typeof data.limits.ttlSec !== "number") {
    return { ok: false, reason: "plans view is missing limits" };
  }
  if (!Array.isArray(data.plans)) return { ok: false, reason: "plans view is missing plans" };
  const plans: PlanRow[] = [];
  for (const row of data.plans) {
    const plan = readPlan(row);
    if (!plan) return { ok: false, reason: "a plan row is malformed" };
    plans.push(plan);
  }
  const targets = Array.isArray(data.targets)
    ? data.targets.filter((t): t is string => typeof t === "string")
    : [];
  return {
    ok: true,
    view: {
      plans,
      limits: {
        ttlSec: data.limits.ttlSec,
        maxPending: typeof data.limits.maxPending === "number" ? data.limits.maxPending : null,
      },
      you: data.you,
      canWrite: data.canWrite,
      maySoloApprove: data.maySoloApprove === true,
      targets,
      csrf: typeof data.csrf === "string" ? data.csrf : null,
    },
  };
}

export function planStage(plan: PlanRow): PlanStage {
  if (plan.publishedAt) return "published";
  if (plan.approval) return "approved";
  return "awaiting";
}

/** Shown, not attempted-and-refused. A button that exists to return 403 is noise. */
export function canOfferApprove(
  plan: PlanRow,
  you: string,
  canWrite: boolean,
  maySoloApprove: boolean,
): boolean {
  if (!canWrite || plan.approval || plan.publishedAt) return false;
  if (plan.proposedBy !== you) return true;
  return maySoloApprove;
}

export function canOfferPublish(plan: PlanRow, canWrite: boolean): boolean {
  return canWrite && plan.approval !== null && plan.publishedAt === null;
}
