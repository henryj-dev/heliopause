// Two-person publishing: propose, approve, publish.
//
// Pure and in-memory, like `computeGate`. The I/O — reaching relays, reading certificates — stays in
// the caller, so the rule that decides whether a firewall change may proceed is testable as data.
//
// ## What this enforces and why it is not the request's job
//
// The design settled on "the approval is a fact the server remembers, not a value the requester
// claims" (docs/인터페이스-설계.md, 결정 4). That single sentence is most of this module:
//
//   · A plan is content-addressed. Approving and publishing name the same bytes, or the publish is
//     refused — so "approve the harmless one, publish the other" is not expressible.
//   · The approver's identity comes from their certificate, not their payload.
//   · The proposer may not approve their own plan. This is the whole point of the mechanism, and it
//     is checked against the *stored* proposer rather than anything in the approval request.
//
// ## Why plans expire
//
// A plan describes a rendering of policy at one moment. The policy moves. An approval from
// yesterday, published today, would apply rules nobody approved — with a generation id that looks
// legitimate because it *is* the one that was approved. The window is short on purpose: long enough
// for a colleague to read a diff, short enough that the tree cannot have moved much underneath it.
//
// ## Why publishing consumes the approval
//
// Otherwise one approval is a standing permission. An operator who gets a plan approved could
// re-publish it any time afterwards — including after the policy has been deliberately changed to
// something else, which makes it a rollback nobody asked for wearing an approved generation id.

/** A plan waiting for approval, or approved and waiting to be published. */
export interface Plan {
  /**
   * Content address of the artifacts, not of the request.
   *
   * This is what makes approval mean something: the bytes that were read are the bytes that get
   * published, and the server can check it rather than trusting either party to be consistent.
   */
  hash: string;
  /** Generation id the artifacts carry. Reported, never trusted for identity — `hash` is identity. */
  generation: string;
  /** Certificate CN of whoever submitted it. */
  proposedBy: string;
  proposedAt: string;
  /** One line per host, for a reviewer who has to decide without re-rendering anything. */
  summary: PlanSummary;
  /** Set once approved. `null` while pending. */
  /**
   * Who vouched for this plan, and when. `solo` marks an approval by the proposer themselves.
   *
   * Absent rather than `false` on an ordinary approval, so the audit trail reads as "this happened"
   * rather than "this did not happen" on every normal plan — the interesting record is the rare one.
   */
  approval: { by: string; at: string; solo?: true } | null;
  /** Set once published, which is also what stops it being published again. */
  publishedAt: string | null;
}

/**
 * What an approver reads. Derived by the server from the bundle, never supplied by the proposer.
 *
 * ## Why the renderer's warnings are not here
 *
 * They would be useful — a Cilium warning means the rendered rule is wider or narrower than what was
 * written, which is exactly what an approver wants to know. The manager cannot recompute them: it has
 * no policy, by design (the repository is private and is never in this image). So the only way to show
 * them is to accept them from the proposer, and a proposal that can choose which warnings accompany it
 * can present itself as clean. An absent warning is the dangerous case and labelling the list
 * "unverified" does not fix an omission.
 *
 * What an approver has instead: the plan hash, and the policy diff in git. That is where a firewall
 * change is actually legible, and it is a source the proposer cannot edit after the fact.
 */
export interface PlanSummary {
  hosts: Array<{ host: string; stage: string; ruleCount: number; rulesetHash: string }>;
}

export interface ApprovalLimits {
  /**
   * How long a pending plan stays publishable, in seconds.
   *
   * Applied from `proposedAt`, not from the approval: the risk being bounded is the policy tree
   * moving under a rendering, and that clock starts when the rendering happened.
   */
  ttlSec: number;
  /** Most plans held at once. A bound, so a loop that proposes cannot exhaust the process. */
  maxPending: number;
}

export const DEFAULT_LIMITS: ApprovalLimits = {
  // Ten minutes. Long enough to read a diff and walk to someone's desk, short enough that the
  // policy repository cannot plausibly have moved twice.
  ttlSec: 600,
  maxPending: 32,
};

/** Why an operation was refused. The message is shown to an operator, so it says what to do next. */
export class ApprovalError extends Error {
  /**
   * HTTP status the caller should use. Kept on the error so every refusal has one obvious mapping and
   * the route handler does not re-decide it from the message text.
   *
   * Assigned in the body rather than declared as a constructor parameter property: Node runs this
   * TypeScript by stripping types, and a parameter property is not erasable — it has a runtime effect.
   */
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApprovalError";
    this.status = status;
  }
}

export interface ApprovalState {
  plans: Map<string, Plan>;
}

export function emptyApprovals(): ApprovalState {
  return { plans: new Map() };
}

function expired(p: Plan, now: Date, limits: ApprovalLimits): boolean {
  return now.getTime() - new Date(p.proposedAt).getTime() > limits.ttlSec * 1000;
}

/**
 * Drop what can no longer be used.
 *
 * Published plans are dropped too, not kept as history. This is not the audit trail — git is, and a
 * published generation is recorded there and in the relay's manifest. Keeping a second copy here
 * would invite reading it as authoritative while it silently disappears on restart.
 */
export function sweep(state: ApprovalState, now: Date, limits = DEFAULT_LIMITS): void {
  for (const [hash, p] of state.plans) {
    if (p.publishedAt || expired(p, now, limits)) state.plans.delete(hash);
  }
}

export function propose(
  state: ApprovalState,
  input: { hash: string; generation: string; summary: PlanSummary; by: string; now: Date },
  limits = DEFAULT_LIMITS,
): Plan {
  sweep(state, input.now, limits);
  if (!input.by) throw new ApprovalError("no operator identity on the request", 401);
  if (!/^sha256:[0-9a-f]{64}$/.test(input.hash)) {
    throw new ApprovalError(`plan hash ${JSON.stringify(input.hash)} is not a sha256 digest`, 400);
  }

  const existing = state.plans.get(input.hash);
  if (existing) {
    // Re-proposing identical content is idempotent rather than an error: a CLI that retried after a
    // timeout must not create a second plan, and must not reset an approval already given.
    //
    // The proposer is **not** overwritten. If it were, a second operator could re-propose a plan and
    // become its proposer, freeing the original proposer to approve it — the two-person rule
    // defeated by replaying a request that changes nothing.
    return existing;
  }

  if (state.plans.size >= limits.maxPending) {
    throw new ApprovalError(
      `${limits.maxPending} plans already pending — approve or let them expire before proposing more`,
      429,
    );
  }

  const plan: Plan = {
    hash: input.hash,
    generation: input.generation,
    proposedBy: input.by,
    proposedAt: input.now.toISOString(),
    summary: input.summary,
    approval: null,
    publishedAt: null,
  };
  state.plans.set(plan.hash, plan);
  return plan;
}

export function approve(
  state: ApprovalState,
  input: {
    hash: string;
    by: string;
    now: Date;
    /**
     * Whether this approver may approve a plan they proposed themselves.
     *
     * **Defaults to false, and every existing caller keeps that.** The parameter exists because one
     * site with one operator decided the alternative — nothing publishable through the API at all —
     * was worse. It is not a convenience: the caller that passes `true` is required to have checked
     * a one-time code first, and the plan records that this happened.
     *
     * Named for what it permits rather than who may do it. "admin" is a fact about a person; this is
     * a fact about a single approval, and it is the approval that the audit trail has to explain.
     */
    mayApproveOwn?: boolean;
    /**
     * Other names that are **the same human** as `by`, as the deployment itself declares.
     *
     * ## Why a string comparison was not enough, measured on the live manager
     *
     * The rule below compares `plan.proposedBy` with `by`. Both are certificate names, and one
     * person can hold two certificates — which the deployment says out loud in its own
     * configuration. From dev on 2026-08-24:
     *
     *     HELIOPAUSE_WRITER_CNS = ops-henry,ops-henry-review
     *     HELIOPAUSE_OTP_USERS  = ops-henry=5b1ed54b-…, ops-henry-review=5b1ed54b-…
     *
     * Two writer names, **one KeyStone user id**. So `ops-henry` proposes, `ops-henry-review`
     * approves, and the comparison passes because the strings differ. The one-time code does not
     * catch it either: both names resolve to the same account, so the same TOTP credential answers
     * for both.
     *
     * ## What the harm actually is
     *
     * Not that one person can publish alone — this site already permits that deliberately, through
     * `soloApprovalRoles`, and `approve` records `solo: true` when it happens. The harm is that this
     * route produces the same outcome **while the record says two people signed off**. An audit
     * reading that plan cannot tell the two apart, which is the one thing the field exists for.
     *
     * `oidc-authz.ts` already argues this exact point in the other direction — an OIDC identity must
     * alias onto a certificate name, "because one human arriving as `ops-alice` by certificate and
     * as `jang@…` by OIDC is two strings". The same argument was never applied to two certificates.
     *
     * So the caller resolves identity and passes it. Empty or absent keeps the previous behaviour,
     * which is what every caller without an OTP user map gets.
     */
    alsoKnownAs?: readonly string[];
  },
  limits = DEFAULT_LIMITS,
): Plan {
  sweep(state, input.now, limits);
  if (!input.by) throw new ApprovalError("no operator identity on the request", 401);

  const plan = state.plans.get(input.hash);
  if (!plan) {
    throw new ApprovalError(
      `no pending plan ${input.hash} — it may have expired (${limits.ttlSec}s) or already been published`,
      404,
    );
  }
  // The same *person*, not the same string. `alsoKnownAs` carries the other certificate names the
  // deployment declares to be this human — see its comment for the live configuration where two
  // writer names shared one identity-provider account.
  const sameHuman = plan.proposedBy === input.by || (input.alsoKnownAs ?? []).includes(plan.proposedBy);
  if (sameHuman && !input.mayApproveOwn) {
    // The rule this whole module exists for. Checked against the stored proposer, so it cannot be
    // sidestepped by anything in this request.
    throw new ApprovalError(
      plan.proposedBy === input.by
        ? `${input.by} proposed this plan and cannot approve it — a second operator must`
        : `${input.by} is the same person as ${plan.proposedBy} (both map to one identity-provider ` +
          `account), so this would be a one-person approval recorded as two — a different operator must`,
      403,
    );
  }
  if (plan.approval) {
    // Already approved, by someone. Idempotent for the same approver, refused for a different one:
    // a second approval would silently overwrite the record of who actually vouched for it.
    if (plan.approval.by === input.by) return plan;
    throw new ApprovalError(`already approved by ${plan.approval.by}`, 409);
  }
  // `solo` is recorded, not inferred. Comparing `approval.by` to `proposedBy` later would give the
  // same answer today and would stop doing so the moment either field is ever normalised — and the
  // question "did one person do this alone" is exactly the one an audit asks first.
  //
  // `sameHuman`, not `proposedBy === by`. Reaching here with two different names for one person
  // means `mayApproveOwn` allowed it, and it is still one person — writing `solo` only for the
  // exact-name case would leave the audit trail saying two, which is the failure this whole
  // parameter exists to close.
  plan.approval = {
    by: input.by,
    at: input.now.toISOString(),
    ...(sameHuman ? { solo: true } : {}),
  };
  return plan;
}

/**
 * Check a plan may be published, and mark it used.
 *
 * Returns the plan so the caller can log who proposed and who approved. Throws on every path that
 * is not "approved, unexpired, unpublished" — there is no boolean return, because a caller that
 * ignores a false is a caller that publishes an unapproved generation.
 */
export function claimForPublish(
  state: ApprovalState,
  input: { hash: string; by: string; now: Date },
  limits = DEFAULT_LIMITS,
): Plan {
  if (!input.by) throw new ApprovalError("no operator identity on the request", 401);
  const plan = state.plans.get(input.hash);

  // Deliberately before `sweep`, so an expired plan gets its own message rather than "not found".
  // "It expired" and "it never existed" send an operator to different places.
  if (plan && expired(plan, input.now, limits)) {
    state.plans.delete(plan.hash);
    throw new ApprovalError(
      `plan ${input.hash} expired after ${limits.ttlSec}s — re-propose it, so what is published is ` +
        `a rendering of the policy as it is now`,
      410,
    );
  }
  sweep(state, input.now, limits);

  if (!plan) throw new ApprovalError(`no pending plan ${input.hash}`, 404);
  if (!plan.approval) {
    throw new ApprovalError(
      `plan ${input.hash} has not been approved — a second operator must approve it first`,
      403,
    );
  }
  if (plan.publishedAt) throw new ApprovalError(`plan ${input.hash} has already been published`, 409);

  plan.publishedAt = input.now.toISOString();
  return plan;
}

/**
 * Undo a claim, for when the publish it was claimed for did not reach a single relay.
 *
 * ## Why this exists rather than "claim after a successful push"
 *
 * Claiming afterwards would leave a window where two concurrent publishes both pass the check and
 * both push. Claiming first closes that, but then a push that failed outright leaves an approved plan
 * permanently unpublishable — and re-proposing produces the *same* hash, because the bundle is
 * deterministic, so the retry is refused as already published. During an incident that reads as "the
 * publish is broken and cannot be retried".
 *
 * So the claim is released only when nothing was written anywhere. A partial push is deliberately
 * **not** released: the generation is live on some relays, and pushing it again is a new act on a
 * fleet that is now inconsistent. That deserves a fresh pair of eyes rather than a retry button.
 */
export function release(state: ApprovalState, hash: string): void {
  const plan = state.plans.get(hash);
  if (plan) plan.publishedAt = null;
}

/** Pending plans, newest first, for an operator deciding what to review. */
export function listPlans(state: ApprovalState, now: Date, limits = DEFAULT_LIMITS): Plan[] {
  sweep(state, now, limits);
  return [...state.plans.values()].sort((a, b) => b.proposedAt.localeCompare(a.proposedAt));
}
