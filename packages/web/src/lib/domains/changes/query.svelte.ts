import { applyHeldPoll, type Held } from "../../poll.ts";
import { changesPath, readPlanDiff, type PlanDiff } from "./diff";
import { readPlansView, type PlanRow, type PlansView } from "./plans";

export const PLANS_POLL_MS = 10_000;

export type PlansState =
  | { kind: "loading" }
  | { kind: "unauth" }
  | { kind: "error"; message: string }
  | { kind: "ok"; view: PlansView; lastOkAt: number; failCount: number; lastFail: string | null };

export function plansQuery() {
  let state = $state<PlansState>({ kind: "loading" });
  let held = $state<Held<PlansView> | null>(null);
  let diffs = $state<Record<string, PlanDiff>>({});

  function paint(next: Held<PlansView> | null, firstFail?: string): void {
    held = next;
    if (next) {
      state = {
        kind: "ok",
        view: next.value,
        lastOkAt: next.lastOkAt,
        failCount: next.failCount,
        lastFail: next.lastFail,
      };
      return;
    }
    state = firstFail ? { kind: "error", message: firstFail } : { kind: "unauth" };
  }

  async function loadDiffs(plans: readonly PlanRow[]): Promise<void> {
    const pending = plans.filter((plan) => !plan.publishedAt);
    const next: Record<string, PlanDiff> = { ...diffs };
    await Promise.all(pending.map(async (plan) => {
      try {
        const res = await fetch(changesPath(plan.hash), { credentials: "include" });
        next[plan.hash] = readPlanDiff(await res.json(), res.status);
      } catch (e) {
        next[plan.hash] = { kind: "error", reason: (e as Error).message };
      }
    }));
    diffs = next;
  }

  async function refresh(): Promise<void> {
    try {
      const res = await fetch("/api/plans", { credentials: "include" });
      if (res.status === 401) {
        paint(applyHeldPoll(held, { kind: "unauth" }));
        diffs = {};
        return;
      }
      if (!res.ok) {
        const reason = `GET /api/plans returned ${res.status}`;
        paint(applyHeldPoll(held, { kind: "fail", reason }), reason);
        return;
      }
      const read = readPlansView(await res.json());
      if (!read.ok) {
        paint(applyHeldPoll(held, { kind: "fail", reason: read.reason }), read.reason);
        return;
      }
      paint(applyHeldPoll(held, { kind: "ok", value: read.view, at: Date.now() }));
      void loadDiffs(read.view.plans);
    } catch (e) {
      const reason = (e as Error).message;
      paint(applyHeldPoll(held, { kind: "fail", reason }), reason);
    }
  }

  return {
    get state() {
      return state;
    },
    get diffs() {
      return diffs;
    },
    refresh,
  };
}
