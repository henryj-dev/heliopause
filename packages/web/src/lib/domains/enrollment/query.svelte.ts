import { applyHeldPoll, type Held } from "../../poll.ts";
import { readEnrollmentView, type EnrollmentView } from "./store";

export const ENROLLMENT_POLL_MS = 10_000;

export type EnrollmentState =
  | { kind: "loading" }
  | { kind: "absent" }
  | { kind: "unauth" }
  | { kind: "error"; message: string }
  | { kind: "ok"; view: EnrollmentView; lastOkAt: number; failCount: number; lastFail: string | null };

async function readJson(res: Response): Promise<unknown> {
  return res.json();
}

export function enrollmentQuery() {
  let state = $state<EnrollmentState>({ kind: "loading" });
  let held = $state<Held<EnrollmentView> | null>(null);

  function paint(next: Held<EnrollmentView> | null, firstFail?: string): void {
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

  async function refresh(): Promise<void> {
    try {
      const [requestsRes, tokensRes, revokeRes, auditRes, appTokensRes] = await Promise.all([
        fetch("/api/enrollment/requests", { credentials: "include" }),
        fetch("/api/enrollment/tokens", { credentials: "include" }),
        fetch("/api/enrollment/revocations", { credentials: "include" }),
        fetch("/api/enrollment/audit", { credentials: "include" }),
        fetch("/api/enrollment/app-tokens", { credentials: "include" }),
      ]);
      if (requestsRes.status === 401) {
        paint(applyHeldPoll(held, { kind: "unauth" }));
        return;
      }
      if (requestsRes.status === 404) {
        held = null;
        state = { kind: "absent" };
        return;
      }
      if (!requestsRes.ok || !tokensRes.ok || !revokeRes.ok || !appTokensRes.ok) {
        const reason = `GET /api/enrollment/* returned ${requestsRes.status}`;
        paint(applyHeldPoll(held, { kind: "fail", reason }), reason);
        return;
      }
      const requestsBody = await readJson(requestsRes) as { requests?: unknown };
      const tokensBody = await readJson(tokensRes) as { tokens?: unknown };
      const revokeBody = await readJson(revokeRes) as { revocations?: unknown };
      const appTokensBody = await readJson(appTokensRes) as { tokens?: unknown };
      const events = auditRes.ok ? (await readJson(auditRes) as { events?: unknown }).events ?? null : null;
      const read = readEnrollmentView({
        tokens: tokensBody.tokens,
        appTokens: appTokensBody.tokens,
        requests: requestsBody.requests,
        revocations: revokeBody.revocations,
        events,
      });
      if (!read.ok) {
        paint(applyHeldPoll(held, { kind: "fail", reason: read.reason }), read.reason);
        return;
      }
      paint(applyHeldPoll(held, { kind: "ok", value: read.view, at: Date.now() }));
    } catch (e) {
      const reason = (e as Error).message;
      paint(applyHeldPoll(held, { kind: "fail", reason }), reason);
    }
  }

  return {
    get state() {
      return state;
    },
    refresh,
  };
}
