import { applyHeldPoll, type Held } from "../../poll.ts";
import { readTrafficView, type TrafficView } from "./traffic";

export const TRAFFIC_POLL_MS = 10_000;

export type TrafficState =
  | { kind: "loading" }
  | { kind: "absent" }
  | { kind: "unauth" }
  | { kind: "error"; message: string }
  | { kind: "ok"; view: TrafficView; lastOkAt: number; failCount: number; lastFail: string | null };

function readError(data: unknown, fallback: string): string {
  if (typeof data === "object" && data !== null && "error" in data && typeof data.error === "string") {
    return data.error;
  }
  return fallback;
}

export function trafficQuery() {
  let state = $state<TrafficState>({ kind: "loading" });
  let held = $state<Held<TrafficView> | null>(null);

  function paint(next: Held<TrafficView> | null, firstFail?: string): void {
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
      const res = await fetch("/api/workload-traffic", { credentials: "include" });
      if (res.status === 401) {
        paint(applyHeldPoll(held, { kind: "unauth" }));
        return;
      }
      if (res.status === 404) {
        held = null;
        state = { kind: "absent" };
        return;
      }
      if (!res.ok) {
        const body: unknown = await res.json().catch(() => null);
        const reason = readError(body, `GET /api/workload-traffic returned ${res.status}`);
        paint(applyHeldPoll(held, { kind: "fail", reason }), reason);
        return;
      }
      const read = readTrafficView(await res.json());
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
