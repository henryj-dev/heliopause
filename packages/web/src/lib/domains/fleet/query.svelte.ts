import { applyHeldPoll, type Held } from "../../poll.ts";
import { readSiteView, type SiteView } from "./site";

export const FLEET_POLL_MS = 10_000;

export type FleetState =
  | { kind: "loading" }
  | { kind: "unauth" }
  | { kind: "error"; message: string }
  | { kind: "ok"; site: SiteView; lastOkAt: number; failCount: number; lastFail: string | null };

export function fleetQuery() {
  let state = $state<FleetState>({ kind: "loading" });
  let held = $state<Held<SiteView> | null>(null);

  function paint(next: Held<SiteView> | null, firstFail?: string): void {
    held = next;
    if (next) {
      state = {
        kind: "ok",
        site: next.value,
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
      const res = await fetch("/api/site", { credentials: "include" });
      if (res.status === 401) {
        paint(applyHeldPoll(held, { kind: "unauth" }));
        return;
      }
      if (!res.ok) {
        const reason = `GET /api/site returned ${res.status}`;
        paint(applyHeldPoll(held, { kind: "fail", reason }), reason);
        return;
      }
      const read = readSiteView(await res.json());
      if (!read.ok) {
        paint(applyHeldPoll(held, { kind: "fail", reason: read.reason }), read.reason);
        return;
      }
      paint(applyHeldPoll(held, { kind: "ok", value: read.site, at: Date.now() }));
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
