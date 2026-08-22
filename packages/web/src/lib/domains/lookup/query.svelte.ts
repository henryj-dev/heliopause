import { applyHeldPoll, type Held } from "../../poll.ts";
import {
  lookupSearch,
  readLookupView,
  readWhereUsedView,
  replayLookupLang,
  type LookupParams,
  type LookupView,
  type WhereUsedView,
} from "./lookup";

export type LookupState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "absent" }
  | { kind: "unauth" }
  | { kind: "error"; message: string }
  | { kind: "ok"; view: LookupView; lastOkAt: number; failCount: number; lastFail: string | null };

export type WhereUsedState =
  | { kind: "loading" }
  | { kind: "absent" }
  | { kind: "unauth" }
  | { kind: "error"; message: string }
  | { kind: "ok"; view: WhereUsedView; lastOkAt: number; failCount: number; lastFail: string | null };

function readError(data: unknown, fallback: string): string {
  if (typeof data === "object" && data !== null && "error" in data && typeof data.error === "string") {
    return data.error;
  }
  return fallback;
}

export function lookupQuery() {
  let state = $state<LookupState>({ kind: "idle" });
  let held = $state<Held<LookupView> | null>(null);
  let seq = 0;
  let running = $state(false);
  let last: LookupParams | null = null;

  function paint(next: Held<LookupView> | null, firstFail?: string): void {
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

  async function run(params: LookupParams): Promise<void> {
    last = params;
    const my = ++seq;
    running = true;
    if (!held) state = { kind: "loading" };
    try {
      const res = await fetch(`/api/policy/lookup?${lookupSearch(params)}`, { credentials: "include" });
      if (my !== seq) return;
      if (res.status === 401) {
        paint(applyHeldPoll(held, { kind: "unauth" }));
        return;
      }
      if (res.status === 404) {
        held = null;
        state = { kind: "absent" };
        return;
      }
      const body: unknown = await res.json();
      if (my !== seq) return;
      if (!res.ok) {
        const reason = readError(body, `GET /api/policy/lookup returned ${res.status}`);
        paint(applyHeldPoll(held, { kind: "fail", reason }), reason);
        return;
      }
      const read = readLookupView(body);
      if (!read.ok) {
        paint(applyHeldPoll(held, { kind: "fail", reason: read.reason }), read.reason);
        return;
      }
      paint(applyHeldPoll(held, { kind: "ok", value: read.view, at: Date.now() }));
    } catch (e) {
      if (my !== seq) return;
      const reason = (e as Error).message;
      paint(applyHeldPoll(held, { kind: "fail", reason }), reason);
    } finally {
      if (my === seq) running = false;
    }
  }

  return {
    get state() {
      return state;
    },
    get running() {
      return running;
    },
    run,
    replayLang(lang: string): void {
      const next = replayLookupLang(last, lang);
      if (next) void run(next);
    },
  };
}

export function whereUsedQuery() {
  let state = $state<WhereUsedState>({ kind: "loading" });
  let held = $state<Held<WhereUsedView> | null>(null);
  let seq = 0;
  let running = $state(false);

  function paint(next: Held<WhereUsedView> | null, firstFail?: string): void {
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

  async function run(q: string): Promise<void> {
    const my = ++seq;
    running = true;
    if (!held) state = { kind: "loading" };
    try {
      const res = await fetch(`/api/policy/where-used?q=${encodeURIComponent(q.trim())}`, {
        credentials: "include",
      });
      if (my !== seq) return;
      if (res.status === 401) {
        paint(applyHeldPoll(held, { kind: "unauth" }));
        return;
      }
      if (res.status === 404) {
        held = null;
        state = { kind: "absent" };
        return;
      }
      const body: unknown = await res.json();
      if (my !== seq) return;
      if (!res.ok) {
        const reason = readError(body, `GET /api/policy/where-used returned ${res.status}`);
        paint(applyHeldPoll(held, { kind: "fail", reason }), reason);
        return;
      }
      const read = readWhereUsedView(body);
      if (!read.ok) {
        paint(applyHeldPoll(held, { kind: "fail", reason: read.reason }), read.reason);
        return;
      }
      paint(applyHeldPoll(held, { kind: "ok", value: read.view, at: Date.now() }));
    } catch (e) {
      if (my !== seq) return;
      const reason = (e as Error).message;
      paint(applyHeldPoll(held, { kind: "fail", reason }), reason);
    } finally {
      if (my === seq) running = false;
    }
  }

  return {
    get state() {
      return state;
    },
    get running() {
      return running;
    },
    run,
  };
}
