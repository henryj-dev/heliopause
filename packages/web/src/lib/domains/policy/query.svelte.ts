import { latestOnly } from "./latest";
import { readPolicyScreen, type PolicyScreenView } from "./screen";

export type PolicyState =
  | { kind: "loading" }
  | { kind: "ok"; view: PolicyScreenView }
  | { kind: "absent" }
  | { kind: "unauth" }
  | { kind: "error"; message: string };

function readError(data: unknown, fallback: string): string {
  if (typeof data === "object" && data !== null && "error" in data && typeof data.error === "string") {
    return data.error;
  }
  return fallback;
}

export function policyQuery() {
  let state = $state<PolicyState>({ kind: "loading" });
  /** The site the state on screen was asked for; empty is the manager's default. */
  let loaded = $state("");
  /** A request is in flight, so the screen may still show the previous site's answer. */
  let pending = $state(false);
  const order = latestOnly();

  async function fetchState(site?: string): Promise<PolicyState> {
    try {
      const at = site ? `/api/policy/screen?site=${encodeURIComponent(site)}` : "/api/policy/screen";
      const res = await fetch(at, { credentials: "include" });
      if (res.status === 401) return { kind: "unauth" };
      if (res.status === 404) return { kind: "absent" };
      const body: unknown = await res.json();
      if (!res.ok) {
        return { kind: "error", message: readError(body, `GET /api/policy/screen returned ${res.status}`) };
      }
      const read = readPolicyScreen(body);
      return read.ok ? { kind: "ok", view: read.view } : { kind: "error", message: read.reason };
    } catch (e) {
      return { kind: "error", message: (e as Error).message };
    }
  }

  /**
   * @param site Which VPC to draw. Omitted keeps the request the manager has always answered, which
   * is what a single-site deployment sends and what an older manager understands.
   */
  async function refresh(site?: string): Promise<void> {
    const current = order.begin();
    pending = true;
    const next = await fetchState(site);
    if (!current()) return;
    state = next;
    loaded = site ?? "";
    pending = false;
  }

  return {
    get state() {
      return state;
    },
    get loaded() {
      return loaded;
    },
    get pending() {
      return pending;
    },
    refresh,
  };
}
