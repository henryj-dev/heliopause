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

  async function refresh(): Promise<void> {
    try {
      const res = await fetch("/api/policy/screen", { credentials: "include" });
      if (res.status === 401) {
        state = { kind: "unauth" };
        return;
      }
      if (res.status === 404) {
        state = { kind: "absent" };
        return;
      }
      const body: unknown = await res.json();
      if (!res.ok) {
        state = { kind: "error", message: readError(body, `GET /api/policy/screen returned ${res.status}`) };
        return;
      }
      const read = readPolicyScreen(body);
      state = read.ok ? { kind: "ok", view: read.view } : { kind: "error", message: read.reason };
    } catch (e) {
      state = { kind: "error", message: (e as Error).message };
    }
  }

  return {
    get state() {
      return state;
    },
    refresh,
  };
}
