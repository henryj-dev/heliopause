import { LOGOUT_PATH, readWho, type WhoView } from "./who";

export const WHO_POLL_MS = 10_000;

export type WhoState =
  | { kind: "loading" }
  | { kind: "ok"; view: WhoView }
  | { kind: "unauth" }
  | { kind: "error" };

export interface WhoQuery {
  readonly state: WhoState;
  refresh(): Promise<void>;
  signOut(): Promise<void>;
}

let instance: WhoQuery | undefined;

function createWhoQuery(): WhoQuery {
  let state = $state<WhoState>({ kind: "loading" });

  async function refresh(): Promise<void> {
    try {
      const res = await fetch("/api/authz", { credentials: "include" });
      if (res.status === 401) {
        state = { kind: "unauth" };
        return;
      }
      if (!res.ok) {
        state = { kind: "error" };
        return;
      }
      const read = readWho(await res.json());
      state = read.ok ? { kind: "ok", view: read.view } : { kind: "error" };
    } catch {
      state = { kind: "error" };
    }
  }

  async function signOut(): Promise<void> {
    try {
      // POST, so a cross-site page cannot end the session with an image tag.
      // No CSRF token: ending your own session is not worth one.
      await fetch(LOGOUT_PATH, { method: "POST", credentials: "same-origin" });
    } catch {
      // The cookie is gone either way once the server answers. If it did not,
      // sending the browser to `/` still lands on login.
    }
    location.href = "/";
  }

  return {
    get state() {
      return state;
    },
    refresh,
    signOut,
  };
}

/** One who object for the bar and the screens that update its pending count. */
export function whoQuery(): WhoQuery {
  instance ??= createWhoQuery();
  return instance;
}
