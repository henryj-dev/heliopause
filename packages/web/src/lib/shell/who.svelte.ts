import { LOGOUT_PATH, logoutDestination, readWho, type WhoView } from "./who";

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
    // Where the IdP's own session gets ended, when it offers somewhere. Destroying this
    // server's cookie does not touch it, and the next authorization request is answered
    // from it — so without this, sign-out then sign-in put the same person back in with
    // no credential asked for. `logoutDestination` is where that decision lives and is
    // tested; this function is the part that cannot be.
    let to = "/";
    try {
      // POST, so a cross-site page cannot end the session with an image tag.
      // No CSRF token: ending your own session is not worth one.
      const res = await fetch(LOGOUT_PATH, { method: "POST", credentials: "same-origin" });
      // The server hands back a URL rather than a 302, because a redirect answered to
      // `fetch` is followed by `fetch` and never reaches the address bar.
      if (res.ok) to = logoutDestination(await res.json());
    } catch {
      // The cookie is gone either way once the server answers. If it did not,
      // sending the browser to `/` still lands on login.
    }
    location.href = to;
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
