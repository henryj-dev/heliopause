// GET /api/authz, as the chrome is allowed to see it.
//
// The changes screen already reads `you` / `canWrite` / `csrf` off `/api/plans`.
// The bar cannot wait on a plan listing — every screen has the bar, and a
// certificate caller has no session to hang a CSRF token on.

import { t, type Lang } from "../i18n.ts";

export interface WhoView {
  you: string;
  canWrite: boolean;
  csrf: string | null;
  pendingPlans: number;
  pendingCsrs: number;
  /** True when this manager verifies a second factor. Missing is ask, not skip. */
  needsOtp: boolean;
  /** How the caller signed in. `null` when an older manager does not say. */
  via: "certificate" | "oidc" | "password" | "sso" | null;
  /** Member administration. Only a member session (password or SSO) that passed its sign-in code is one. */
  isAdmin: boolean;
}

const VIAS = ["certificate", "oidc", "password", "sso"] as const;

export type WhoRead =
  | { ok: true; view: WhoView }
  | { ok: false; reason: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function readWho(data: unknown): WhoRead {
  if (!isRecord(data)) return { ok: false, reason: "authz is not an object" };
  if (typeof data.you !== "string" || data.you === "") return { ok: false, reason: "authz is missing you" };
  if (typeof data.canWrite !== "boolean") return { ok: false, reason: "authz is missing canWrite" };
  return {
    ok: true,
    view: {
      you: data.you,
      canWrite: data.canWrite,
      csrf: typeof data.csrf === "string" && data.csrf !== "" ? data.csrf : null,
      pendingPlans: typeof data.pendingPlans === "number" && data.pendingPlans > 0 ? data.pendingPlans : 0,
      pendingCsrs: typeof data.pendingCsrs === "number" && data.pendingCsrs > 0 ? data.pendingCsrs : 0,
      needsOtp: data.otp !== null,
      via: VIAS.find((v) => v === data.via) ?? null,
      isAdmin: data.isAdmin === true,
    },
  };
}

/** Fail closed: if we have not read /authz, still ask. */
export function shouldAskOtp(view: WhoView | null): boolean {
  return view === null || view.needsOtp;
}

export function viaLabel(csrf: string | null, lang: Lang = "en"): string {
  return csrf ? t(lang, "m.signedIn") : t(lang, "m.viaCert");
}

export function mayLabel(canWrite: boolean, lang: Lang = "en"): string {
  return canWrite ? t(lang, "m.mayWrite") : t(lang, "m.readOnly");
}

export const LOGOUT_PATH = "/auth/logout";
/**
 * The console's own sign-in page. It offers the password form, SSO, or both, as `/auth/methods`
 * says; with SSO alone it goes straight on to `/auth/login`. `/app` is the build's `paths.base`.
 */
export const LOGIN_PATH = "/app/login";

/**
 * What a refused `/api/authz` means for the chrome. 401 is signed out; 403 with `mustChange` is a
 * member whose password must change first, which only `/account` can answer; anything else is a
 * failure to read, not a verdict.
 */
export function readWhoRefusal(status: number, body: unknown): "unauth" | "mustChange" | "error" {
  if (status === 401) return "unauth";
  if (status === 403 && isRecord(body) && body.mustChange === true) return "mustChange";
  return "error";
}

/** Headers for `POST /auth/logout`. A member password session needs its CSRF token to end. */
export function logoutHeaders(csrf: string | null): Record<string, string> {
  return csrf ? { "x-heliopause-csrf": csrf } : {};
}

/**
 * Where the browser goes after a sign-out.
 *
 * `/auth/logout` destroys this server's session and answers with where — if anywhere — the identity
 * provider's session can be ended too. Destroying the cookie does not touch that one, and the next
 * authorization request is answered from it, so without going there sign-out followed by sign-in put
 * the same person back in with no credential asked for.
 *
 * A plain function beside `readWho` rather than logic inside the rune module, for the same reason
 * `readWho` is: this parses a response from the other side of a socket, and that is a thing worth
 * being able to run in a test.
 *
 * Anything but a non-empty string means `/` — the login page, behind an already-destroyed session.
 * An older manager answers `204` with no body at all, and this is what makes that keep working.
 */
export function logoutDestination(body: unknown): string {
  if (body && typeof body === "object" && !Array.isArray(body)) {
    const to = (body as { endSession?: unknown }).endSession;
    if (typeof to === "string" && to) return to;
  }
  return "/";
}

export function loginHref(next: string): string {
  return `${LOGIN_PATH}?next=${encodeURIComponent(next)}`;
}
