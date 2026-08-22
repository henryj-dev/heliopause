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
}

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
export const LOGIN_PATH = "/auth/login";

/** Where a signed-out browser is sent. Same-origin path; `/auth/login` encodes it. */
export function loginHref(next: string): string {
  return `${LOGIN_PATH}?next=${encodeURIComponent(next)}`;
}
