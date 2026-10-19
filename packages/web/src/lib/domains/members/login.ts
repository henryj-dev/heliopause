// The sign-in page's decisions, apart from the page so they can run in a test.

import type { MessageKey } from "../../i18n.ts";
import { errorText, isRecord, type Refusal } from "./answer.ts";

export const METHODS_PATH = "/auth/methods";
export const PASSWORD_LOGIN_PATH = "/auth/password/login";
export const SSO_LOGIN_PATH = "/auth/login";
const MAX_NEXT = 512;

/** Which sign-ins `/auth/methods` says this manager offers. Anything unreadable offers nothing. */
export interface Methods {
  password: boolean;
  sso: boolean;
}

export function readMethods(body: unknown): Methods {
  if (!isRecord(body)) return { password: false, sso: false };
  return { password: body.password === true, sso: body.sso === true };
}

/**
 * Where to go after signing in, or null for "the default".
 *
 * The same rule as the server's `safeReturnTo` (`src/manager-server.ts`):
 *   1. starts with `/`, not `//`, and holds only printable ASCII other than a backslash — the
 *      WHATWG URL parser drops tab, CR and LF and reads a backslash as `/`, so those turn a path
 *      into `//evil.example`, and the server's `Location` header refuses anything outside ASCII;
 *   2. not under `/auth/`, and not the sign-in, invitation or reset page, with or without `base`.
 */
export function safeNext(raw: string | null, base: string): string | null {
  if (!raw || raw.length > MAX_NEXT || !raw.startsWith("/") || raw.startsWith("//")) return null;
  if (/[^\x21-\x7e]/.test(raw) || raw.includes("\\")) return null;
  // No origin check follows: a value that starts with a single `/` and holds only printable ASCII
  // other than a backslash always resolves to this origin.
  // @see login.test.ts "refuses what the server's safeReturnTo refuses"
  const path = new URL(raw, PLACEHOLDER_ORIGIN).pathname;
  if (path.startsWith("/auth/")) return null;
  for (const own of ["/login", "/invite", "/reset"]) {
    for (const prefix of ["", base]) {
      const p = `${prefix}${own}`;
      if (path === p || path.startsWith(`${p}/`)) return null;
    }
  }
  return raw;
}
const PLACEHOLDER_ORIGIN = "https://next.invalid";

/** The SSO link, carrying `next` only when it is safe; the server checks it again on the way back. */
export function ssoHref(next: string | null, base: string): string {
  const safe = safeNext(next, base);
  return safe ? `${SSO_LOGIN_PATH}?next=${encodeURIComponent(safe)}` : SSO_LOGIN_PATH;
}

/** A must-change password goes to `/account` whatever `next` said: nothing else answers until it changes. */
export function afterSignIn(mustChange: boolean, next: string | null, base: string): string {
  if (mustChange) return `${base}/account`;
  return safeNext(next, base) ?? `${base}/fleet`;
}

export type LoginAnswer =
  | { kind: "signedIn"; mustChange: boolean }
  | { kind: "needOtp"; wrongCode: boolean }
  | { kind: "refused"; refusal: Refusal };

function refused(key: MessageKey, body: unknown): LoginAnswer {
  return { kind: "refused", refusal: { key, detail: errorText(body), problems: [] } };
}

/**
 * One answer from `POST /auth/password/login`.
 *
 * A writer or admin first gets 401 `needOtp`; the page then asks for the code and sends all three
 * fields again. A wrong code is the same 401 `needOtp`, told apart by whether a code was sent.
 * 401 without `needOtp` is a wrong username or password (the server does not say which).
 * 403 is an account that needs a code but has none linked; 503 is the store or the code checker
 * being unavailable.
 */
export function readLogin(status: number, body: unknown, sentOtp: boolean): LoginAnswer {
  if (status === 200) return { kind: "signedIn", mustChange: isRecord(body) && body.mustChange === true };
  if (status === 401 && isRecord(body) && body.needOtp === true) return { kind: "needOtp", wrongCode: sentOtp };
  if (status === 401) return refused("m.loginInvalid", body);
  if (status === 429) return refused("m.loginTooMany", body);
  if (status === 403) return refused("m.loginNoOtpUser", body);
  if (status === 400) return refused("m.loginBadInput", body);
  if (status >= 500) return refused("m.loginUnavailable", body);
  return refused("m.mbFailed", body);
}

/** The step the form is on after an answer. A refusal keeps the step it happened on. */
export type LoginStep = "password" | "otp";

export function nextStep(step: LoginStep, answer: LoginAnswer): LoginStep {
  if (answer.kind === "needOtp") return "otp";
  // A wrong password while on the code step means the password changed underneath; start again.
  if (answer.kind === "refused" && answer.refusal.key === "m.loginInvalid") return "password";
  return step;
}

export function loginBody(username: string, password: string, otp: string | null): string {
  return JSON.stringify({ username, password, ...(otp !== null ? { otp } : {}) });
}
