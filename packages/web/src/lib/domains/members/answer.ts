// What the member routes answer, read into what a page shows.
//
// The server's error strings are English and are shown as they came, under a translated sentence
// that says what kind of refusal it was. The kind is decided by status (and `needOtp` / `problems`),
// never by matching the English, so a reworded server message cannot change which sentence shows.

import type { MessageKey } from "../../i18n.ts";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A refusal as a page draws it: a translated sentence, the server's own words, and any password problems. */
export interface Refusal {
  key: MessageKey;
  detail: string;
  /** The server's password-policy reasons, as sent. Empty when the refusal was not about the password. */
  problems: string[];
}

export function errorText(body: unknown): string {
  return isRecord(body) && typeof body.error === "string" ? body.error : "";
}

export function passwordProblems(body: unknown): string[] {
  if (!isRecord(body) || !Array.isArray(body.problems)) return [];
  return body.problems.filter((p): p is string => typeof p === "string" && p !== "");
}

/** Statuses every member route shares. `null` means the caller decides. */
function common(status: number): MessageKey | null {
  if (status === 429) return "m.mbTooMany";
  if (status === 503) return "m.mbUnavailable";
  if (status >= 500) return "m.mbServerError";
  return null;
}

export function refusal(key: MessageKey, body: unknown): Refusal {
  return { key, detail: errorText(body), problems: passwordProblems(body) };
}

/** `POST /api/me/password`. 403 is a wrong current password. */
export function readPasswordChange(status: number, body: unknown): Refusal | null {
  if (status === 200) return null;
  if (status === 400 && passwordProblems(body).length > 0) return refusal("m.mbPasswordRefused", body);
  if (status === 403) return refusal("m.mbCurrentWrong", body);
  return refusal(common(status) ?? "m.mbFailed", body);
}

/** `POST /auth/invite/accept`. 409 is a name already taken; 400 without problems is a bad or used link. */
export function readInviteAccept(status: number, body: unknown): Refusal | null {
  if (status === 201 || status === 200) return null;
  if (status === 400 && passwordProblems(body).length > 0) return refusal("m.mbPasswordRefused", body);
  if (status === 400) return refusal("m.mbLinkInvalid", body);
  if (status === 409) return refusal("m.mbUsernameTaken", body);
  if (status === 403) return refusal("m.mbWrongPage", body);
  return refusal(common(status) ?? "m.mbFailed", body);
}

export type ResetAnswer =
  | { kind: "done" }
  | { kind: "needOtp"; wrongCode: boolean }
  | { kind: "refused"; refusal: Refusal };

/**
 * `POST /auth/password/reset`. A writer or admin also needs a one-time code: the server answers 401
 * `needOtp` for a missing or wrong one. 403 is an unconfirmed code (or no code user at all).
 */
export function readReset(status: number, body: unknown, sentOtp: boolean): ResetAnswer {
  if (status === 200) return { kind: "done" };
  if (status === 401 && isRecord(body) && body.needOtp === true) return { kind: "needOtp", wrongCode: sentOtp };
  if (status === 400 && passwordProblems(body).length > 0) return { kind: "refused", refusal: refusal("m.mbPasswordRefused", body) };
  if (status === 400) return { kind: "refused", refusal: refusal("m.mbLinkInvalid", body) };
  if (status === 403) return { kind: "refused", refusal: refusal("m.mbResetOtpUnconfirmed", body) };
  if (status === 409) return { kind: "refused", refusal: refusal("m.mbResetChanged", body) };
  return { kind: "refused", refusal: refusal(common(status) ?? "m.mbFailed", body) };
}

/**
 * `/api/members*`. 409 is the store refusing a state (the last admin, an address or code user already
 * in use); 403 is something this admin may not do (their own roles or code, or no admin role).
 */
export function readAdminWrite(status: number, body: unknown): Refusal | null {
  if (status === 200 || status === 201) return null;
  if (status === 409) return refusal("m.mbConflict", body);
  if (status === 403) return refusal("m.mbForbidden", body);
  if (status === 401) return refusal("m.mbSessionEnded", body);
  if (status === 400) return refusal("m.mbBadRequest", body);
  return refusal(common(status) ?? "m.mbFailed", body);
}

/** The two password fields a form asks for. Length and character rules are the server's to judge. */
export function repeatProblem(next: string, repeat: string): MessageKey | null {
  if (next === "") return "m.mbPasswordEmpty";
  if (next !== repeat) return "m.mbPasswordMismatch";
  return null;
}
