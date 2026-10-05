// Headers and bodies for POST /api/approve, /api/publish, /api/policy/plan.
//
// The custom CSRF header is what a cross-origin form cannot set. The server
// names it `x-heliopause-csrf`; this file spells it so a rename there fails
// this package's tests rather than silently sending the old header.

export const CSRF_HEADER = "x-heliopause-csrf";

export function writeHeaders(csrf: string | null): Record<string, string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (csrf) headers[CSRF_HEADER] = csrf;
  return headers;
}

export function approveBody(hash: string, otp: string): string {
  return JSON.stringify({ hash, otp });
}

export function publishBody(hash: string, otp: string): string {
  return JSON.stringify({ hash, otp });
}

/**
 * `allowProtected` is omitted unless it is true, so the ordinary body is byte-for-byte what it was.
 *
 * The server reads it with `=== true` and refuses a plan reaching a protected host without it
 * (409 + `needsAllowProtected`). It is a second call rather than a checkbox shown up front: the
 * page cannot know which hosts are protected until the server has rendered the plan, so asking
 * beforehand would mean asking on every propose — and a confirmation that always appears is one
 * people click without reading.
 */
export function proposeBody(target: string, allowProtected = false): string {
  return JSON.stringify(allowProtected ? { target, allowProtected: true } : { target });
}
