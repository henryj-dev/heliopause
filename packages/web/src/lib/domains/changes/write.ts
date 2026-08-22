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

export function proposeBody(target: string): string {
  return JSON.stringify({ target });
}
