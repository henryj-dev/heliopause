// The header the manager checks on every write from a cookie session. `src/session.ts` names it
// `x-heliopause-csrf`; each domain spells it in its own `write.ts`, and `members.test.ts` pins this one.
export const CSRF_HEADER = "x-heliopause-csrf";

export function writeHeaders(csrf: string | null): Record<string, string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (csrf) headers[CSRF_HEADER] = csrf;
  return headers;
}
