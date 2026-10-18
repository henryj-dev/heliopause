// The one-time token in an invitation or reset link.
//
// The link carries it in the fragment (`/app/invite#<token>`), which a browser never sends to any
// server, so it is not in this server's or a front proxy's access log. The page reads it once, keeps
// it in memory, and clears it from the address bar and the current history entry. The browser's
// own history and address-bar autocomplete may still keep the full link. What protects it is that
// the token works once and expires.

export const INVITE_ACCEPT_PATH = "/auth/invite/accept";
export const RESET_PATH = "/auth/password/reset";
const MAX_TOKEN = 128;

/** The token in `location.hash`, or null for a fragment that does not carry a usable one. */
export function readFragmentToken(hash: string): string | null {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  if (!raw || raw.length > MAX_TOKEN || !/^[A-Za-z0-9_-]+$/.test(raw)) return null;
  return raw;
}

/** The address to leave behind: the same page with no fragment. */
export function withoutFragment(pathname: string, search: string): string {
  return `${pathname}${search}`;
}

/**
 * Take the token out of the address bar and the current history entry.
 *
 * Plain `history.replaceState`, not SvelteKit's: `$app/navigation`'s `replaceState` writes
 * `page.url.href` — the URL with the token — into `history.state` (`sveltekit:pageurl`). The state
 * passed through here is the entry's own, which on a first load holds SvelteKit's two index keys.
 */
export function clearFragment(): void {
  if (location.hash === "") return;
  history.replaceState(history.state, "", withoutFragment(location.pathname, location.search));
}

export function inviteAcceptBody(token: string, username: string, password: string): string {
  return JSON.stringify({ token, username: username.trim(), password });
}

export function resetBody(token: string, password: string, otp: string | null): string {
  return JSON.stringify({ token, password, ...(otp !== null ? { otp } : {}) });
}
