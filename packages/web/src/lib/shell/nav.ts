// The same seven screens as the classic console, under /app.
//
// Groups are the three questions this console exists for — what is the fleet
// doing, what does the evidence say, and what do the rules say.

import type { MessageKey } from "../i18n.ts";

export const NAV_I18N: Record<string, MessageKey> = {
  fleet: "nav.fleet",
  changes: "nav.changes",
  enrollment: "nav.enrollment",
  lookup: "nav.lookup",
  traffic: "nav.traffic",
  routing: "nav.routing",
  policy: "nav.policy",
  account: "nav.account",
  members: "nav.members",
};

export const GROUP_I18N: Record<string, MessageKey> = {
  fleet: "g.fleet",
  evidence: "g.evidence",
  policy: "g.policy",
  account: "g.account",
};

export interface AppNavItem {
  href: string;
  key: string;
  label: string;
  group: string;
  /** Who the item is for. Absent means every caller; an item a caller may not use is left out, not greyed. */
  for?: "member" | "admin";
}

export interface AppNavGroup {
  label: string;
  items: AppNavItem[];
}

export const APP_NAV: readonly AppNavItem[] = [
  { href: "/fleet", key: "fleet", label: "fleet", group: "fleet" },
  { href: "/changes", key: "changes", label: "changes", group: "fleet" },
  { href: "/enrollment", key: "enrollment", label: "enrollment", group: "fleet" },
  { href: "/lookup", key: "lookup", label: "lookup", group: "evidence" },
  { href: "/traffic", key: "traffic", label: "traffic", group: "evidence" },
  { href: "/routing", key: "routing", label: "routing", group: "evidence" },
  { href: "/policy", key: "policy", label: "policy", group: "policy" },
  { href: "/account", key: "account", label: "account", group: "account", for: "member" },
  { href: "/members", key: "members", label: "members", group: "account", for: "admin" },
];

/** What decides which `for` items show: from `/api/authz`, or null before it has been read. */
export interface NavCaller {
  via: string | null;
  isAdmin: boolean;
}

function shows(item: AppNavItem, caller: NavCaller | null): boolean {
  if (item.for === "admin") return caller?.isAdmin === true;
  if (item.for === "member") return caller?.via === "password";
  return true;
}

export function navGroups(caller: NavCaller | null = null): AppNavGroup[] {
  const groups: AppNavGroup[] = [];
  for (const item of APP_NAV) {
    if (!shows(item, caller)) continue;
    let group = groups.find((g) => g.label === item.group);
    if (!group) groups.push((group = { label: item.group, items: [] }));
    group.items.push(item);
  }
  return groups;
}

/**
 * The pages a signed-out browser uses: sign-in, and the invitation and reset links (whose token is
 * in the fragment, not the path). They draw no menu and poll nothing.
 */
export function isPublicPath(pathname: string, base: string): boolean {
  const rest = pathname.startsWith(base) ? pathname.slice(base.length) : pathname;
  return rest === "/login" || rest === "/invite" || rest === "/reset";
}

/**
 * Where the chrome sends a browser whose password must change: `/account`, the one screen that
 * answers then. Null when it may stay where it is.
 */
export function mustChangeRedirect(whoKind: string, key: string, base: string): string | null {
  return whoKind === "mustChange" && key !== "account" ? `${base}/account` : null;
}

/** Which screen the path is on. `/app` and `/app/` are fleet, like CONSOLE_HOME. */
export function activeKey(pathname: string, base: string): string {
  const rest = pathname.startsWith(base) ? pathname.slice(base.length) : pathname;
  const path = rest === "" || rest === "/" ? "/fleet" : rest;
  if (path === "/policy" || path.startsWith("/policy/")) return "policy";
  const hit = APP_NAV.find((item) => path === item.href || path.startsWith(`${item.href}/`));
  return hit?.key ?? "fleet";
}

export function crumbsFor(key: string, pathname: string, base: string): string[] {
  const rest = pathname.startsWith(base) ? pathname.slice(base.length) : pathname;
  if (key === "policy") {
    const section = rest.replace(/^\/policy\/?/, "");
    return section ? ["policy", section] : ["policy"];
  }
  if (key === "changes") {
    const slug = rest.replace(/^\/changes\/?/, "");
    return slug ? ["changes", crumbPlanHash(slug)] : ["changes"];
  }
  if (key === "enrollment") {
    const slug = rest.replace(/^\/enrollment\/?/, "");
    return slug && ENROLL_STATUSES.has(slug) ? ["enrollment", slug] : ["enrollment"];
  }
  const item = APP_NAV.find((row) => row.key === key);
  return [item?.label ?? key];
}

const ENROLL_STATUSES = new Set(["pending", "conflict", "rejected", "signed"]);

/** Short enough for the 42px bar. The card still shows the full hash on hover. */
function crumbPlanHash(raw: string): string {
  let hash = raw;
  try {
    hash = decodeURIComponent(raw);
  } catch {
    // A malformed percent-escape still names a place; leave it.
  }
  const hex = hash.startsWith("sha256:") ? hash.slice("sha256:".length) : hash;
  if (hex.length <= 12) return hash;
  return `sha256:${hex.slice(0, 8)}…${hex.slice(-4)}`;
}
