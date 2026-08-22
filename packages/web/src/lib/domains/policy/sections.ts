// Which policy tables exist, and how a URL names one.
//
// The classic page used `?s=files`. The Svelte console uses `/policy/files` so the section
// is the path, not a query — a link can be copied, bookmarked, and sent to the colleague
// who has to approve the thing they are looking at.

import { t, type Lang, type MessageKey } from "../../i18n.ts";

export const POLICY_SECTION_IDS = [
  "policies",
  "rules",
  "files",
  "baseline",
  "zones",
  "crossings",
  "coverage",
  "devices",
  "users",
  "workload",
  "hosts",
  "membership",
  "objects",
  "services",
  "feeds",
  "address-space",
  "history",
] as const;

export type PolicySectionId = (typeof POLICY_SECTION_IDS)[number];

export const ALL_SECTION = "all";

const SECTION_I18N: Record<PolicySectionId, MessageKey> = {
  rules: "s.rules",
  files: "s.files",
  baseline: "s.baseline",
  policies: "s.policies",
  zones: "s.zones",
  crossings: "s.crossings",
  coverage: "s.coverage",
  devices: "s.devices",
  users: "s.users",
  workload: "s.workload",
  hosts: "s.hosts",
  membership: "s.membership",
  objects: "s.objects",
  services: "s.services",
  feeds: "s.feeds",
  "address-space": "s.addressSpace",
  history: "s.history",
};

export function sectionLabel(id: PolicySectionId, lang: Lang): string {
  return t(lang, SECTION_I18N[id]);
}

export const POLICY_SECTION_LABEL: Record<PolicySectionId, string> = {
  rules: "rules",
  files: "files",
  baseline: "baseline",
  policies: "policies",
  zones: "zones",
  crossings: "trust crossings",
  coverage: "coverage",
  devices: "devices",
  users: "users",
  workload: "workload",
  hosts: "hosts",
  membership: "membership",
  objects: "address objects",
  services: "service catalogue",
  feeds: "feeds",
  "address-space": "address space",
  history: "history",
};

export interface SectionRef {
  id: PolicySectionId;
  label: string;
  count?: number;
}

/** Path under the `/app` base. Never a query string. */
export function sectionPath(id: PolicySectionId | typeof ALL_SECTION): string {
  return `/policy/${id}`;
}

export function isSectionId(value: string): value is PolicySectionId {
  return (POLICY_SECTION_IDS as readonly string[]).includes(value);
}

/**
 * Which section the URL asked for, after applying the classic fallback.
 *
 * `"all"` is a mode, not a table. An unknown or empty slug becomes the first
 * section that actually rendered — an empty page would read as "this site has
 * none of that".
 */
export function resolveSection(present: readonly PolicySectionId[], asked: string): PolicySectionId | typeof ALL_SECTION {
  if (asked === ALL_SECTION) return ALL_SECTION;
  if (isSectionId(asked) && present.includes(asked)) return asked;
  return present[0] ?? "policies";
}

/** Enough of the screen to decide which index links to keep. */
export interface SectionSource {
  edit: { more: readonly unknown[] } | null;
  baseline: readonly unknown[];
  rows: readonly unknown[];
  zones: readonly unknown[];
  crossings: readonly unknown[];
  coverage: { rows: readonly unknown[] } | null;
  devices: { rows: readonly unknown[]; unapproved?: readonly unknown[] | number } | null;
  users: readonly unknown[];
  workload: readonly unknown[];
  hosts: readonly unknown[];
  membership: readonly unknown[];
  objects: readonly unknown[];
  services: readonly unknown[];
  feeds: readonly unknown[];
  addressSpace: readonly unknown[];
  history: readonly unknown[];
}

/**
 * The index is built from what would actually render. A link to a section that
 * emitted nothing is a promise the page does not keep.
 */
export function presentSections(view: SectionSource): SectionRef[] {
  const has = (id: PolicySectionId): { present: boolean; count?: number } => {
    switch (id) {
      case "rules":
        return { present: view.edit !== null };
      case "files":
        return { present: (view.edit?.more.length ?? 0) > 0, count: view.edit?.more.length };
      case "baseline":
        return { present: view.baseline.length > 0, count: view.baseline.length };
      case "policies":
        return { present: true, count: view.rows.length };
      case "zones":
        return { present: view.zones.length > 0, count: view.zones.length };
      case "crossings":
        return { present: true, count: view.crossings.length };
      case "coverage":
        return {
          present: (view.coverage?.rows.length ?? 0) > 0,
          count: view.coverage?.rows.length,
        };
      case "devices": {
        const extra = view.devices?.unapproved;
        const extraCount = Array.isArray(extra) ? extra.length : typeof extra === "number" ? extra : 0;
        return {
          present: (view.devices?.rows.length ?? 0) > 0 || extraCount > 0,
          count: view.devices?.rows.length,
        };
      }
      case "users":
        return { present: view.users.length > 0, count: view.users.length };
      case "workload":
        return { present: view.workload.length > 0, count: view.workload.length };
      case "hosts":
        return { present: view.hosts.length > 0, count: view.hosts.length };
      case "membership":
        return { present: view.membership.length > 0, count: view.membership.length };
      case "objects":
        return { present: view.objects.length > 0, count: view.objects.length };
      case "services":
        return { present: view.services.length > 0, count: view.services.length };
      case "feeds":
        return { present: view.feeds.length > 0, count: view.feeds.length };
      case "address-space":
        return { present: view.addressSpace.length > 0, count: view.addressSpace.length };
      case "history":
        return { present: view.history.length > 0, count: view.history.length };
    }
  };
  const out: SectionRef[] = [];
  for (const id of POLICY_SECTION_IDS) {
    const { present, count } = has(id);
    if (!present) continue;
    out.push({
      id,
      label: POLICY_SECTION_LABEL[id],
      ...(count === undefined ? {} : { count }),
    });
  }
  return out;
}
