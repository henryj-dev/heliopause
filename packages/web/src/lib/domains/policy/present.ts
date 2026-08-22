import { t, type Lang } from "../../i18n.ts";
import type { PolicyRisk, PolicyRow } from "./screen";

export function sourceCell(cidrs: string[], anySource: boolean, lang: Lang = "en"): string {
  if (anySource || cidrs.length === 0) return t(lang, "m.anySource");
  return cidrs.length <= 2 ? cidrs.join(", ") : `${cidrs.slice(0, 2).join(", ")} +${cidrs.length - 2}`;
}

export function placement(row: {
  hosts: string[];
  egressHosts: string[];
  skippedOn: string[];
  placementKnown: boolean;
}, lang: Lang = "en"): string {
  const parts: string[] = [];
  if (row.hosts.length) parts.push(row.hosts.join(", "));
  if (row.egressHosts.length) parts.push(t(lang, "m.placementEgress", { hosts: row.egressHosts.join(", ") }));
  if (row.skippedOn.length) parts.push(t(lang, "m.placementSkipped", { hosts: row.skippedOn.join(", ") }));
  if (!parts.length) return row.placementKnown ? t(lang, "m.placementNone") : t(lang, "m.placementUnknown");
  return parts.join(" · ");
}

export function policyRowClass(row: PolicyRow): string {
  if (row.risks.includes("renders-nowhere")) return "hit-bad";
  if (row.risks.includes("any-source") || row.risks.includes("all-ports")) return "hit-warn";
  if (!row.placementKnown) return "hatch";
  return "";
}

export function riskKind(risk: PolicyRisk): "bad" | "warn" | "mute" {
  if (risk === "renders-nowhere") return "bad";
  if (risk === "disabled") return "mute";
  return "warn";
}

export const RISK_LABEL_KEY = {
  "renders-nowhere": "m.riskNowhere",
  "any-source": "m.anySource",
  "all-ports": "m.allPorts",
  "disabled": "m.disabled",
} as const;

export function riskLabel(risk: PolicyRisk, lang: Lang = "en"): string {
  return t(lang, RISK_LABEL_KEY[risk]);
}

export type PolicyFindingKey = PolicyRisk | "placement-unknown";

export interface PolicyFinding {
  key: PolicyFindingKey;
  count: number;
  kind: "bad" | "warn" | "mute" | "none";
  hatch: boolean;
  mark: string;
  label: string;
  note: string;
}

const FINDING_META: readonly {
  key: PolicyFindingKey;
  kind: PolicyFinding["kind"];
  hatch: boolean;
  mark: string;
}[] = [
  { key: "renders-nowhere", kind: "bad", hatch: false, mark: "✕" },
  { key: "any-source", kind: "warn", hatch: false, mark: "△" },
  { key: "all-ports", kind: "warn", hatch: false, mark: "△" },
  { key: "disabled", kind: "mute", hatch: false, mark: "◇" },
  { key: "placement-unknown", kind: "none", hatch: true, mark: "" },
];

function findingNote(key: PolicyFindingKey, lang: Lang): string {
  if (key === "renders-nowhere") return t(lang, "m.findingNowhere");
  if (key === "any-source") return t(lang, "m.findingAnySource");
  if (key === "disabled") return t(lang, "m.findingDisabled");
  if (key === "placement-unknown") return t(lang, "m.findingPlacementNote");
  return "";
}

function findingLabel(key: PolicyFindingKey, lang: Lang): string {
  return key === "placement-unknown" ? t(lang, "m.findingPlacement") : riskLabel(key, lang);
}

/**
 * The chips above the policies table. Zero is omitted — a 0 here would say
 * "counted, none", which is a different claim from "this finding is not in play".
 */
export function policyFindings(rows: readonly PolicyRow[], lang: Lang = "en"): PolicyFinding[] {
  const countOf = (key: PolicyFindingKey): number => {
    if (key === "placement-unknown") return rows.filter((row) => !row.placementKnown).length;
    return rows.filter((row) => row.risks.includes(key)).length;
  };
  return FINDING_META
    .map((meta) => ({
      ...meta,
      label: findingLabel(meta.key, lang),
      note: findingNote(meta.key, lang),
      count: countOf(meta.key),
    }))
    .filter((finding) => finding.count > 0);
}

export function rowFor(rows: readonly PolicyRow[], id: string): PolicyRow | undefined {
  return rows.find((row) => row.id === id);
}

export function coverageKind(verdict: string): "ok" | "bad" | "none" | "mute" {
  if (verdict === "pass") return "ok";
  if (verdict === "fail") return "bad";
  if (verdict === "n/a") return "mute";
  return "none";
}

export function deviceKind(state: string): "ok" | "warn" | "bad" | "none" {
  if (state === "ok") return "ok";
  if (state === "moved") return "warn";
  if (state === "gone") return "bad";
  return "none";
}
