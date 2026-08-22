// The policy document the rule table edits.
//
// The classic console already said the quiet part: a textarea over this file
// was a mistake. The table writes `policies.json` and nothing else. Extra
// keys on a rule or on the document must survive a save — the first table
// dropped `notes` and `denyMode`, and a rule created there was born without
// a reason.

// Source-editor columns. Rendered hosts / skippedOn / srcCidrs / 발견 live
// on the policies list (시안 G1). This table is G3 — what you commit.
export const RULE_COLUMNS = [
  "c.rule",
  "c.action",
  "c.protoPorts",
  "c.pri",
  "c.group",
  "",
] as const;

export const ENDPOINT_KINDS = [
  "host",
  "host-group",
  "cidr",
  "object",
  "internet",
  "any",
  "k8s-namespace",
  "k8s-label",
] as const;

export const PROTOS = ["tcp", "udp", "icmp", "any"] as const;
export const ACTIONS = ["allow", "deny"] as const;
export const DENY_MODES = ["", "drop", "reject"] as const;

export interface Endpoint {
  kind: string;
  value: string;
}

export interface Rule {
  id: string;
  name: string;
  src: Endpoint;
  dst: Endpoint;
  proto: string;
  ports: string;
  action: string;
  denyMode?: string;
  priority: number;
  enabled: boolean;
  notes: string;
  [key: string]: unknown;
}

export interface PolicyDoc {
  schemaVersion: number;
  groups: Record<string, Rule[]>;
  [key: string]: unknown;
}

export type DocRead = { ok: true; doc: PolicyDoc } | { ok: false; reason: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isEndpoint(value: unknown): value is Endpoint {
  return isRecord(value) && typeof value.kind === "string" && typeof value.value === "string";
}

function isRule(value: unknown): value is Rule {
  return isRecord(value) && isEndpoint(value.src) && isEndpoint(value.dst);
}

export function readPolicyDoc(content: string): DocRead {
  let raw: unknown;
  try {
    raw = JSON.parse(content);
  } catch (e) {
    return { ok: false, reason: `not JSON: ${(e as Error).message}` };
  }
  if (!isRecord(raw)) return { ok: false, reason: "the policy document is not an object" };
  if (!isRecord(raw.groups)) return { ok: false, reason: "the policy document has no groups table" };
  for (const [name, list] of Object.entries(raw.groups)) {
    if (!Array.isArray(list)) return { ok: false, reason: `group ${name} is not a list of rules` };
    for (const rule of list) {
      if (!isRule(rule)) return { ok: false, reason: `group ${name} has a rule the table cannot edit` };
    }
  }
  return { ok: true, doc: raw as PolicyDoc };
}

export function writePolicyDoc(doc: PolicyDoc): string {
  return `${JSON.stringify(doc, null, 2)}\n`;
}

export function newRule(): Rule {
  return {
    id: "NEW-RULE",
    name: "",
    src: { kind: "cidr", value: "" },
    dst: { kind: "host", value: "" },
    proto: "tcp",
    ports: "",
    action: "allow",
    denyMode: "drop",
    priority: 100,
    enabled: true,
    notes: "",
  };
}

export function addRule(doc: PolicyDoc, group: string): Rule | null {
  const list = doc.groups[group];
  if (!list) return null;
  const rule = newRule();
  list.push(rule);
  return rule;
}

export function moveRule(doc: PolicyDoc, from: string, to: string, rule: Rule): boolean {
  const src = doc.groups[from];
  const dst = doc.groups[to];
  if (!src || !dst || from === to) return false;
  const at = src.indexOf(rule);
  if (at < 0) return false;
  src.splice(at, 1);
  dst.push(rule);
  return true;
}

export function deleteRule(doc: PolicyDoc, group: string, rule: Rule): boolean {
  const list = doc.groups[group];
  if (!list) return false;
  const at = list.indexOf(rule);
  if (at < 0) return false;
  list.splice(at, 1);
  return true;
}

/** Empty deny mode is absence. A blank string is not a value the schema accepts. */
export function setDenyMode(rule: Rule, value: string): void {
  if (value === "") delete rule.denyMode;
  else rule.denyMode = value;
}

export function rulesWithoutNotes(doc: PolicyDoc): string[] {
  const bare: string[] = [];
  for (const list of Object.values(doc.groups)) {
    for (const rule of list) if (!rule.notes) bare.push(rule.id);
  }
  return bare;
}

export function groupLabel(name: string): string {
  return name.replace("Policies", "");
}

export function endpointText(ep: Endpoint): string {
  if (ep.kind === "any" || ep.kind === "internet") return ep.kind;
  return ep.value ? `${ep.kind} ${ep.value}` : ep.kind;
}

export function portsText(proto: string, ports: string): string {
  const port = ports.trim() === "" ? "모든 포트" : ports;
  return `${proto} ${port}`;
}

export interface RuleDraft {
  group: string;
  id: string;
  name: string;
  srcKind: string;
  srcValue: string;
  dstKind: string;
  dstValue: string;
  proto: string;
  ports: string;
  action: string;
  denyMode: string;
  priority: number;
  enabled: boolean;
  notes: string;
}

export function draftFromRule(group: string, rule: Rule): RuleDraft {
  return {
    group,
    id: rule.id,
    name: rule.name,
    srcKind: rule.src.kind,
    srcValue: rule.src.value,
    dstKind: rule.dst.kind,
    dstValue: rule.dst.value,
    proto: rule.proto,
    ports: rule.ports,
    action: rule.action,
    denyMode: rule.denyMode ?? "",
    priority: rule.priority,
    enabled: rule.enabled,
    notes: rule.notes ?? "",
  };
}

/** Writes the draft onto the same object the table is bound to. Extra keys stay. */
export function applyDraft(doc: PolicyDoc, group: string, rule: Rule, draft: RuleDraft): void {
  rule.id = draft.id;
  rule.name = draft.name;
  rule.src.kind = draft.srcKind;
  rule.src.value = draft.srcValue;
  rule.dst.kind = draft.dstKind;
  rule.dst.value = draft.dstValue;
  rule.proto = draft.proto;
  rule.ports = draft.ports;
  rule.action = draft.action;
  setDenyMode(rule, draft.denyMode);
  rule.priority = draft.priority;
  rule.enabled = draft.enabled;
  rule.notes = draft.notes;
  if (draft.group !== group) moveRule(doc, group, draft.group, rule);
}
