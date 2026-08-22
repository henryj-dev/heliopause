// GET /api/policy/screen, as this package is allowed to see it.
//
// Duplicated rather than imported from `heliopause`: the web package must not
// pull the library into a Vite bundle. Extra keys from the server are ignored.

export type PolicyAction = "allow" | "deny";
export type PolicyRisk = "renders-nowhere" | "any-source" | "all-ports" | "disabled";

export interface PolicyRow {
  id: string;
  name: string;
  action: PolicyAction;
  denyMode: string;
  proto: string;
  ports: string;
  priority: number;
  enabled: boolean;
  notes: string | null;
  hosts: string[];
  skippedOn: string[];
  placementKnown: boolean;
  egressHosts: string[];
  srcCidrs: string[];
  risks: PolicyRisk[];
}

export interface BaselineRow {
  desc: string;
  proto: string;
  ports: string;
  srcCidrs: string[];
  anySource: boolean;
}

export interface HostRow {
  id: string;
  stage: string;
  inputCount: number;
  egressCount: number;
  skipped: string[];
  placementKnown: boolean;
  protected: boolean;
  fleet?: { state: string | null; generation: string | null; current: boolean; drifted: boolean; ageSec: number | null; blockedBy: string | null };
}

export interface WorkloadRow {
  id: string;
  name: string;
  action: string;
  src: string;
  dst: string;
  proto: string;
  ports: string;
  enabled: boolean;
  notes: string | null;
}

export interface ZoneRow {
  id: string;
  name: string;
  cidrs: string[];
  trust: number;
  notes: string;
  asSource: number;
  asDestination: number;
  admits: number;
}

export interface CrossingRow {
  policyId: string;
  policyName: string;
  from: string;
  to: string;
  gain: number;
  action: string;
}

export type CoverageVerdict = "pass" | "fail" | "unknown" | "n/a";

export interface CoverageCellView {
  verdict: CoverageVerdict;
  stale: boolean;
  at: string | null;
  observedFrom: string | null;
}

export interface CoverageRow {
  title: string;
  expect: "reach" | "blocked" | null;
  targets: string[];
  v4: CoverageCellView;
  v6: CoverageCellView;
}

export interface CoverageView {
  rows: CoverageRow[];
  failing: number;
  unknown: number;
  passing: number;
}

export interface DeviceRow {
  deviceName: string;
  userEmail: string;
  v4: string;
  v6: string;
  zone: string;
  state: string;
  notes: string;
  liveV4: string | null;
}

export interface UnapprovedDevice {
  deviceName: string;
  v4: string;
}

export interface DeviceView {
  rows: DeviceRow[];
  unapproved: UnapprovedDevice[];
  compared: boolean;
  readAt: string | null;
  addressless: number;
}

export interface UserRow {
  email: string;
  devices: number;
  zones: string[];
  v4: string[];
}

export interface ObjectRow {
  id: string;
  name: string;
  members: string[];
  notes: string | null;
  usedBy: string[];
}

export interface FeedRow {
  ref: string;
  usedBy: string[];
}

export interface MembershipRow {
  kind: string;
  name: string;
  members: string[];
  at: string;
  host: string;
  usedBy: string[];
}

export interface AddressSpaceRow {
  cidr: string;
  asSource: number;
  asHost: string[];
}

export interface HistoryRow {
  id: string;
  subject: string;
  author: string;
  at: string;
  status: string;
  liveOn: string[];
}

export interface EditableFile {
  path: string;
  content: string;
}

export interface PolicyEdit {
  path: string;
  content: string;
  more: EditableFile[];
}

export type Freshness =
  | { state: "fresh" }
  | { state: "stale"; rendered: string | null; repository: string }
  | { state: "unknown"; why: string };

export interface PolicyScreenView {
  rows: PolicyRow[];
  baseline: BaselineRow[];
  hosts: HostRow[];
  workload: WorkloadRow[];
  zones: ZoneRow[];
  crossings: CrossingRow[];
  coverage: CoverageView | null;
  devices: DeviceView | null;
  users: UserRow[];
  objects: ObjectRow[];
  services: ObjectRow[];
  feeds: FeedRow[];
  membership: MembershipRow[];
  addressSpace: AddressSpaceRow[];
  history: HistoryRow[];
  site: string;
  generation: string | null;
  hostIds: string[];
  freshness: Freshness | null;
  renderer: { build: string | null; mine: string } | null;
  canWrite: boolean;
  edit: PolicyEdit | null;
}

export type PolicyScreenRead =
  | { ok: true; view: PolicyScreenView }
  | { ok: false; reason: string };

const ACTIONS = new Set<PolicyAction>(["allow", "deny"]);
const RISKS = new Set<PolicyRisk>(["renders-nowhere", "any-source", "all-ports", "disabled"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readStrings(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") return null;
    out.push(item);
  }
  return out;
}

function readPolicyRow(value: unknown): PolicyRow | null {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.name !== "string") return null;
  if (typeof value.action !== "string" || !ACTIONS.has(value.action as PolicyAction)) return null;
  if (typeof value.priority !== "number" || typeof value.enabled !== "boolean") return null;
  if (typeof value.placementKnown !== "boolean") return null;
  const hosts = readStrings(value.hosts);
  const skippedOn = readStrings(value.skippedOn);
  const egressHosts = readStrings(value.egressHosts);
  const srcCidrs = readStrings(value.srcCidrs);
  if (!hosts || !skippedOn || !egressHosts || !srcCidrs || !Array.isArray(value.risks)) return null;
  const risks: PolicyRisk[] = [];
  for (const risk of value.risks) {
    if (typeof risk !== "string" || !RISKS.has(risk as PolicyRisk)) return null;
    risks.push(risk as PolicyRisk);
  }
  return {
    id: value.id,
    name: value.name,
    action: value.action as PolicyAction,
    denyMode: typeof value.denyMode === "string" ? value.denyMode : "",
    proto: typeof value.proto === "string" ? value.proto : "",
    ports: typeof value.ports === "string" ? value.ports : "",
    priority: value.priority,
    enabled: value.enabled,
    notes: typeof value.notes === "string" ? value.notes : null,
    hosts,
    skippedOn,
    placementKnown: value.placementKnown,
    egressHosts,
    srcCidrs,
    risks,
  };
}

function readBaseline(value: unknown): BaselineRow | null {
  if (!isRecord(value) || typeof value.desc !== "string" || typeof value.proto !== "string") return null;
  const srcCidrs = readStrings(value.srcCidrs);
  if (!srcCidrs || typeof value.anySource !== "boolean") return null;
  return {
    desc: value.desc,
    proto: value.proto,
    ports: typeof value.ports === "string" ? value.ports : "",
    srcCidrs,
    anySource: value.anySource,
  };
}

function readHost(value: unknown): HostRow | null {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.stage !== "string") return null;
  if (typeof value.inputCount !== "number" || typeof value.egressCount !== "number") return null;
  const skipped = readStrings(value.skipped);
  if (!skipped || typeof value.placementKnown !== "boolean" || typeof value.protected !== "boolean") return null;
  let fleet: HostRow["fleet"];
  if (isRecord(value.fleet)) {
    fleet = {
      state: typeof value.fleet.state === "string" ? value.fleet.state : null,
      generation: typeof value.fleet.generation === "string" ? value.fleet.generation : null,
      current: value.fleet.current === true,
      drifted: value.fleet.drifted === true,
      ageSec: typeof value.fleet.ageSec === "number" ? value.fleet.ageSec : null,
      blockedBy: typeof value.fleet.blockedBy === "string" ? value.fleet.blockedBy : null,
    };
  }
  return {
    id: value.id,
    stage: value.stage,
    inputCount: value.inputCount,
    egressCount: value.egressCount,
    skipped,
    placementKnown: value.placementKnown,
    protected: value.protected,
    ...(fleet ? { fleet } : {}),
  };
}

function readWorkload(value: unknown): WorkloadRow | null {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.name !== "string") return null;
  return {
    id: value.id,
    name: value.name,
    action: typeof value.action === "string" ? value.action : "",
    src: typeof value.src === "string" ? value.src : "",
    dst: typeof value.dst === "string" ? value.dst : "",
    proto: typeof value.proto === "string" ? value.proto : "",
    ports: typeof value.ports === "string" ? value.ports : "",
    enabled: value.enabled === true,
    notes: typeof value.notes === "string" ? value.notes : null,
  };
}

function readZone(value: unknown): ZoneRow | null {
  if (!isRecord(value)) return null;
  const zone = isRecord(value.zone) ? value.zone : value;
  if (typeof zone.id !== "string" || typeof zone.name !== "string") return null;
  const cidrs = readStrings(zone.cidrs);
  if (!cidrs || typeof zone.trust !== "number") return null;
  return {
    id: zone.id,
    name: zone.name,
    cidrs,
    trust: zone.trust,
    notes: typeof zone.notes === "string" ? zone.notes : "",
    asSource: typeof value.asSource === "number" ? value.asSource : 0,
    asDestination: typeof value.asDestination === "number" ? value.asDestination : 0,
    admits: typeof value.admits === "number" ? value.admits : 0,
  };
}

function readCrossing(value: unknown): CrossingRow | null {
  if (!isRecord(value) || typeof value.policyId !== "string" || typeof value.policyName !== "string") return null;
  const from = isRecord(value.from) && typeof value.from.name === "string" ? value.from.name : "";
  const to = isRecord(value.to) && typeof value.to.name === "string" ? value.to.name : "";
  if (!from || !to) return null;
  return {
    policyId: value.policyId,
    policyName: value.policyName,
    from,
    to,
    gain: typeof value.gain === "number" ? value.gain : 0,
    action: typeof value.action === "string" ? value.action : "",
  };
}

const VERDICTS = new Set<CoverageVerdict>(["pass", "fail", "unknown", "n/a"]);

function readCoverageCell(value: unknown): CoverageCellView {
  if (typeof value === "string" && VERDICTS.has(value as CoverageVerdict)) {
    return { verdict: value as CoverageVerdict, stale: false, at: null, observedFrom: null };
  }
  if (!isRecord(value) || typeof value.verdict !== "string" || !VERDICTS.has(value.verdict as CoverageVerdict)) {
    return { verdict: "unknown", stale: false, at: null, observedFrom: null };
  }
  return {
    verdict: value.verdict as CoverageVerdict,
    stale: value.stale === true,
    at: typeof value.at === "string" ? value.at : null,
    observedFrom: typeof value.observedFrom === "string" ? value.observedFrom : null,
  };
}

function readCoverageRow(value: unknown): CoverageRow | null {
  if (!isRecord(value)) return null;
  const check = isRecord(value.check) ? value.check : null;
  const title = check && typeof check.title === "string" ? check.title : typeof value.title === "string" ? value.title : "";
  const expect = check && (check.expect === "reach" || check.expect === "blocked") ? check.expect : null;
  const targets = readStrings(value.targets) ?? [];
  if (!title) return null;
  return { title, expect, targets, v4: readCoverageCell(value.v4), v6: readCoverageCell(value.v6) };
}

function readCoverage(value: unknown): CoverageView | null {
  if (!isRecord(value) || !Array.isArray(value.rows)) return null;
  const rows: CoverageRow[] = [];
  for (const item of value.rows) {
    const row = readCoverageRow(item);
    if (!row) return null;
    rows.push(row);
  }
  const summary = isRecord(value.summary) ? value.summary : value;
  return {
    rows,
    failing: typeof summary.failing === "number" ? summary.failing : 0,
    unknown: typeof summary.unknown === "number" ? summary.unknown : 0,
    passing: typeof summary.passing === "number" ? summary.passing : 0,
  };
}

function readDevice(value: unknown): DeviceRow | null {
  if (!isRecord(value) || typeof value.deviceName !== "string" || typeof value.userEmail !== "string") return null;
  const zone = isRecord(value.zone) && typeof value.zone.name === "string"
    ? value.zone.name
    : typeof value.zone === "string" ? value.zone : "";
  return {
    deviceName: value.deviceName,
    userEmail: value.userEmail,
    v4: typeof value.v4 === "string" ? value.v4 : "",
    v6: typeof value.v6 === "string" ? value.v6 : "",
    zone,
    state: typeof value.state === "string" ? value.state : "unchecked",
    notes: typeof value.notes === "string" ? value.notes : "",
    liveV4: typeof value.liveV4 === "string" ? value.liveV4 : null,
  };
}

function readUnapproved(value: unknown): UnapprovedDevice | null {
  if (!isRecord(value) || typeof value.deviceName !== "string") return null;
  const after = isRecord(value.after) ? value.after : null;
  const v4 = after && typeof after.v4 === "string"
    ? after.v4
    : typeof value.v4 === "string" ? value.v4 : "";
  return { deviceName: value.deviceName, v4 };
}

function readDevices(value: unknown): DeviceView | null {
  if (!isRecord(value) || !Array.isArray(value.rows)) return null;
  const rows: DeviceRow[] = [];
  for (const item of value.rows) {
    const row = readDevice(item);
    if (!row) return null;
    rows.push(row);
  }
  const unapproved: UnapprovedDevice[] = [];
  if (Array.isArray(value.unapproved)) {
    for (const item of value.unapproved) {
      const row = readUnapproved(item);
      if (row) unapproved.push(row);
    }
  }
  return {
    rows,
    unapproved,
    compared: value.compared === true,
    readAt: typeof value.readAt === "string" ? value.readAt : null,
    addressless: typeof value.addressless === "number" ? value.addressless : 0,
  };
}

function readUser(value: unknown): UserRow | null {
  if (!isRecord(value) || typeof value.email !== "string" || typeof value.devices !== "number") return null;
  const zones = readStrings(value.zones) ?? [];
  const v4 = readStrings(value.v4) ?? [];
  return { email: value.email, devices: value.devices, zones, v4 };
}

function readObject(value: unknown): ObjectRow | null {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.name !== "string") return null;
  const members = readStrings(value.members);
  const usedBy = readStrings(value.usedBy);
  if (!members || !usedBy) return null;
  return {
    id: value.id,
    name: value.name,
    members,
    notes: typeof value.notes === "string" ? value.notes : null,
    usedBy,
  };
}

function readFeed(value: unknown): FeedRow | null {
  if (!isRecord(value) || typeof value.ref !== "string") return null;
  const usedBy = readStrings(value.usedBy);
  if (!usedBy) return null;
  return { ref: value.ref, usedBy };
}

function readMembership(value: unknown): MembershipRow | null {
  if (!isRecord(value) || typeof value.name !== "string" || typeof value.host !== "string") return null;
  const members = readStrings(value.members);
  const usedBy = readStrings(value.usedBy);
  if (!members || !usedBy) return null;
  return {
    kind: typeof value.kind === "string" ? value.kind : "",
    name: value.name,
    members,
    at: typeof value.at === "string" ? value.at : "",
    host: value.host,
    usedBy,
  };
}

function readAddress(value: unknown): AddressSpaceRow | null {
  if (!isRecord(value) || typeof value.cidr !== "string" || typeof value.asSource !== "number") return null;
  const asHost = readStrings(value.asHost);
  if (!asHost) return null;
  return { cidr: value.cidr, asSource: value.asSource, asHost };
}

function readHistory(value: unknown): HistoryRow | null {
  if (!isRecord(value)) return null;
  const commit = isRecord(value.commit) ? value.commit : value;
  if (typeof commit.id !== "string" || typeof commit.subject !== "string") return null;
  const liveOn = readStrings(value.liveOn) ?? [];
  return {
    id: commit.id,
    subject: commit.subject,
    author: typeof commit.author === "string" ? commit.author : "",
    at: typeof commit.at === "string" ? commit.at : "",
    status: typeof value.status === "string" ? value.status : "unknown",
    liveOn,
  };
}

function readList<T>(value: unknown, read: (item: unknown) => T | null, label: string): T[] | string {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return `${label} is not a list`;
  const out: T[] = [];
  for (const item of value) {
    const row = read(item);
    if (!row) return `a ${label} row is malformed`;
    out.push(row);
  }
  return out;
}

function readEdit(value: unknown): PolicyEdit | null {
  if (!isRecord(value) || typeof value.path !== "string" || typeof value.content !== "string") return null;
  const more: EditableFile[] = [];
  if (Array.isArray(value.more)) {
    for (const item of value.more) {
      if (!isRecord(item) || typeof item.path !== "string" || typeof item.content !== "string") return null;
      more.push({ path: item.path, content: item.content });
    }
  }
  return { path: value.path, content: value.content, more };
}

function readFreshness(value: unknown): Freshness | null {
  if (!isRecord(value) || typeof value.state !== "string") return null;
  if (value.state === "fresh") return { state: "fresh" };
  if (value.state === "unknown" && typeof value.why === "string") return { state: "unknown", why: value.why };
  if (value.state === "stale" && typeof value.repository === "string") {
    return {
      state: "stale",
      rendered: typeof value.rendered === "string" ? value.rendered : null,
      repository: value.repository,
    };
  }
  return null;
}

function readRenderer(value: unknown): { build: string | null; mine: string } | null {
  if (!isRecord(value) || typeof value.mine !== "string") return null;
  return {
    build: typeof value.build === "string" ? value.build : null,
    mine: value.mine,
  };
}

export function readPolicyScreen(data: unknown): PolicyScreenRead {
  if (!isRecord(data)) return { ok: false, reason: "policy screen is not an object" };
  if (!Array.isArray(data.rows)) return { ok: false, reason: "policy screen is missing rows" };
  const rows: PolicyRow[] = [];
  for (const item of data.rows) {
    const row = readPolicyRow(item);
    if (!row) return { ok: false, reason: "a policy row is malformed" };
    rows.push(row);
  }
  const extra = isRecord(data.extra) ? data.extra : data;
  const baseline = readList(extra.baseline, readBaseline, "baseline");
  if (typeof baseline === "string") return { ok: false, reason: baseline };
  const hosts = readList(extra.hosts, readHost, "hosts");
  if (typeof hosts === "string") return { ok: false, reason: hosts };
  const workload = readList(extra.workload, readWorkload, "workload");
  if (typeof workload === "string") return { ok: false, reason: workload };
  const zones = readList(extra.zones, readZone, "zones");
  if (typeof zones === "string") return { ok: false, reason: zones };
  const crossings = readList(extra.crossings, readCrossing, "crossings");
  if (typeof crossings === "string") return { ok: false, reason: crossings };
  const users = readList(extra.users, readUser, "users");
  if (typeof users === "string") return { ok: false, reason: users };
  const objects = readList(extra.objects, readObject, "objects");
  if (typeof objects === "string") return { ok: false, reason: objects };
  const services = readList(extra.services, readObject, "services");
  if (typeof services === "string") return { ok: false, reason: services };
  const feeds = readList(extra.feeds, readFeed, "feeds");
  if (typeof feeds === "string") return { ok: false, reason: feeds };
  const membership = readList(extra.membership, readMembership, "membership");
  if (typeof membership === "string") return { ok: false, reason: membership };
  const addressSpace = readList(extra.addressSpace, readAddress, "address space");
  if (typeof addressSpace === "string") return { ok: false, reason: addressSpace };
  const history = readList(extra.history, readHistory, "history");
  if (typeof history === "string") return { ok: false, reason: history };
  const hostIds = readStrings(data.hosts) ?? [];
  let coverage: CoverageView | null = null;
  if (extra.coverage !== undefined) {
    coverage = readCoverage(extra.coverage);
    if (!coverage) return { ok: false, reason: "coverage is malformed" };
  }
  let devices: DeviceView | null = null;
  if (extra.devices !== undefined) {
    devices = readDevices(extra.devices);
    if (!devices) return { ok: false, reason: "devices are malformed" };
  }
  return {
    ok: true,
    view: {
      rows,
      baseline,
      hosts,
      workload,
      zones,
      crossings,
      coverage,
      devices,
      users,
      objects,
      services,
      feeds,
      membership,
      addressSpace,
      history,
      site: typeof data.site === "string" ? data.site : "",
      generation: typeof data.generation === "string" ? data.generation : null,
      hostIds,
      freshness: data.freshness === undefined ? null : readFreshness(data.freshness),
      renderer: readRenderer(data.renderer),
      canWrite: data.canWrite === true,
      edit: data.edit === undefined ? null : readEdit(data.edit),
    },
  };
}
