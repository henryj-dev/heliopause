// Every certificate this deployment depends on, with how long each has left — `GET /api/certificates`.
//
// Pure: the manager gathers the readings (relay polls, its own files, the certificate it is serving)
// and this decides what they add up to. The interesting cases are the incomplete ones — a relay that
// did not answer, a file that would not parse — and those are data here, not infrastructure.
//
// ## Expected is derived, not counted from what was seen
//
// A report that lists only what it observed cannot say that something is missing: a relay that did
// not answer simply contributes no rows, and the total shrinks without anything turning red. So the
// expected set comes from configuration (one relay, one client certificate and one CA per configured
// VPC; one agent per host in each relay's manifest), and every expected item without a row is named
// in `missing`. A consumer alerts on `complete: false`, not on a count it has to remember.
//
// ## What the consumer can rely on
//
// stardust's cert-drift rejects a whole report when any string exceeds `MAX_WIRE_STRING` or a `kind`
// does not match `^[a-z][a-z-]{0,31}$`, so both are properties of every report this returns. Strings
// that identify something are never truncated — two truncated names can collide — they are replaced
// by a digest of the original instead. Only explanatory text is shortened.

import { createHash } from "node:crypto";
import { CERT_THRESHOLDS, certState, type CertFacts, type CertState } from "./cert-watch.ts";
import type { RelayResult } from "./manager.ts";

export const CERTIFICATE_REPORT_SCHEMA = 1;

/** The longest string any report carries. Set by the consumer's validation, not by this code. */
export const MAX_WIRE_STRING = 512;

/** An agent reading older than this is reported but flagged: heartbeats arrive every few seconds. */
export const AGENT_READING_STALE_SEC = 600;

export const CERT_KINDS = [
  "agent", "relay-server", "manager-client", "manager-server", "ca", "operator",
] as const;
export type CertKind = (typeof CERT_KINDS)[number];

export type CertSource = "wire" | "loaded" | "file";

export interface CertificateRow {
  /** Unique within one report, stable across reports for the same thing. Use this as the name. */
  id: string;
  kind: CertKind;
  vpc: string | null;
  host: string | null;
  cn: string | null;
  serial: string;
  sha256: string;
  notBefore: string;
  notAfter: string;
  daysLeft: number | null;
  state: CertState;
  source: CertSource;
  /** `manager`, or `relay:<vpc>` for an agent certificate the relay saw on a heartbeat. */
  observedBy: string;
  observedAt: string;
  stale: boolean;
}

export interface MissingCertificate {
  kind: CertKind;
  vpc: string | null;
  host: string | null;
  reason: string;
}

export interface CertificateReport {
  schema: typeof CERTIFICATE_REPORT_SCHEMA;
  observedAt: string;
  renewBeforeDays: number;
  criticalDays: number;
  /** `true` only when every expected certificate has a row. */
  complete: boolean;
  /**
   * Whether a known-operators directory is configured. `false` reports no operator certificates and
   * expects none — which is not the same as a configured directory that is empty, and a consumer
   * deciding whether operator expiry is watched at all needs to tell the two apart.
   */
  operatorsConfigured: boolean;
  expected: { total: number; byKind: Record<CertKind, number> };
  observed: { total: number; byKind: Record<CertKind, number> };
  missing: MissingCertificate[];
  certificates: CertificateRow[];
}

/** A file this process tried to read: its facts, or why it could not. */
export type FileReading = CertFacts | { error: string };

export interface InventoryInput {
  now: Date;
  /** One per configured relay, in configuration order — reachable or not. */
  relays: readonly RelayResult[];
  /** Per configured VPC: the client certificate presented to its relay, and its CA. */
  vpcFiles: ReadonlyArray<{ vpc: string; client: FileReading; ca: FileReading }>;
  manager: {
    /** The certificate this process is serving — fixed at start. */
    loaded: CertFacts;
    /** The same path read now. Differs from `loaded` after a rotation the process has not restarted for. */
    file: FileReading;
  };
  /**
   * Known operators' public certificates, one entry per file in the configured directory. `null`
   * when no directory is configured — distinct from an empty one, which expects nothing on purpose.
   */
  operators: ReadonlyArray<{ file: string; reading: FileReading }> | null;
}

const isFacts = (r: FileReading): r is CertFacts => !("error" in r);

const digest = (s: string) => `sha256:${createHash("sha256").update(s).digest("hex")}`;

/** An identifying string, kept whole when it fits and replaced by its digest when it does not. */
function ident(s: string): string;
function ident(s: string | null): string | null;
function ident(s: string | null): string | null {
  if (s === null) return null;
  return s.length <= MAX_WIRE_STRING ? s : digest(s);
}

/** Explanatory text, shortened to fit. Never used for anything a consumer keys on. */
export function prose(s: string): string {
  const mark = "…[truncated]";
  return s.length <= MAX_WIRE_STRING ? s : s.slice(0, MAX_WIRE_STRING - mark.length) + mark;
}

const zero = (): Record<CertKind, number> =>
  Object.fromEntries(CERT_KINDS.map((k) => [k, 0])) as Record<CertKind, number>;

export function certificateInventory(input: InventoryInput): CertificateReport {
  const { now } = input;
  const at = now.toISOString();
  const rows: CertificateRow[] = [];
  const missing: MissingCertificate[] = [];
  const expected = zero();
  const ids = new Set<string>();

  const add = (
    kind: CertKind, vpc: string | null, host: string | null, facts: CertFacts,
    source: CertSource, observedBy: string, observedAt: string, stale: boolean,
  ) => {
    const v = ident(vpc), h = ident(host), cn = ident(facts.cn);
    // `source` is part of the id because the manager's own certificate has two rows — the one it is
    // serving and the one on disk — and they are the same thing otherwise.
    let id = ident([kind, v ?? "-", h ?? cn ?? "-", source].join("/"));
    // Two rows can still meet: two operator files carrying one CN. Suffixed rather than dropped, so
    // the count still matches the files.
    for (let n = 2; ids.has(id); n++) id = ident(`${id}#${n}`);
    ids.add(id);
    const { state, daysLeft } = certState(facts.notAfter, now);
    rows.push({
      id, kind, vpc: v, host: h, cn,
      // Every field, not only the names: an agent row is what a relay told the manager, and a relay's
      // answer is input like any other.
      serial: ident(facts.serial), sha256: ident(facts.sha256),
      notBefore: ident(facts.notBefore), notAfter: ident(facts.notAfter), daysLeft, state,
      source, observedBy: ident(observedBy), observedAt: ident(observedAt), stale,
    });
  };
  const lack = (kind: CertKind, vpc: string | null, host: string | null, reason: string) =>
    missing.push({ kind, vpc: ident(vpc), host: ident(host), reason: prose(reason) });

  for (const r of input.relays) {
    expected["relay-server"]++;
    if (!r.ok) {
      lack("relay-server", r.name, null, `relay unreachable: ${r.error}`);
      // Its agents are not countable from here — the manifest that lists them is behind the relay.
      lack("agent", r.name, null, "relay unreachable — the agents behind it can be neither counted nor read");
      continue;
    }
    if (r.relayCert) add("relay-server", r.name, null, r.relayCert, "wire", "manager", at, false);
    else lack("relay-server", r.name, null, "relay answered but its certificate could not be read");

    for (const h of r.view.hosts) {
      expected.agent++;
      const c = h.agentCert ?? null;
      if (!c) {
        lack("agent", r.name, h.host, "no heartbeat certificate recorded by the relay since it started");
        continue;
      }
      const ageSec = (now.getTime() - new Date(c.observedAt).getTime()) / 1000;
      add("agent", r.name, h.host, c, "wire", `relay:${r.name}`, c.observedAt, !(ageSec <= AGENT_READING_STALE_SEC));
    }
  }

  for (const f of input.vpcFiles) {
    expected["manager-client"]++;
    if (isFacts(f.client)) add("manager-client", f.vpc, null, f.client, "file", "manager", at, false);
    else lack("manager-client", f.vpc, null, f.client.error);
    expected.ca++;
    if (isFacts(f.ca)) add("ca", f.vpc, null, f.ca, "file", "manager", at, false);
    else lack("ca", f.vpc, null, f.ca.error);
  }

  expected["manager-server"] += 2;
  add("manager-server", null, null, input.manager.loaded, "loaded", "manager", at, false);
  if (isFacts(input.manager.file)) add("manager-server", null, null, input.manager.file, "file", "manager", at, false);
  else lack("manager-server", null, null, input.manager.file.error);

  for (const o of input.operators ?? []) {
    expected.operator++;
    if (isFacts(o.reading)) add("operator", null, null, o.reading, "file", "manager", at, false);
    else lack("operator", null, ident(o.file), o.reading.error);
  }

  const observed = zero();
  for (const row of rows) observed[row.kind]++;
  const sum = (m: Record<CertKind, number>) => Object.values(m).reduce((a, b) => a + b, 0);

  return {
    schema: CERTIFICATE_REPORT_SCHEMA,
    observedAt: at,
    renewBeforeDays: CERT_THRESHOLDS.renewBeforeDays,
    criticalDays: CERT_THRESHOLDS.criticalDays,
    complete: missing.length === 0,
    operatorsConfigured: input.operators !== null,
    expected: { total: sum(expected), byKind: expected },
    observed: { total: sum(observed), byKind: observed },
    missing,
    certificates: rows,
  };
}

/**
 * One line per certificate that needs a person, for the fleet view's `problems`.
 *
 * `renew` and worse. A stale agent reading is still reported — its expiry did not move because the
 * relay stopped hearing about it.
 */
export function certificateProblems(report: CertificateReport): string[] {
  const out: string[] = [];
  for (const c of report.certificates) {
    if (c.state === "ok") continue;
    const where = [c.vpc, c.host ?? c.cn].filter(Boolean).join(" ");
    const when = c.daysLeft === null ? "an unreadable expiry" : c.daysLeft < 0
      ? `expired ${-c.daysLeft} day(s) ago` : `${c.daysLeft} day(s) left`;
    out.push(`${c.kind} certificate ${where} (${c.source}): ${c.state} — ${when}, notAfter ${c.notAfter}`);
  }
  return out;
}
