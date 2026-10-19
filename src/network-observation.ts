/** Authenticated host claims, kept separate from policy confirmation and desired inventory. */
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { atomicWriteFile, withFileLock } from "./json-store.ts";

export const MAX_NETWORK_OBSERVATION_BYTES = 128 * 1024;
export const MAX_NETWORK_OBSERVATION_HOSTS = 32;
export const MAX_NETWORK_OBSERVATIONS_BYTES = 5 * 1024 * 1024;
export type CollectorStatus = "success" | "not-installed" | "unsupported" | "unavailable" | "timeout" | "output-limit" | "error";
export interface NetworkCollectorObservation { status: CollectorStatus; startedAt: string; completedAt: string; data?: Record<string, unknown>[] }
export interface NetworkObservationReport {
  schemaVersion: 1; collectionId: string; startedAt: string; completedAt: string;
  observations: Record<string, NetworkCollectorObservation>;
  capabilities: Record<string, { available: boolean; status: CollectorStatus }>;
}
export interface NetworkObservationRecord { host: string; receivedAt: string; report: NetworkObservationReport; source?: string; relayReceivedAt?: string }
const statuses = new Set(["success", "not-installed", "unsupported", "unavailable", "timeout", "output-limit", "error"]);
const fields: Record<string, string[]> = {
  links: ["ifindex", "ifname", "mtu", "master", "link_index", "operstate", "flags"],
  addresses: ["ifindex", "ifname", "mtu", "master", "link_index", "operstate", "flags", "addresses"],
  routes4: ["dst", "gateway", "dev", "protocol", "metric", "table", "type", "prefsrc", "scope"],
  routes6: ["dst", "gateway", "dev", "protocol", "metric", "table", "type", "prefsrc", "scope"],
  rules4: ["priority", "src", "dst", "table", "iif", "oif", "action", "protocol"],
  rules6: ["priority", "src", "dst", "table", "iif", "oif", "action", "protocol"],
  "wg-public-key": ["interface", "publicKey"], "wg-listen-port": ["interface", "listenPort"],
  "wg-peers": ["interface", "peerPublicKey"], "wg-endpoints": ["interface", "peerPublicKey", "endpoint"],
  "wg-allowed-ips": ["interface", "peerPublicKey", "allowedIPs"], "wg-latest-handshakes": ["interface", "peerPublicKey", "latestHandshake"],
  "wg-transfer": ["interface", "peerPublicKey", "rxBytes", "txBytes"], "wg-persistent-keepalive": ["interface", "peerPublicKey", "persistentKeepalive"],
  "frr-version": ["version"], "frr-daemons": ["name", "state"],
  "frr-bgp-summary": ["addressFamily", "localAs", "routerId", "peer", "remoteAs", "state", "prefixesReceived", "prefixesSent"],
  "frr-routes4": ["addressFamily", "prefix", "valid", "bestPath", "peerId", "nextHops"],
  "frr-routes6": ["addressFamily", "prefix", "valid", "bestPath", "peerId", "nextHops"],
  "frr-bfd": ["peer", "state", "local", "interface", "vrf"],
};
export const NETWORK_COLLECTOR_NAMES = Object.freeze(Object.keys(fields));
export function observationHost(host: unknown): asserts host is string {
  if (typeof host !== "string" || !/^[A-Za-z0-9_.-]{1,128}$/.test(host)) throw new Error("invalid observation host");
}
function object(v: unknown): v is Record<string, unknown> { return !!v && typeof v === "object" && !Array.isArray(v); }
function keys(v: Record<string, unknown>, allowed: readonly string[]) { if (Object.keys(v).some(k => !allowed.includes(k))) throw new Error("unknown observation field"); }
function timestamp(v: unknown): v is string { return typeof v === "string" && /^\d{4}-\d\d-\d\dT.*(?:Z|\+00:00)$/.test(v) && Number.isFinite(Date.parse(v)); }
function label(v: unknown): boolean { return typeof v === "string" && /^[A-Za-z0-9_.:@/-]{1,128}$/.test(v); }
function integer(v: unknown, max = Number.MAX_SAFE_INTEGER): boolean { return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max; }
function prefix(v: unknown): boolean {
  if (typeof v !== "string") return false;
  const parts = v.split("/"); const family = isIP(parts[0] ?? "");
  return parts.length === 2 && family !== 0 && /^(0|[1-9]\d*)$/.test(parts[1]!) && Number(parts[1]) <= (family === 4 ? 32 : 128);
}
function row(name: string, value: unknown): void {
  if (!object(value)) throw new Error("invalid collector row"); keys(value, fields[name]!);
  const required = name === "addresses" ? ["ifindex", "ifname", "addresses"] : name === "links" ? ["ifindex", "ifname"] : name.startsWith("routes") ? ["dst"] : name.startsWith("rules") ? ["priority"] : name.startsWith("wg-") ? fields[name]! : name === "frr-version" ? ["version"] : name === "frr-daemons" ? ["name", "state"] : name === "frr-bgp-summary" ? ["addressFamily", "localAs", "peer", "remoteAs", "state"] : name.startsWith("frr-routes") ? ["addressFamily", "prefix", "valid", "bestPath", "nextHops"] : ["peer", "state"];
  if (required.some(k => !(k in value))) throw new Error("missing collector field");
  if (name.startsWith("rules") && !["src", "dst", "table", "action"].some(k => k in value)) throw new Error("missing rule identity");
  const expectedFamily = ["routes4", "rules4", "frr-routes4"].includes(name) ? 4 : ["routes6", "rules6", "frr-routes6"].includes(name) ? 6 : 0;
  if (expectedFamily) {
    if (name.startsWith("frr-routes") && value.addressFamily !== (expectedFamily === 4 ? "ipv4" : "ipv6")) throw new Error("route address family mismatch");
    for (const field of ["dst", "src", "gateway", "prefsrc", "prefix"]) {
      const candidate = value[field];
      if (candidate === undefined || candidate === "default" || candidate === "all") continue;
      if (typeof candidate !== "string" || isIP(candidate.split("/")[0]!) !== expectedFamily) throw new Error("route or rule address family mismatch");
    }
  }
  for (const [key, v] of Object.entries(value)) {
    let valid = false;
    if (["gateway", "prefsrc", "peer", "peerId", "local", "routerId"].includes(key)) valid = typeof v === "string" && isIP(v) !== 0 && (key !== "routerId" || isIP(v) === 4);
    else if (["dst", "src", "prefix"].includes(key)) valid = prefix(v) || (name.startsWith("routes") && key === "dst" && v === "default") || (name.startsWith("rules") && v === "all");
    else if (["publicKey", "peerPublicKey"].includes(key)) valid = (key === "publicKey" && v === null) || (typeof v === "string" && /^[A-Za-z0-9+/]{43}=$/.test(v));
    else if (key === "addresses") { valid = Array.isArray(v) && v.length <= 2048; if (valid) for (const a of v as unknown[]) { if (!object(a)) throw new Error("invalid address"); keys(a, ["family", "local", "prefixlen", "scope"]); if ((a.family !== "inet" && a.family !== "inet6") || typeof a.local !== "string" || isIP(a.local) !== (a.family === "inet" ? 4 : 6) || !integer(a.prefixlen, a.family === "inet" ? 32 : 128) || (a.scope !== undefined && !label(a.scope))) throw new Error("invalid address"); } }
    else if (key === "endpoint") { valid = v === null; if (object(v)) { keys(v, ["address", "port"]); valid = typeof v.address === "string" && isIP(v.address) !== 0 && integer(v.port, 65535); } }
    else if (["flags", "allowedIPs", "nextHops"].includes(key)) valid = Array.isArray(v) && v.length <= 2048 && v.every(x => key === "flags" ? label(x) : key === "allowedIPs" ? prefix(x) : typeof x === "string" && isIP(x) !== 0);
    else if (["valid", "bestPath"].includes(key)) valid = typeof v === "boolean";
    else if (key === "addressFamily") valid = v === "ipv4" || v === "ipv6";
    else if (key === "state") valid = typeof v === "string" && (name === "frr-daemons" ? v === "connected" : name === "frr-bfd" ? ["up", "down", "init", "admin-down"].includes(v) : ["Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established"].includes(v));
    else if (key === "version") valid = typeof v === "string" && /^[A-Za-z0-9_.+()-]{1,96}$/.test(v);
    else if (["ifindex", "mtu", "link_index", "metric", "priority", "localAs", "remoteAs", "prefixesReceived", "prefixesSent"].includes(key)) valid = integer(v, 4294967295);
    else if (["listenPort", "persistentKeepalive"].includes(key)) valid = integer(v, 65535);
    else if (["rxBytes", "txBytes", "latestHandshake"].includes(key)) valid = typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 18446744073709551615 && Number.isInteger(v);
    else if (["master", "table", "protocol", "scope"].includes(key)) valid = label(v) || integer(v, 4294967295);
    else valid = label(v);
    if (!valid) throw new Error("invalid normalized collector field");
  }
}
export function validateNetworkObservation(input: unknown): NetworkObservationReport {
  if (Buffer.byteLength(JSON.stringify(input) ?? "") > MAX_NETWORK_OBSERVATION_BYTES || !object(input)) throw new Error("observation too large or invalid");
  keys(input, ["schemaVersion", "collectionId", "startedAt", "completedAt", "observations", "capabilities"]);
  if (input.schemaVersion !== 1 || typeof input.collectionId !== "string" || !/^[a-f0-9-]{16,64}$/.test(input.collectionId) || !timestamp(input.startedAt) || !timestamp(input.completedAt) || Date.parse(input.completedAt) < Date.parse(input.startedAt) || !object(input.observations) || !object(input.capabilities)) throw new Error("invalid observation envelope");
  const names = Object.keys(input.observations);
  if (!names.length || names.length > Object.keys(fields).length || Object.keys(input.capabilities).length !== names.length) throw new Error("invalid collectors");
  for (const name of names) {
    if (!Object.hasOwn(fields, name)) throw new Error("unknown collector");
    const entry = input.observations[name]; const capability = input.capabilities[name];
    if (!object(entry) || !object(capability)) throw new Error("invalid collector result");
    keys(entry, ["status", "startedAt", "completedAt", "data"]); keys(capability, ["status", "available"]);
    if (typeof entry.status !== "string" || !statuses.has(entry.status) || !timestamp(entry.startedAt) || !timestamp(entry.completedAt) || Date.parse(entry.completedAt) < Date.parse(entry.startedAt) || Date.parse(entry.startedAt) < Date.parse(input.startedAt) || Date.parse(entry.completedAt) > Date.parse(input.completedAt) || capability.status !== entry.status || capability.available !== (entry.status === "success")) throw new Error("invalid collector status");
    if (entry.status === "success") { if (!Array.isArray(entry.data) || entry.data.length > 2048) throw new Error("invalid collector data"); for (const value of entry.data) row(name, value); }
    else if (entry.data !== undefined) throw new Error("failed collector cannot supply data");
  }
  return structuredClone(input) as unknown as NetworkObservationReport;
}
export function observationFreshness(record: NetworkObservationRecord | null, now = Date.now(), maxAgeMs = 10 * 60_000): "never-observed" | "fresh" | "stale" {
  if (!record) return "never-observed";
  const times = [record.receivedAt, record.report.completedAt, record.relayReceivedAt].filter((v): v is string => !!v).map(Date.parse);
  return times.every(t => Number.isFinite(t) && now >= t && now - t <= maxAgeMs) ? "fresh" : "stale";
}
/** Telemetry contention must not put the Relay event loop to sleep beside heartbeats. */
export class NetworkObservationStoreBusyError extends Error {}
export class NetworkObservationStore {
  readonly dir: string;
  constructor(dir: string) { this.dir = dir; mkdirSync(dir, { recursive: true, mode: 0o700 }); }
  private path(host: string, source?: string) { observationHost(host); if (source !== undefined) observationHost(source); return join(this.dir, createHash("sha256").update(JSON.stringify([source ?? "", host])).digest("hex") + ".json"); }
  get(host: string, source?: string): NetworkObservationRecord | null {
    const path = this.path(host, source); if (!existsSync(path)) return null;
    if (statSync(path).size > MAX_NETWORK_OBSERVATION_BYTES + 2048) throw new Error("stored observation too large");
    const record = JSON.parse(readFileSync(path, "utf8"));
    if (!object(record)) throw new Error("invalid stored observation");
    keys(record, ["host", "receivedAt", "report", "source", "relayReceivedAt"]);
    if (record.host !== host || record.source !== source || !timestamp(record.receivedAt) || (record.relayReceivedAt !== undefined && !timestamp(record.relayReceivedAt))) throw new Error("invalid stored observation");
    record.report = validateNetworkObservation(record.report); return record as unknown as NetworkObservationRecord;
  }
  list(): NetworkObservationRecord[] {
    const paths = readdirSync(this.dir).filter(n => /^[a-f0-9]{64}\.json$/.test(n)); if (paths.length > MAX_NETWORK_OBSERVATION_HOSTS) throw new Error("observation host limit exceeded");
    return paths.map(name => { const path = join(this.dir, name); if (statSync(path).size > MAX_NETWORK_OBSERVATION_BYTES + 2048) throw new Error("stored observation too large"); const r = JSON.parse(readFileSync(path, "utf8")); const found = this.get(r.host, r.source); if (!found) throw new Error("missing stored observation"); return found; });
  }
  put(host: string, report: unknown, metadata: { relayReceivedAt?: string; source?: string } = {}): NetworkObservationRecord {
    const value = validateNetworkObservation(report); const path = this.path(host, metadata.source);
    if (metadata.relayReceivedAt !== undefined && !timestamp(metadata.relayReceivedAt)) throw new Error("invalid relay receive time");
    return withFileLock(join(this.dir, "store"), 0, "network observations", (message, status) => status === 503 ? new NetworkObservationStoreBusyError("network observation store is busy") : new Error(message), () => {
      const previous = this.get(host, metadata.source);
      if (previous && (previous.report.collectionId === value.collectionId || Date.parse(value.completedAt) <= Date.parse(previous.report.completedAt))) return previous;
      if (!previous && this.list().length >= MAX_NETWORK_OBSERVATION_HOSTS) throw new Error("observation host limit exceeded");
      const record: NetworkObservationRecord = { host, receivedAt: new Date().toISOString(), report: value, ...metadata };
      atomicWriteFile(path, JSON.stringify(record)); return record;
    });
  }
}
