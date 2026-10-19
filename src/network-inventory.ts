import { isIP } from "node:net";
import { cidrRange } from "./nft.ts";

/** Inventory only: these records confer no authority to apply network configuration. */
/** Adoption metadata records operator intent; it is not authenticated approval evidence. */
export type NetworkManagement =
  | { mode: "external"; provider: string }
  | { mode: "managed"; provider: string; driver: string }
  | { mode: "adopted"; provider: string; driver: string; adoption: { approvedBy: string; source: string } };

export interface NetworkResource {
  id: string;
  /** Administrative owner, independent of the system that provides the resource. */
  owner: string;
  management: NetworkManagement;
  generation: number;
  /** Last desired generation actually observed; absence means no reconciliation evidence. */
  observedGeneration?: number;
}
export interface InventorySite extends NetworkResource { kind: "site" }
export interface InventoryNode extends NetworkResource { kind: "node"; siteId: string }
export interface InventoryGateway extends NetworkResource { kind: "gateway"; nodeId: string }
/** CIDR conflicts are scoped to a network (an isolated address domain), not a site. */
export interface InventoryNetwork extends NetworkResource { kind: "network"; siteId: string }
export interface InventorySubnet extends NetworkResource { kind: "subnet"; networkId: string; cidr: string }
export interface InventoryAddressPool extends NetworkResource {
  kind: "address-pool";
  subnetId: string;
  cidr: string;
  /** Who allocates addresses; observing a pool does not transfer allocation authority. */
  allocationAuthority: string;
}
export interface InventoryInterface extends NetworkResource {
  kind: "interface";
  nodeId: string;
  networkId: string;
  name: string;
}
export interface InventoryRoute extends NetworkResource {
  kind: "route";
  interfaceId: string;
  destination: string;
  /** Explicit table avoids conflating routes in different policy routing tables. */
  table: number;
}
export type NetworkInventoryResource = InventorySite | InventoryNode | InventoryGateway |
  InventoryNetwork | InventorySubnet | InventoryAddressPool | InventoryInterface | InventoryRoute;
export interface NetworkInventoryIssue { resourceId: string; message: string }

const text = (v: unknown): v is string => typeof v === "string" && v.trim().length > 0;
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const kinds = new Set(["site", "node", "gateway", "network", "subnet", "address-pool", "interface", "route"]);

function prefix(value: unknown) {
  if (typeof value !== "string" || !/^[^\s/]+\/(0|[1-9]\d*)$/.test(value)) return null;
  const [address] = value.split("/");
  if (!address || !isIP(address)) return null;
  const range = cidrRange(value);
  const host = cidrRange(address);
  // Inventories describe network prefixes, not addresses with an implicit masked base.
  return range && host && range.first === host.first ? range : null;
}

/** Validate untrusted inventory documents without performing I/O or changing existing config. */
export function validateNetworkInventory(input: unknown): NetworkInventoryIssue[] {
  const issues: NetworkInventoryIssue[] = [];
  const add = (id: string, message: string) => issues.push({ resourceId: id, message });
  if (!Array.isArray(input)) return [{ resourceId: "", message: "inventory must be an array" }];
  const records: Record<string, unknown>[] = [];
  const byId = new Map<string, Record<string, unknown>>();
  for (const value of input) {
    if (!object(value)) { add("", "resource must be an object"); continue; }
    const id = text(value.id) ? value.id : "";
    records.push(value);
    if (!id) add(id, "id must be nonempty");
    else if (byId.has(id)) add(id, "duplicate id");
    else byId.set(id, value);
    if (typeof value.kind !== "string" || !kinds.has(value.kind)) add(id, "unknown resource kind");
    if (!text(value.owner)) add(id, "owner must be nonempty");
    if (!Number.isSafeInteger(value.generation) || Number(value.generation) < 1) add(id, "generation must be a positive safe integer");
    if (value.observedGeneration !== undefined && (!Number.isSafeInteger(value.observedGeneration) || Number(value.observedGeneration) < 1 || Number(value.observedGeneration) > Number(value.generation))) add(id, "observedGeneration must be positive and no greater than generation");
    const m = value.management;
    if (!object(m) || !text(m.provider) || typeof m.mode !== "string" || !["external", "managed", "adopted"].includes(m.mode)) {
      add(id, "management requires a mode and provider");
    } else if (m.mode === "external") {
      if (m.driver !== undefined || m.adoption !== undefined) add(id, "external resources cannot claim a driver or adoption");
    } else {
      if (!text(m.driver)) add(id, "managed resources require one driver");
      if (m.mode === "adopted" && (!object(m.adoption) || !text(m.adoption.approvedBy) || !text(m.adoption.source))) add(id, "adoption requires approval and source evidence");
      if (m.mode === "managed" && m.adoption !== undefined) add(id, "adoption evidence requires adopted mode");
    }
  }
  const ref = (r: Record<string, unknown>, field: string, kind: string) => {
    const target = typeof r[field] === "string" ? byId.get(r[field]) : undefined;
    if (!target || target.kind !== kind) add((text(r.id) ? r.id : ""), `${field} must reference a ${kind}`);
    return target?.kind === kind ? target : undefined;
  };
  const ranges = new Map<Record<string, unknown>, NonNullable<ReturnType<typeof prefix>>>();
  const interfaces = new Set<string>();
  const routes = new Set<string>();
  for (const r of records) {
    const id = (text(r.id) ? r.id : "");
    switch (r.kind) {
      case "node": case "network": ref(r, "siteId", "site"); break;
      case "gateway": ref(r, "nodeId", "node"); break;
      case "subnet": ref(r, "networkId", "network"); break;
      case "address-pool":
        ref(r, "subnetId", "subnet");
        if (!text(r.allocationAuthority)) add(id, "allocationAuthority must be explicit");
        break;
      case "interface": {
        const node = ref(r, "nodeId", "node");
        const network = ref(r, "networkId", "network");
        if (node && network && node.siteId !== network.siteId) add(id, "interface node and network must belong to the same site");
        if (!text(r.name)) add(id, "interface name must be nonempty");
        const key = JSON.stringify([r.nodeId, r.name]);
        if (interfaces.has(key)) add(id, "interface already has an inventory owner");
        interfaces.add(key);
        break;
      }
      case "route": {
        ref(r, "interfaceId", "interface");
        if (!Number.isSafeInteger(r.table) || Number(r.table) < 1 || Number(r.table) > 4294967295) add(id, "route table must be a positive uint32");
        break;
      }
    }
    if (typeof r.kind === "string" && ["subnet", "address-pool", "route"].includes(r.kind)) {
      const range = prefix(r.kind === "route" ? r.destination : r.cidr);
      if (!range) add(id, "CIDR must be a valid, aligned IPv4 or IPv6 prefix");
      else {
        ranges.set(r, range);
        if (r.kind === "route") {
          const iface = byId.get((text(r.interfaceId) ? r.interfaceId : ""));
          const key = JSON.stringify([iface?.nodeId, r.table, range.family, String(range.first), range.bits]);
          if (routes.has(key)) add(id, "route destination and table already have an inventory owner on this node");
          routes.add(key);
        }
      }
    }
  }
  for (const r of records) {
    const range = ranges.get(r);
    if (!range) continue;
    if (r.kind === "address-pool") {
      const parent = byId.get((text(r.subnetId) ? r.subnetId : ""));
      const outer = parent && ranges.get(parent);
      if (outer && (range.family !== outer.family || range.first < outer.first || range.last > outer.last)) add((text(r.id) ? r.id : ""), "pool must be contained in its subnet");
    }
    if (r.kind !== "subnet" && r.kind !== "address-pool") continue;
    for (const other of records.slice(records.indexOf(r) + 1)) {
      if (other.kind !== r.kind) continue;
      const scope = r.kind === "subnet" ? "networkId" : "subnetId";
      const b = ranges.get(other);
      if (r[scope] === other[scope] && b && range.family === b.family && range.first <= b.last && b.first <= range.last) add((text(other.id) ? other.id : ""), `CIDR overlaps ${(text(r.id) ? r.id : "")} in the same ${scope}`);
    }
  }
  return issues;
}
