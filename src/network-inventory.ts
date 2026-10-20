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
export interface InventoryRoutingDomain extends NetworkResource {
  kind: "routing-domain";
  name: string;
  isolation: "global" | "vrf" | "external";
  /** A logical domain does not require a Linux VRF. */
  vrf?: { name: string; table: number };
}
/** Explicit connectivity; validation conservatively treats connected domains as one address space.
 * This is not an advertisement policy and never installs or exports routes. */
export interface InventoryDomainConnection extends NetworkResource {
  kind: "domain-connection";
  domainIds: [string, string];
  allowManagement?: boolean;
}
export type NetworkPurpose = "application" | "infrastructure" | "management" | "backbone" | "kubernetes";
export type AddressPoolPurpose = "infrastructure" | "kubernetes-pod" | "kubernetes-service" | "tunnel" | "management";
/** Legacy siteId-only documents retain an implicit domain per network. Mixing with v2 is rejected. */
export type InventoryNetwork = NetworkResource & { kind: "network" } & (
  | { siteId: string; scope?: never; routingDomainId?: never; purpose?: never }
  | { scope: "site-local"; siteId: string; routingDomainId: string; purpose: NetworkPurpose }
  | { scope: "transit" | "overlay"; siteIds: string[]; routingDomainId: string; purpose: NetworkPurpose }
);
export interface InventorySubnet extends NetworkResource { kind: "subnet"; networkId: string; cidr: string; parentSubnetId?: string }
export interface InventoryAddressPool extends NetworkResource {
  kind: "address-pool";
  subnetId: string;
  cidr: string;
  /** Who allocates addresses; observing a pool does not transfer allocation authority. */
  allocationAuthority: string;
  /** Required in v2 documents; a pool is a reserved range, not an individual allocation. */
  purpose?: AddressPoolPurpose;
}
export interface InventoryInterface extends NetworkResource {
  kind: "interface";
  nodeId: string;
  networkId: string;
  name: string;
  /** Explicit desired MTU; omission does not assert the host default. */
  mtu?: number;
}
export interface InventoryRoute extends NetworkResource {
  kind: "route";
  interfaceId: string;
  destination: string;
  /** Explicit table avoids conflating routes in different policy routing tables. */
  table: number;
  routingDomainId?: string;
  /** Omission leaves the attribute unmanaged; null explicitly selects a direct route. */
  nextHop?: string | null;
  metric?: number;
  preferredSource?: string;
  routeType?: "unicast";
  protocol?: "static" | "boot";
}
/** Dynamic route candidates are observations, never configuration ownership claims.
 * Protocol/interface identity does not authorize a writer; external management is mandatory. */
export interface InventoryLearnedRoute extends NetworkResource {
  kind: "learned-route";
  management: { mode: "external"; provider: string };
  interfaceId: string;
  routingDomainId: string;
  destination: string;
  table: number;
  protocol: string;
  source: string;
  stage: "learned" | "selected" | "installed";
  nextHop?: string;
}
export type NetworkInventoryResource = InventorySite | InventoryNode | InventoryGateway |
  InventoryNetwork | InventorySubnet | InventoryAddressPool | InventoryInterface | InventoryRoute |
  InventoryRoutingDomain | InventoryDomainConnection | InventoryLearnedRoute;
export interface NetworkInventoryIssue { resourceId: string; message: string }

const text = (v: unknown): v is string => typeof v === "string" && v.trim().length > 0;
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const fields: Record<string, string[]> = {
  site: [], node: ["siteId"], gateway: ["nodeId"],
  network: ["siteId", "siteIds", "scope", "routingDomainId", "purpose"],
  subnet: ["networkId", "cidr", "parentSubnetId"],
  "address-pool": ["subnetId", "cidr", "allocationAuthority", "purpose"],
  interface: ["nodeId", "networkId", "name", "mtu"],
  route: ["interfaceId", "destination", "table", "routingDomainId", "nextHop", "metric", "preferredSource", "routeType", "protocol"],
  "learned-route": ["interfaceId", "routingDomainId", "destination", "table", "protocol", "source", "stage", "nextHop"],
  "routing-domain": ["name", "isolation", "vrf"], "domain-connection": ["domainIds", "allowManagement"],
};
const commonFields = ["id", "kind", "owner", "management", "generation", "observedGeneration"];
const unknownFields = (v: Record<string, unknown>, allowed: string[]) => Object.keys(v).some(k => !allowed.includes(k));
const kinds = new Set(["site", "node", "gateway", "network", "subnet", "address-pool", "interface", "route", "routing-domain", "domain-connection", "learned-route"]);

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
    const validGeneration = Number.isSafeInteger(value.generation) && typeof value.generation === "number" && value.generation >= 1;
    if (!validGeneration) add(id, "generation must be a positive safe integer");
    if (value.observedGeneration !== undefined && (!Number.isSafeInteger(value.observedGeneration) || Number(value.observedGeneration) < 1 || (!validGeneration || Number(value.observedGeneration) > (value.generation as number)))) add(id, "observedGeneration must be positive and no greater than generation");
    if (typeof value.kind === "string" && fields[value.kind] && unknownFields(value, [...commonFields, ...fields[value.kind]!])) add(id, "unknown resource field");
    const m = value.management;
    if (object(m) && unknownFields(m, ["mode", "provider", "driver", "adoption"])) add(id, "unknown management field");
    if (object(m) && object(m.adoption) && unknownFields(m.adoption, ["approvedBy", "source"])) add(id, "unknown adoption field");
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
  const lookup = (value: unknown) => typeof value === "string" ? byId.get(value) : undefined;
  const idOf = (r: Record<string, unknown>) => text(r.id) ? r.id : "";
  const uint32 = (value: unknown) => Number.isSafeInteger(value) && Number(value) >= 1 && Number(value) <= 4294967295;
  const v2 = records.some(r => r.kind === "routing-domain" || r.kind === "domain-connection" ||
    r.kind === "learned-route" || (r.kind === "route" && r.routingDomainId !== undefined) || (r.kind === "network" && ["scope", "routingDomainId", "purpose", "siteIds"].some(f => r[f] !== undefined)));
  const sitesOf = (network: Record<string, unknown>): unknown[] =>
    network.scope === "transit" || network.scope === "overlay" ? (Array.isArray(network.siteIds) ? network.siteIds : []) : [network.siteId];
  const domainOf = (network: Record<string, unknown> | undefined): string | undefined => {
    if (!network) return undefined;
    // Separate namespaces prevent a legacy network id from aliasing an explicit domain id.
    return v2 ? (text(network.routingDomainId) ? `domain:${network.routingDomainId}` : undefined) : `legacy:${idOf(network)}`;
  };
  const subnetDomain = (r: Record<string, unknown>) => domainOf(lookup(r.networkId));
  const ranges = new Map<Record<string, unknown>, NonNullable<ReturnType<typeof prefix>>>();
  const interfaces = new Set<string>();
  const routes = new Set<string>();
  for (const r of records) {
    const id = (text(r.id) ? r.id : "");
    switch (r.kind) {
      case "node": ref(r, "siteId", "site"); break;
      case "routing-domain":
        if (object(r.vrf) && unknownFields(r.vrf, ["name", "table"])) add(id, "unknown VRF field");
        if (!text(r.name)) add(id, "routing domain name must be nonempty");
        if (typeof r.isolation !== "string" || !["global", "vrf", "external"].includes(r.isolation)) add(id, "invalid routing domain isolation");
        if (r.vrf !== undefined && (!object(r.vrf) || !text(r.vrf.name) || !uint32(r.vrf.table))) add(id, "vrf requires name and positive uint32 table");
        if (r.vrf !== undefined && r.isolation !== "vrf") add(id, "vrf binding requires vrf isolation");
        break;
      case "domain-connection":
        if (!Array.isArray(r.domainIds) || r.domainIds.length !== 2 || !r.domainIds.every(d => text(d) && lookup(d)?.kind === "routing-domain") || r.domainIds[0] === r.domainIds[1]) add(id, "domainIds must reference two distinct routing domains");
        if (r.allowManagement !== undefined && typeof r.allowManagement !== "boolean") add(id, "allowManagement must be boolean");
        break;
      case "network":
        if (!v2) { ref(r, "siteId", "site"); break; }
        ref(r, "routingDomainId", "routing-domain");
        if (typeof r.purpose !== "string" || !["application", "infrastructure", "management", "backbone", "kubernetes"].includes(r.purpose)) add(id, "v2 network requires an explicit purpose");
        if (r.scope === "site-local") {
          ref(r, "siteId", "site");
          if (r.siteIds !== undefined) add(id, "site-local network cannot have siteIds");
        } else if (r.scope === "transit" || r.scope === "overlay") {
          if (r.siteId !== undefined) add(id, "multi-site network cannot have siteId");
          if (!Array.isArray(r.siteIds) || r.siteIds.length === 0 || !r.siteIds.every(s => text(s) && lookup(s)?.kind === "site") || new Set(r.siteIds).size !== r.siteIds.length) add(id, "multi-site network requires unique existing siteIds");
        } else add(id, "v2 inventory requires explicit network scope; migrate all legacy networks together");
        break;
      case "gateway": ref(r, "nodeId", "node"); break;
      case "subnet":
        ref(r, "networkId", "network");
        if (r.parentSubnetId !== undefined) ref(r, "parentSubnetId", "subnet");
        break;
      case "address-pool":
        ref(r, "subnetId", "subnet");
        if (!text(r.allocationAuthority)) add(id, "allocationAuthority must be explicit");
        if ((v2 || r.purpose !== undefined) && (typeof r.purpose !== "string" || !["infrastructure", "kubernetes-pod", "kubernetes-service", "tunnel", "management"].includes(r.purpose))) add(id, "pool requires a valid purpose");
        if ((r.purpose === "kubernetes-pod" || r.purpose === "kubernetes-service") && r.allocationAuthority !== "kubernetes") add(id, "Kubernetes pools must retain kubernetes allocation authority");
        break;
      case "interface": {
        const node = ref(r, "nodeId", "node");
        const network = ref(r, "networkId", "network");
        if (node && network && !sitesOf(network).includes(node.siteId)) add(id, "interface node and network must belong to the same site or explicit network membership");
        if (!text(r.name)) add(id, "interface name must be nonempty");
        if (r.mtu !== undefined && (!Number.isInteger(r.mtu) || Number(r.mtu) < 68 || Number(r.mtu) > 65535)) add(id, "interface mtu must be an integer between 68 and 65535");
        if (r.mtu !== undefined && Number(r.mtu) < 1280 && records.some(s => s.kind === "subnet" && s.networkId === r.networkId && typeof s.cidr === "string" && isIP(s.cidr.split("/")[0]!) === 6)) add(id, "IPv6 interface mtu must be at least 1280");
        const key = JSON.stringify([r.nodeId, r.name]);
        if (interfaces.has(key)) add(id, "interface already has an inventory owner");
        interfaces.add(key);
        break;
      }
      case "route": case "learned-route": {
        const iface = ref(r, "interfaceId", "interface");
        const network = iface && lookup(iface.networkId);
        if (v2) {
          ref(r, "routingDomainId", "routing-domain");
          if (network && r.routingDomainId !== network.routingDomainId) add(id, "route routing domain must match its interface network");
          const domain = lookup(r.routingDomainId);
          if (domain && object(domain.vrf) && r.table !== domain.vrf.table) add(id, "route table must match its routing domain VRF binding");
        }
        if (r.kind === "route") {
          const family = typeof r.destination === "string" ? isIP(r.destination.split("/")[0]!) : 0;
          for (const field of ["nextHop", "preferredSource"]) if (r[field] !== undefined && !(field === "nextHop" && r[field] === null) && (typeof r[field] !== "string" || !family || isIP(r[field] as string) !== family)) add(id, `${field} must match route address family`);
          if (r.metric !== undefined && (!Number.isSafeInteger(r.metric) || Number(r.metric) < 0 || Number(r.metric) > 4294967295)) add(id, "metric must be uint32");
          if (r.routeType !== undefined && r.routeType !== "unicast") add(id, "only unicast desired routes are supported");
          if (r.protocol !== undefined && !["static", "boot"].includes(String(r.protocol))) add(id, "only static or boot desired route protocols are supported");
        }
        if (r.kind === "learned-route") {
          if (!object(r.management) || r.management.mode !== "external") add(id, "learned routes are external observations, not writer claims");
          if (!text(r.protocol) || !text(r.source) || typeof r.stage !== "string" || !["learned", "selected", "installed"].includes(r.stage)) add(id, "learned route requires protocol, source and observation stage");
          if (r.nextHop !== undefined && (typeof r.nextHop !== "string" || isIP(r.nextHop) === 0)) add(id, "learned route nextHop must be an IP address");
        }
        if (!Number.isSafeInteger(r.table) || Number(r.table) < 1 || Number(r.table) > 4294967295) add(id, "route table must be a positive uint32");
        break;
      }
    }
    if (typeof r.kind === "string" && ["subnet", "address-pool", "route", "learned-route"].includes(r.kind)) {
      const range = prefix(r.kind === "route" || r.kind === "learned-route" ? r.destination : r.cidr);
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
  const contains = (outer: NonNullable<ReturnType<typeof prefix>>, inner: NonNullable<ReturnType<typeof prefix>>) =>
    outer.family === inner.family && outer.first <= inner.first && outer.last >= inner.last;
  const overlaps = (a: NonNullable<ReturnType<typeof prefix>>, b: NonNullable<ReturnType<typeof prefix>>) =>
    a.family === b.family && a.first <= b.last && b.first <= a.last;
  // Walk explicit parent edges only. Equal prefixes are not valid parent/child subdivisions.
  const ancestor = (child: Record<string, unknown>, candidate: Record<string, unknown>) => {
    const seen = new Set<Record<string, unknown>>();
    let current = lookup(child.parentSubnetId);
    while (current && !seen.has(current)) {
      if (current === candidate) return true;
      seen.add(current);
      current = lookup(current.parentSubnetId);
    }
    return false;
  };
  const graph = new Map<string, Set<string>>();
  for (const r of records.filter(r => r.kind === "domain-connection")) {
    if (!Array.isArray(r.domainIds) || r.domainIds.length !== 2) continue;
    const [a, b] = r.domainIds;
    if (!text(a) || !text(b) || lookup(a)?.kind !== "routing-domain" || lookup(b)?.kind !== "routing-domain" || a === b) continue;
    for (const [from, to] of [[a, b], [b, a]] as const) {
      if (!graph.has(`domain:${from}`)) graph.set(`domain:${from}`, new Set());
      graph.get(`domain:${from}`)!.add(`domain:${to}`);
    }
  }
  const connected = (a: string | undefined, b: string | undefined): boolean => {
    if (!a || !b) return false;
    const pending = [a];
    const seen = new Set<string>();
    for (const current of pending) {
      if (current === b) return true;
      if (seen.has(current)) continue;
      seen.add(current);
      pending.push(...(graph.get(current) ?? []));
    }
    return false;
  };
  for (const network of records.filter(r => r.kind === "network" && r.purpose === "management")) {
    if (records.some(r => r.kind === "network" && r.purpose !== "management" && domainOf(r) === domainOf(network))) add(idOf(network), "management networks require a separate routing domain from application and transit networks");
  }
  const managementDomains = records.filter(r => r.kind === "network" && r.purpose === "management").map(domainOf);
  for (const r of records.filter(r => r.kind === "domain-connection")) {
    if (Array.isArray(r.domainIds) && r.domainIds.some(d => text(d) && managementDomains.some(m => connected(m, `domain:${d}`))) && r.allowManagement !== true) add(idOf(r), "management domain connectivity requires explicit allowManagement consent on every connection");
  }
  for (const r of records) {
    const range = ranges.get(r);
    if (!range) continue;
    if (r.kind === "subnet" && r.parentSubnetId !== undefined) {
      const parent = lookup(r.parentSubnetId);
      const outer = parent && ranges.get(parent);
      if (parent && parent.kind === "subnet") {
        if (parent.networkId !== r.networkId) add(idOf(r), "parent subnet must belong to the same network");
        if (!outer || !contains(outer, range) || outer.bits >= range.bits) add(idOf(r), "child subnet must be a strict subdivision of its parent");
        if (ancestor(r, r)) add(idOf(r), "subnet parent hierarchy must be acyclic");
      }
    }
    if (r.kind === "address-pool") {
      const parent = lookup(r.subnetId);
      const outer = parent && ranges.get(parent);
      if (outer && !contains(outer, range)) add(idOf(r), "pool must be contained in its subnet");
    }
    if (r.kind !== "subnet" && r.kind !== "address-pool") continue;
    for (const other of records.slice(records.indexOf(r) + 1)) {
      if (other.kind !== r.kind) continue;
      const b = ranges.get(other);
      const domainA = r.kind === "subnet" ? subnetDomain(r) : subnetDomain(lookup(r.subnetId) ?? {});
      const domainB = other.kind === "subnet" ? subnetDomain(other) : subnetDomain(lookup(other.subnetId) ?? {});
      if (!b || !overlaps(range, b) || !connected(domainA, domainB)) continue;
      if (r.kind === "subnet" && r.networkId === other.networkId && (ancestor(r, other) || ancestor(other, r))) continue;
      add(idOf(other), `CIDR overlaps ${idOf(r)} in the same or connected routing domain`);
    }
  }
  return issues;
}
