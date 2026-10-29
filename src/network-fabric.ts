/**
 * BGP fabric planner. Pure and offline: it reads a registry snapshot and returns what every
 * gateway would run. It never resolves secrets, invokes FRR or WireGuard, or touches a host.
 *
 * The shape is chosen so that routing follows BGP rather than configuration:
 * - one WireGuard interface per peer, `AllowedIPs = 0.0.0.0/0, ::/0` and `Table = off`, so the
 *   tunnel only binds a key to a path and FRR decides which prefixes use it;
 * - peer filters derived from each site's origin blocks, so a new subnet inside a block changes
 *   only its own gateway.
 * Adding a site still adds one peer on every existing gateway in a full mesh; `diffBgpFabricPlans`
 * reports exactly which gateways change.
 */
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { cidrRange } from "./nft.ts";
import { compareNetworkText, networkDigest } from "./network-canonical.ts";
import {
  validateNetworkInventory,
  type InventoryAddressPool, type InventoryBgpFabric, type InventoryBgpRouter, type InventoryFabricAttachment,
  type InventoryFabricTransport, type NetworkInventoryResource,
} from "./network-inventory.ts";
import type { NetworkRegistryDocument } from "./network-registry.ts";

export interface FabricWireGuardInterface {
  interfaceName: string;
  transportNetworkId: string;
  peerRouterId: string;
  listenPort: number;
  localAddress: string;
  peerAddress: string;
  peerPublicKey: string;
  peerEndpoint: string;
  allowedIps: string[];
  privateKeyRef: { provider: string; reference: string };
  persistentKeepalive?: number;
  mtu?: number;
  /** wg-quick text without PrivateKey; the key is resolved on the host from `privateKeyRef`. */
  template: string;
}
export interface FabricSession {
  routers: [string, string];
  transportNetworkId: string;
  preference: "primary" | "secondary";
}
export interface FabricGatewayPlan {
  routerId: string;
  nodeId: string;
  siteId: string;
  asn: number;
  wireguard: FabricWireGuardInterface[];
  /** High-metric routes for a static-fallback transport; FRR's eBGP routes win while they exist. */
  fallbackRoutes: Array<{ destination: string; interfaceId: string; metric: number }>;
  /** UDP ports the host firewall must accept for the native transport. */
  listenPorts: number[];
  frr: string;
  hash: string;
}
export interface BgpFabricPlan {
  schemaVersion: 1;
  kind: "bgp-fabric-plan";
  mode: "dry-run";
  executable: false;
  registryRevision: number;
  fabricId: string;
  sessions: FabricSession[];
  gateways: FabricGatewayPlan[];
  preconditions: string[];
  warnings: string[];
  hash: string;
}
export type BgpFabricPlanResult = { ok: true; plan: BgpFabricPlan; diagnostics: [] } | { ok: false; diagnostics: string[] };

/** Kernel metric for static-fallback routes. FRR installs eBGP routes with metric 20. */
export const FABRIC_FALLBACK_METRIC = 200;
const LOCAL_PREF = { primary: 200, secondary: 100 } as const;

const sorted = <T>(items: T[], key: (item: T) => string) => [...items].sort((a, b) => compareNetworkText(key(a), key(b)));
const hostBits = (address: string) => isIP(address) === 6 ? 128 : 32;
const familyOf = (cidr: string) => cidrRange(cidr)?.family === "ip6" ? 6 : 4;
const name = (...parts: string[]) => createHash("sha256").update(parts.join("\0")).digest("hex");
/** Route-map and list names derive from resource ids; hashing keeps them short and shell-safe. */
const tag = (id: string) => name("tag", id).slice(0, 10).toUpperCase();

export function planBgpFabric(input: {
  registry: Pick<NetworkRegistryDocument, "revision" | "resources">;
  expectedRegistryRevision: number;
  fabricId: string;
}): BgpFabricPlanResult {
  const errors: string[] = [];
  const bad = (m: string) => errors.push(m);
  const { registry } = input;
  if (!Number.isSafeInteger(input.expectedRegistryRevision) || registry.revision !== input.expectedRegistryRevision) bad("registry revision mismatch");
  for (const issue of validateNetworkInventory(registry.resources)) bad(`inventory ${issue.resourceId}: ${issue.message}`);
  if (errors.length) return { ok: false, diagnostics: errors.sort() };

  const resources = registry.resources;
  const byId = new Map<string, NetworkInventoryResource>(resources.map(r => [r.id, r]));
  const fabric = byId.get(input.fabricId);
  if (fabric?.kind !== "bgp-fabric") return { ok: false, diagnostics: ["fabricId must reference a bgp-fabric"] };
  const siteOf = (router: InventoryBgpRouter) => { const n = byId.get(router.nodeId); return n?.kind === "node" ? n.siteId : ""; };
  const attachments = resources.filter((r): r is InventoryFabricAttachment => r.kind === "fabric-attachment" && r.fabricId === fabric.id);
  const routerOf = (a: InventoryFabricAttachment) => byId.get(a.routerId) as InventoryBgpRouter;
  const addressOf = (a: InventoryFabricAttachment) => { const x = byId.get(a.tunnelAllocationId); return x?.kind === "address-allocation" ? x.address : ""; };
  const transportOf = (networkId: string) => fabric.transports.find(t => t.networkId === networkId)!;
  const native = (t: InventoryFabricTransport) => { const n = byId.get(t.networkId); return n?.kind === "network" && n.management.mode !== "external"; };
  const routers = sorted([...new Map(attachments.map(a => [a.routerId, routerOf(a)])).values()], r => r.id);
  if (routers.length < 2) return { ok: false, diagnostics: ["fabric needs at least two attached gateway routers"] };

  const warnings: string[] = [];
  for (const site of new Set(routers.map(siteOf))) {
    if (routers.filter(r => siteOf(r) === site).length > 1) warnings.push(`site ${site} has several gateway routers; in-site iBGP between them is not generated`);
  }
  const sessions: FabricSession[] = [];
  for (const t of sorted(fabric.transports, t => t.networkId)) {
    if (t.mode !== "bgp") continue;
    const onTransport = attachments.filter(a => a.networkId === t.networkId);
    for (const a of onTransport) for (const b of onTransport) {
      const ra = routerOf(a), rb = routerOf(b);
      if (compareNetworkText(ra.id, rb.id) >= 0 || siteOf(ra) === siteOf(rb)) continue;
      if (familyOf(`${addressOf(a)}/${hostBits(addressOf(a))}`) !== familyOf(`${addressOf(b)}/${hostBits(addressOf(b))}`)) { bad(`tunnel address families differ between ${a.id} and ${b.id}`); continue; }
      sessions.push({ routers: [ra.id, rb.id], transportNetworkId: t.networkId, preference: t.preference });
    }
  }
  for (const r of routers) {
    for (const t of fabric.transports) {
      if (!attachments.some(a => a.routerId === r.id && a.networkId === t.networkId)) warnings.push(`router ${r.id} is not attached to transport ${t.networkId}`);
    }
  }
  if (!sessions.length && fabric.transports.every(t => t.mode === "bgp")) bad("fabric produces no inter-site sessions");
  for (const t of fabric.transports.filter(native)) {
    for (const r of routers) if (t.listenPortBase! + r.fabricIndex! > 65535) bad(`listen port for ${r.id} on ${t.networkId} exceeds 65535`);
  }
  if (errors.length) return { ok: false, diagnostics: errors.sort() };

  const pools = resources.filter((r): r is InventoryAddressPool => r.kind === "address-pool");
  const subnetCidr = (id: string) => { const s = byId.get(id); return s?.kind === "subnet" ? s.cidr : ""; };
  const clustersOf = (site: string) => sorted(resources.filter((r): r is InventoryBgpRouter => r.kind === "bgp-router" && r.role === "cluster" && siteOf(r) === site), r => r.id);
  const inside = (outer: string, inner: string) => { const o = cidrRange(outer), i = cidrRange(inner); return !!o && !!i && o.family === i.family && o.first <= i.first && o.last >= i.last; };

  /** Prefix-list body for what a site may announce: its origin blocks, minus management and
   * tunnel pools, and only host routes from Service and load-balancer pools. */
  const siteFilter = (router: InventoryBgpRouter, family: 4 | 6) => {
    const blocks = (router.originSubnetIds ?? []).map(subnetCidr).filter(c => familyOf(c) === family).sort(compareNetworkText);
    const lines: string[] = [];
    const max = family === 6 ? 128 : 32;
    const inBlocks = (cidr: string) => blocks.some(b => inside(b, cidr));
    for (const p of sorted(pools, p => p.cidr)) {
      if (familyOf(p.cidr) !== family || !inBlocks(p.cidr)) continue;
      const bits = Number(p.cidr.split("/")[1]);
      if (p.purpose === "management" || p.purpose === "tunnel") lines.push(`deny ${p.cidr} le ${max}`);
      else if (p.purpose === "kubernetes-service" || p.purpose === "kubernetes-loadbalancer") {
        lines.push(`permit ${p.cidr} ge ${max}`);
        lines.push(bits === max ? `deny ${p.cidr}` : `deny ${p.cidr} le ${max}`);
      }
    }
    for (const b of blocks) lines.push(`permit ${b} le ${max}`);
    return lines;
  };
  /** What a gateway accepts from its own cluster speakers: Pod pools, and host routes from
   * Service and load-balancer pools. Nothing else, so a cluster cannot announce infrastructure. */
  const clusterFilter = (router: InventoryBgpRouter, family: 4 | 6) => {
    const max = family === 6 ? 128 : 32;
    const blocks = (router.originSubnetIds ?? []).map(subnetCidr);
    const lines: string[] = [];
    for (const p of sorted(pools, p => p.cidr)) {
      if (familyOf(p.cidr) !== family || !blocks.some(b => inside(b, p.cidr))) continue;
      if (p.purpose === "kubernetes-pod") lines.push(`permit ${p.cidr} le ${max}`);
      if (p.purpose === "kubernetes-service" || p.purpose === "kubernetes-loadbalancer") lines.push(`permit ${p.cidr} ge ${max}`);
    }
    return lines;
  };
  const asPath = (router: InventoryBgpRouter) => {
    const clusterAsns = [...new Set(clustersOf(siteOf(router)).map(c => c.asn))].sort((a, b) => a - b);
    return clusterAsns.length ? `^${router.asn}(_(${clusterAsns.join("|")}))?$` : `^${router.asn}$`;
  };

  const gateways: FabricGatewayPlan[] = [];
  const ifaceName = (local: string, peer: string, network: string) => `hpf${name("wg", fabric.id, network, local, peer).slice(0, 12)}`;
  for (const local of routers) {
    const mine = sorted(attachments.filter(a => a.routerId === local.id), a => a.networkId);
    const wireguard: FabricWireGuardInterface[] = [];
    const fallbackRoutes: FabricGatewayPlan["fallbackRoutes"] = [];
    const neighbors: Array<{ address: string; asn: number; description: string; routeMapIn: string; source?: string; family: 4 | 6; bfd: boolean }> = [];
    const prefixLists = new Map<string, { family: 4 | 6; lines: string[] }>();
    const routeMaps: string[] = [];
    const asPaths = new Map<string, string[]>();
    for (const a of mine) {
      const t = transportOf(a.networkId);
      const peers = attachments.filter(b => b.networkId === a.networkId && siteOf(routerOf(b)) !== siteOf(local));
      for (const b of sorted(peers, b => b.routerId)) {
        const peer = routerOf(b);
        if (native(t)) {
          const listenPort = t.listenPortBase! + peer.fabricIndex!;
          const peerPort = t.listenPortBase! + local.fabricIndex!;
          const endpoint = isIP(b.endpoint!) === 6 ? `[${b.endpoint}]:${peerPort}` : `${b.endpoint}:${peerPort}`;
          const localAddress = `${addressOf(a)}/${hostBits(addressOf(a))}`;
          const peerAddress = `${addressOf(b)}/${hostBits(addressOf(b))}`;
          const allowedIps = ["0.0.0.0/0", "::/0"];
          const template = [
            "[Interface]", `Address = ${localAddress}`, `ListenPort = ${listenPort}`, "Table = off",
            ...(t.mtu ? [`MTU = ${t.mtu}`] : []),
            "", "[Peer]", `PublicKey = ${b.publicKey}`, `Endpoint = ${endpoint}`, `AllowedIPs = ${allowedIps.join(", ")}`,
            ...(t.persistentKeepalive ? [`PersistentKeepalive = ${t.persistentKeepalive}`] : []), "",
          ].join("\n");
          wireguard.push({
            interfaceName: ifaceName(local.id, peer.id, a.networkId), transportNetworkId: a.networkId, peerRouterId: peer.id,
            listenPort, localAddress, peerAddress, peerPublicKey: b.publicKey!, peerEndpoint: endpoint, allowedIps,
            privateKeyRef: structuredClone(a.privateKeyRef!),
            ...(t.persistentKeepalive ? { persistentKeepalive: t.persistentKeepalive } : {}), ...(t.mtu ? { mtu: t.mtu } : {}),
            template,
          });
        }
        const peerTag = tag(peer.id);
        if (t.mode === "static-fallback") {
          for (const block of (peer.originSubnetIds ?? []).map(subnetCidr)) fallbackRoutes.push({ destination: block, interfaceId: a.interfaceId!, metric: FABRIC_FALLBACK_METRIC });
          continue;
        }
        const family = familyOf(`${addressOf(b)}/${hostBits(addressOf(b))}`) as 4 | 6;
        const list = `PL-SITE-${peerTag}-V${family}`;
        prefixLists.set(list, { family, lines: siteFilter(peer, family) });
        asPaths.set(`AP-${peerTag}`, [asPath(peer)]);
        const map = `RM-IN-${peerTag}-${tag(a.networkId)}`;
        routeMaps.push(
          `route-map ${map} permit 10`,
          ` match ${family === 6 ? "ipv6" : "ip"} address prefix-list ${list}`,
          ` match as-path AP-${peerTag}`,
          ` set local-preference ${LOCAL_PREF[t.preference]}`,
          "exit",
          `route-map ${map} deny 100`,
          "exit",
        );
        neighbors.push({ address: addressOf(b), asn: peer.asn, description: `${peer.id} via ${a.networkId}`, routeMapIn: map, source: addressOf(a), family, bfd: fabric.bfd === true });
      }
    }
    // Locally originated routes, plus routes from this site's cluster speakers.
    const ownTag = tag(local.id);
    const clusters = clustersOf(siteOf(local));
    const outPaths = ["^$", ...[...new Set(clusters.map(c => c.asn))].sort((x, y) => x - y).map(asn => `^${asn}$`)];
    asPaths.set(`AP-OUT-${ownTag}`, outPaths);
    for (const family of [4, 6] as const) {
      if (!neighbors.some(n => n.family === family)) continue;
      prefixLists.set(`PL-SITE-${ownTag}-V${family}`, { family, lines: siteFilter(local, family) });
      routeMaps.push(
        `route-map RM-OUT-V${family} permit 10`,
        ` match ${family === 6 ? "ipv6" : "ip"} address prefix-list PL-SITE-${ownTag}-V${family}`,
        ` match as-path AP-OUT-${ownTag}`,
        "exit",
        `route-map RM-OUT-V${family} deny 100`,
        "exit",
      );
    }
    for (const c of clusters) {
      const family = isIP(c.address!) as 4 | 6;
      const list = `PL-CLUSTER-${ownTag}-V${family}`;
      prefixLists.set(list, { family, lines: clusterFilter(local, family) });
      const map = `RM-IN-CLUSTER-V${family}`;
      if (!routeMaps.includes(`route-map ${map} permit 10`)) routeMaps.push(
        `route-map ${map} permit 10`,
        ` match ${family === 6 ? "ipv6" : "ip"} address prefix-list ${list}`,
        "exit",
        `route-map ${map} deny 100`,
        "exit",
      );
      neighbors.push({ address: c.address!, asn: c.asn, description: `cluster ${c.id}`, routeMapIn: map, family, bfd: false });
    }
    if (clusters.length) routeMaps.push("route-map RM-DENY-ALL deny 10", "exit");

    const frr: string[] = [
      "! Generated by heliopause (dry-run). Do not edit on the host.",
      "frr defaults traditional",
      "!",
    ];
    for (const [list, { family, lines }] of sorted([...prefixLists], ([k]) => k)) {
      lines.forEach((line, i) => frr.push(`${family === 6 ? "ipv6" : "ip"} prefix-list ${list} seq ${(i + 1) * 5} ${line}`));
      frr.push("!");
    }
    for (const [list, patterns] of sorted([...asPaths], ([k]) => k)) {
      patterns.forEach((p, i) => frr.push(`bgp as-path access-list ${list} seq ${(i + 1) * 5} permit ${p}`));
    }
    frr.push("!", ...routeMaps, "!");
    frr.push(`router bgp ${local.asn}`, ` bgp router-id ${local.routerId}`, " no bgp default ipv4-unicast", " bgp ebgp-requires-policy");
    const ordered = sorted(neighbors, n => n.address);
    for (const n of ordered) {
      frr.push(` neighbor ${n.address} remote-as ${n.asn}`, ` neighbor ${n.address} description ${n.description}`);
      if (n.source) frr.push(` neighbor ${n.address} update-source ${n.source}`);
      if (n.bfd) frr.push(` neighbor ${n.address} bfd`);
    }
    const advertised = (local.advertiseSubnetIds ?? []).map(subnetCidr).sort(compareNetworkText);
    for (const family of [4, 6] as const) {
      const ns = ordered.filter(n => n.family === family);
      if (!ns.length) continue;
      frr.push(" !", ` address-family ${family === 6 ? "ipv6" : "ipv4"} unicast`);
      for (const cidr of advertised.filter(c => familyOf(c) === family)) frr.push(`  network ${cidr}`);
      if (clusters.some(c => isIP(c.address!) === family)) frr.push("  maximum-paths 8");
      for (const n of ns) {
        const cluster = n.description.startsWith("cluster ");
        frr.push(`  neighbor ${n.address} activate`, `  neighbor ${n.address} route-map ${n.routeMapIn} in`,
          `  neighbor ${n.address} route-map ${cluster ? "RM-DENY-ALL" : `RM-OUT-V${family}`} out`);
      }
      frr.push(" exit-address-family");
    }
    frr.push("exit", "");
    const listenPorts = [...new Set(wireguard.map(w => w.listenPort))].sort((x, y) => x - y);
    const body = { routerId: local.id, nodeId: local.nodeId, siteId: siteOf(local), asn: local.asn, wireguard: sorted(wireguard, w => w.interfaceName), fallbackRoutes: sorted(fallbackRoutes, r => r.destination + r.interfaceId), listenPorts, frr: frr.join("\n") };
    gateways.push({ ...body, hash: networkDigest(body) });
  }

  const preconditions = [
    "underlay: each peer endpoint must stay reachable through the underlay, never through a fabric tunnel; pin endpoint host routes if the default route can move",
    "kernel: net.ipv4.ip_forward=1, and rp_filter loose (2) or off on fabric interfaces so a backup path cannot drop return traffic",
    "firewall: accept UDP on each gateway's listenPorts from its peers' endpoints, and TCP 179 on fabric interfaces",
    "routing: FRR zebra must install BGP routes into the main table; no other writer may claim the same destinations",
  ];
  if (fabric.transports.some(t => !native(t))) preconditions.push("external transport: verify how its existing routes are installed (table and metric); a metric-0 route to a remote block beats every BGP route");
  if (resources.some(r => r.kind === "bgp-router" && r.role === "cluster")) preconditions.push("cluster speakers: their BGP configuration (peer address, ASN, advertisements) is owned by the cluster and must match this plan");
  const body = {
    schemaVersion: 1 as const, kind: "bgp-fabric-plan" as const, mode: "dry-run" as const, executable: false as const,
    registryRevision: registry.revision, fabricId: fabric.id,
    sessions: sorted(sessions, s => s.routers.join(" ") + s.transportNetworkId), gateways, preconditions, warnings: warnings.sort(),
  };
  return { ok: true, plan: { ...body, hash: networkDigest(body) }, diagnostics: [] };
}

export interface FabricGatewayChange {
  routerId: string;
  change: "added" | "removed" | "changed" | "unchanged";
  /** Which parts differ; empty unless `changed`. */
  parts: Array<"wireguard" | "frr" | "fallbackRoutes" | "listenPorts">;
}
/** Per-gateway difference between two plans of the same fabric. */
export function diffBgpFabricPlans(before: BgpFabricPlan | null, after: BgpFabricPlan): FabricGatewayChange[] {
  const old = new Map((before?.gateways ?? []).map(g => [g.routerId, g]));
  const changes: FabricGatewayChange[] = [];
  for (const g of after.gateways) {
    const prev = old.get(g.routerId);
    old.delete(g.routerId);
    if (!prev) { changes.push({ routerId: g.routerId, change: "added", parts: [] }); continue; }
    const parts = (["wireguard", "frr", "fallbackRoutes", "listenPorts"] as const).filter(p => networkDigest(prev[p]) !== networkDigest(g[p]));
    changes.push({ routerId: g.routerId, change: parts.length ? "changed" : "unchanged", parts: [...parts] });
  }
  for (const id of old.keys()) changes.push({ routerId: id, change: "removed", parts: [] });
  return sorted(changes, c => c.routerId);
}

export type { InventoryBgpFabric };
