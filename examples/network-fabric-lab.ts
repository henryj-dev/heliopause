/** Synthetic four-site BGP fabric for the isolated namespace lab. No operational addresses or keys.
 * Site i owns 10.(40+i).0.0/16; the native backbone uses 10.90.0.0/24 and the simulated external
 * backbone 10.91.0.0/24. Underlay endpoints are documentation addresses 203.0.113.(i+1). */
import type { NetworkInventoryResource } from "../src/network-inventory.ts";

export const FABRIC_LAB_SITES = 4;
/** In-site cluster speaker (stands in for Cilium) lives at this site's client namespace. */
export const FABRIC_LAB_CLUSTER_SITE = 1;
export const fabricLabBlock = (i: number) => `10.${40 + i}.0.0/16`;
export const fabricLabGatewayLan = (i: number) => `10.${40 + i}.0.1`;
export const fabricLabClientLan = (i: number) => `10.${40 + i}.0.2`;
export const fabricLabNativeAddress = (i: number) => `10.90.0.${i + 1}`;
export const fabricLabExternalAddress = (i: number) => `10.91.0.${i + 1}`;
export const fabricLabEndpoint = (i: number) => `203.0.113.${i + 1}`;
/** Load-balancer VIP the cluster speaker announces as a host route. */
export const fabricLabVip = (i: number) => `10.${40 + i}.127.10`;
/** Placeholder public keys; the lab replaces them with freshly generated ones. */
export const fabricLabPlaceholderKey = (i: number) => Buffer.alloc(32, i + 1).toString("base64");

export function fabricLabInventory(): NetworkInventoryResource[] {
  const base = { owner: "lab", generation: 1 } as const;
  const ext = (provider: string) => ({ mode: "external", provider } as const);
  const managed = (provider: string, driver: string) => ({ mode: "managed", provider, driver } as const);
  const sites = Array.from({ length: FABRIC_LAB_SITES }, (_, i) => i);
  const r: NetworkInventoryResource[] = [
    { ...base, management: ext("lab"), id: "rd", kind: "routing-domain", name: "lab", isolation: "global" },
    { ...base, management: managed("wireguard", "wireguard"), id: "native", kind: "network", scope: "overlay", siteIds: sites.map(i => `s${i}`), routingDomainId: "rd", purpose: "backbone" },
    { ...base, management: managed("wireguard", "wireguard"), id: "native-sub", kind: "subnet", networkId: "native", cidr: "10.90.0.0/24" },
    { ...base, management: managed("wireguard", "wireguard"), id: "native-pool", kind: "address-pool", subnetId: "native-sub", cidr: "10.90.0.0/24", allocationAuthority: "heliopause", purpose: "tunnel" },
    { ...base, management: ext("external-mesh"), id: "external", kind: "network", scope: "overlay", siteIds: sites.map(i => `s${i}`), routingDomainId: "rd", purpose: "backbone" },
    { ...base, management: ext("external-mesh"), id: "external-sub", kind: "subnet", networkId: "external", cidr: "10.91.0.0/24" },
    { ...base, management: ext("external-mesh"), id: "external-pool", kind: "address-pool", subnetId: "external-sub", cidr: "10.91.0.0/24", allocationAuthority: "external-mesh", purpose: "tunnel" },
    { ...base, management: ext("lab"), id: "mgmt-rd", kind: "routing-domain", name: "management", isolation: "external" },
    { ...base, management: ext("lab"), id: "mgmt", kind: "network", scope: "transit", siteIds: ["s0"], routingDomainId: "mgmt-rd", purpose: "management" },
    { ...base, management: ext("lab"), id: "mgmt-sub", kind: "subnet", networkId: "mgmt", cidr: "10.95.0.0/16" },
    { ...base, management: managed("frr", "frr"), id: "fabric", kind: "bgp-fabric", topology: "full-mesh", transports: [
      { networkId: "native", preference: "primary", mode: "bgp", listenPortBase: 51800, persistentKeepalive: 5, mtu: 1420 },
      { networkId: "external", preference: "secondary", mode: "bgp" },
    ] },
  ];
  for (const i of sites) {
    const o = 40 + i;
    const cluster = i === FABRIC_LAB_CLUSTER_SITE;
    r.push(
      { ...base, management: ext("lab"), id: `s${i}`, kind: "site" },
      { ...base, management: ext("lab"), id: `n${i}`, kind: "node", siteId: `s${i}` },
      { ...base, management: ext("lab"), id: `g${i}`, kind: "gateway", nodeId: `n${i}` },
      { ...base, management: ext("lab"), id: `vpc${i}`, kind: "network", scope: "site-local", siteId: `s${i}`, routingDomainId: "rd", purpose: "infrastructure" },
      { ...base, management: ext("lab"), id: `blk${i}`, kind: "subnet", networkId: `vpc${i}`, cidr: `10.${o}.0.0/16` },
      { ...base, management: ext("lab"), id: `infra${i}`, kind: "subnet", networkId: `vpc${i}`, cidr: `10.${o}.0.0/17`, parentSubnetId: `blk${i}` },
      { ...base, management: ext("lab"), id: `lan${i}`, kind: "subnet", networkId: `vpc${i}`, cidr: `10.${o}.0.0/24`, parentSubnetId: `infra${i}` },
      { ...base, management: ext("lab"), id: `k8s${i}`, kind: "subnet", networkId: `vpc${i}`, cidr: `10.${o}.128.0/17`, parentSubnetId: `blk${i}` },
      { ...base, management: ext("lab"), id: `pod${i}`, kind: "address-pool", subnetId: `k8s${i}`, cidr: `10.${o}.128.0/18`, allocationAuthority: "kubernetes", purpose: "kubernetes-pod" },
      { ...base, management: ext("lab"), id: `svc${i}`, kind: "address-pool", subnetId: `k8s${i}`, cidr: `10.${o}.192.0/18`, allocationAuthority: "kubernetes", purpose: "kubernetes-service" },
      { ...base, management: ext("lab"), id: `lb${i}`, kind: "address-pool", subnetId: `infra${i}`, cidr: `10.${o}.127.0/24`, allocationAuthority: "cilium", purpose: "kubernetes-loadbalancer" },
      { ...base, management: managed("frr", "frr"), id: `r${i}`, kind: "bgp-router", nodeId: `n${i}`, role: "gateway", asn: 65001 + i, routerId: fabricLabGatewayLan(i),
        originSubnetIds: [`blk${i}`], advertiseSubnetIds: [`blk${i}`], fabricIndex: i + 1, ...(cluster ? { address: fabricLabGatewayLan(i) } : {}) },
      { ...base, management: managed("heliopause", "ipam"), id: `nip${i}`, kind: "address-allocation", poolId: "native-pool", address: fabricLabNativeAddress(i), state: "allocated", consumerId: `natt${i}` },
      { ...base, management: managed("wireguard", "wireguard"), id: `natt${i}`, kind: "fabric-attachment", fabricId: "fabric", routerId: `r${i}`, networkId: "native",
        tunnelAllocationId: `nip${i}`, endpoint: fabricLabEndpoint(i), publicKey: fabricLabPlaceholderKey(i), privateKeyRef: { provider: "ephemeral-lab", reference: `native-${i}` } },
      { ...base, management: ext("external-mesh"), id: `xif${i}`, kind: "interface", nodeId: `n${i}`, networkId: "external", name: "cf0" },
      { ...base, management: ext("external-mesh"), id: `xip${i}`, kind: "address-allocation", poolId: "external-pool", address: fabricLabExternalAddress(i), state: "allocated" },
      { ...base, management: ext("external-mesh"), id: `xatt${i}`, kind: "fabric-attachment", fabricId: "fabric", routerId: `r${i}`, networkId: "external", tunnelAllocationId: `xip${i}`, interfaceId: `xif${i}` },
    );
    if (cluster) r.push({ ...base, management: ext("cilium"), id: `c${i}`, kind: "bgp-router", nodeId: `n${i}`, role: "cluster", asn: 65100, routerId: fabricLabClientLan(i), address: fabricLabClientLan(i) });
  }
  return r;
}
