import { compareNetworkText } from "./network-canonical.ts";
/** Pure conservative FRR template compiler. Never invokes FRR or mutates an interface. */
import { normalizePrefixPolicy, validatePrefixPolicy, permittedPrefix, type NetworkPrefixPolicy } from './network-prefix-policy.ts';
import { isIP } from 'node:net';
import { cidrRange } from './nft.ts';
import { networkDigest } from './network-canonical.ts';
import { validateNetworkInventory } from './network-inventory.ts';
import type { NetworkRegistryDocument } from './network-registry.ts';
export interface FrrPeerSpec {
    nodeId: string;
    siteId: string;
    networkId: string;
    interfaceId: string;
    remoteAsn: number;
    address: string;
    updateSource: string;
    addressFamily: 'ipv4' | 'ipv6';
    backbone: 'primary' | 'secondary';
    importSubnetIds: string[];
    reachabilityRouteId: string;
    bfd?: boolean;
}
export interface FrrSpec {
    schemaVersion: 1;
    frrVersion: '8.5.6' | '10.2.1';
    nodeId: string;
    siteId: string;
    routerId: string;
    localAsn: number;
    exportSubnetIds: string[];
    peers: FrrPeerSpec[];
}
export interface FrrCompilation {
    schemaVersion: 1;
    kind: 'frr-compilation';
    mode: 'dry-run';
    executable: false;
    registryRevision: number;
    inputDigest: string;
    nodeId: string;
    frrVersion: string;
    template: string;
    hash: string;
    preconditions: string[];
    changedInterfaceIds: [];
}
const obj = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const keys = (x: Record<string, unknown>, k: string[]) => Object.keys(x).every(v => k.includes(v));
const id = (x: unknown): x is string => typeof x === 'string' && /^[A-Za-z0-9_.:-]{1,256}$/.test(x);
const ids = (x: unknown): x is string[] => Array.isArray(x) && x.length <= 128 && x.every(id) && new Set(x).size === x.length;
const asn = (x: unknown) => Number.isSafeInteger(x) && ((Number(x) >= 64512 && Number(x) <= 65534) || (Number(x) >= 4200000000 && Number(x) <= 4294967294));
const overlap = (a: string, b: string) => { const x = cidrRange(a), y = cidrRange(b); return !!x && !!y && x.family === y.family && x.first <= y.last && y.first <= x.last; };
const contains = (a: string, b: string) => { const x = cidrRange(a), y = cidrRange(b); return !!x && !!y && x.family === y.family && x.first <= y.first && x.last >= y.last; };
function addressIdentity(address: string): string | null {
    const range = cidrRange(address);
    return range ? `${range.family}:${range.first}` : null;
}
// Scoped link-local sessions require interface zone handling that this compiler does not support.
function unicast(address: string) {
    if (isIP(address) === 4) {
        const [a, b] = address.split('.').map(Number);
        return a !== 0 && a !== 127 && a! < 224 && !(a === 169 && b === 254);
    }
    if (isIP(address) === 6) {
        const r = cidrRange(address);
        if (!r || r.first <= 1n)
            return false;
        return (r.first >> 120n) !== 255n && (r.first >> 118n) !== 1018n;
    }
    return false;
}
export function compileFrr(input: {
    registry: Pick<NetworkRegistryDocument, 'revision' | 'resources'>;
    expectedRegistryRevision: number;
    spec: unknown;
    prefixPolicy?: NetworkPrefixPolicy;
}): {
    ok: true;
    artifact: FrrCompilation;
    diagnostics: [];
} | {
    ok: false;
    diagnostics: string[];
} {
    const errors: string[] = [];
    const bad = (x: string) => errors.push(x);
    const { registry } = input;
    if (!Number.isSafeInteger(input.expectedRegistryRevision) || input.expectedRegistryRevision < 0 || registry.revision !== input.expectedRegistryRevision)
        bad('registry revision mismatch');
    for (const e of validateNetworkInventory(registry.resources))
        bad(`inventory ${e.resourceId}: ${e.message}`);
    if(input.prefixPolicy!==undefined) { const policyErrors=validatePrefixPolicy(registry.resources,input.prefixPolicy); if(policyErrors.length) return {ok:false,diagnostics:[...errors,...policyErrors].sort()}; }
    const s = input.spec;
    if (!obj(s) || !keys(s, ['schemaVersion', 'frrVersion', 'nodeId', 'siteId', 'routerId', 'localAsn', 'exportSubnetIds', 'peers']) || s.schemaVersion !== 1 || !['8.5.6', '10.2.1'].includes(String(s.frrVersion)) || !id(s.nodeId) || !id(s.siteId) || typeof s.routerId !== 'string' || isIP(s.routerId) !== 4 || !asn(s.localAsn) || !ids(s.exportSubnetIds) || !Array.isArray(s.peers) || s.peers.length < 2 || s.peers.length > 128)
        return {
            ok: false, diagnostics: [...errors, 'invalid FRR spec']
        };
    const spec = s as unknown as FrrSpec;
    const rs = new Map(registry.resources.map(r => [r.id, r]));
    const local = rs.get(spec.nodeId);
    if (local?.kind !== 'node' || local.siteId !== spec.siteId || local.management.mode !== 'managed' || !['native', 'wireguard'].includes(local.management.provider) || !registry.resources.some(r => r.kind === 'gateway' && r.nodeId === spec.nodeId && r.management.mode === 'managed' && ['native', 'wireguard'].includes(r.management.provider)))
        bad('local node requires native managed gateway at explicit site');
    if (/^(0|127)\./.test(spec.routerId) || Number(spec.routerId.split('.')[0]) >= 224)
        bad('invalid unicast router id');
    const forbidden = registry.resources.flatMap(r => {
        if (r.kind === 'address-pool' && ['management', 'kubernetes-pod', 'kubernetes-service'].includes(r.purpose ?? ''))
            return [r.cidr];
        if (r.kind === 'subnet') {
            const n = rs.get(r.networkId);
            if (n?.kind === 'network' && ['management', 'kubernetes'].includes(n.purpose ?? ''))
                return [r.cidr];
        }
        return [];
    });
    function prefixes(refs: string[], site: string, family?: string) {
        return refs.flatMap(ref => {
            const r = rs.get(ref);
            if (input.prefixPolicy) {
                if(r?.kind!=='subnet' && r?.kind!=='address-pool') {bad(`prefix must reference subnet or pool: ${ref}`);return [];}
                const subnet=r.kind==='subnet'?r:rs.get(r.subnetId);
                const net=subnet?.kind==='subnet'?rs.get(subnet.networkId):undefined;
                const candidates=input.prefixPolicy.permissions.filter(p=>p.resourceId===ref&&p.siteId===site);
                if(!candidates.length || net?.kind!=='network') {bad(`prefix lacks explicit policy permission: ${ref}`);return [];}
                return candidates.flatMap(p=>{
                    if(family && cidrRange(p.prefix)?.family!==family) {bad(`unsafe or mismatched prefix: ${ref}`);return [];}
                    if(site===spec.siteId && !permittedPrefix(input.prefixPolicy!,site,p.prefix,{nodeId:spec.nodeId,provider:'native',driver:'frr'})) bad(`prefix advertisement owner mismatch: ${ref}`);
                    return [p.prefix];
                }).sort();
            }
            if (r?.kind !== 'subnet') {
                bad(`prefix must reference subnet: ${ref}`);
                return [];
            }
            const n = rs.get(r.networkId);
            if (n?.kind !== 'network' || n.scope !== 'site-local' || n.siteId !== site || n.purpose !== 'infrastructure')
                bad(`only local explicit infrastructure prefixes supported: ${ref}`);
            const range = cidrRange(r.cidr);
            if (!range || range.bits === 0 || (family && range.family !== family) || forbidden.some(p => overlap(p, r.cidr)))
                bad(`unsafe or mismatched prefix: ${ref}`);
            return [r.cidr];
        }).sort();
    }
    const exports = prefixes(spec.exportSubnetIds, spec.siteId);
    const peers: FrrPeerSpec[] = [];
    const routingDomains = new Set<string>();
    const seen = new Set<string>();
    const nodeAsns = new Map<string, number>();
    const asnNodes = new Map<number, string>();
    for (const v of spec.peers) {
        if (!obj(v) || !keys(v, ['nodeId', 'siteId', 'networkId', 'interfaceId', 'remoteAsn', 'address', 'updateSource', 'addressFamily', 'backbone', 'importSubnetIds', 'reachabilityRouteId', 'bfd']) || !['nodeId', 'siteId', 'networkId', 'interfaceId', 'reachabilityRouteId'].every(k => id(v[k])) || !asn(v.remoteAsn) || !['ipv4', 'ipv6'].includes(String(v.addressFamily)) || !['primary', 'secondary'].includes(String(v.backbone)) || typeof v.address !== 'string' || typeof v.updateSource !== 'string' || !ids(v.importSubnetIds) || (v.bfd !== undefined && typeof v.bfd !== 'boolean')) {
            bad('invalid FRR peer schema');
            continue;
        }
        const p = v as unknown as FrrPeerSpec;
        peers.push(p);
        const family = p.addressFamily === 'ipv4' ? 'ip' : 'ip6';
        if (!unicast(p.address) || !unicast(p.updateSource))
            bad('peer and source require unicast scoped addresses');
        if (isIP(p.address) !== (family === 'ip' ? 4 : 6) || isIP(p.updateSource) !== (family === 'ip' ? 4 : 6) || addressIdentity(p.address) === addressIdentity(p.updateSource) || p.nodeId === spec.nodeId || p.siteId === spec.siteId || p.remoteAsn === spec.localAsn)
            bad('self peer or address family conflict');
        if (seen.has(addressIdentity(p.address) ?? p.address))
            bad('duplicate peer address');
        seen.add(addressIdentity(p.address) ?? p.address);
        if (nodeAsns.has(p.nodeId) && nodeAsns.get(p.nodeId) !== p.remoteAsn)
            bad('peer ASN conflict');
        nodeAsns.set(p.nodeId, p.remoteAsn);
        if (asnNodes.has(p.remoteAsn) && asnNodes.get(p.remoteAsn) !== p.nodeId)
            bad('ASN owned by multiple nodes');
        asnNodes.set(p.remoteAsn, p.nodeId);
        const node = rs.get(p.nodeId), net = rs.get(p.networkId), iface = rs.get(p.interfaceId), route = rs.get(p.reachabilityRouteId);
        if (node?.kind !== 'node' || node.siteId !== p.siteId || net?.kind !== 'network' || net.purpose !== 'backbone' || !['overlay', 'transit'].includes(net.scope ?? '') || !('siteIds' in net) || !net.siteIds.includes(spec.siteId) || !net.siteIds.includes(p.siteId))
            bad('peer requires explicit remote node and shared backbone');
        if (iface?.kind !== 'interface' || iface.nodeId !== spec.nodeId || iface.networkId !== p.networkId || !/^[-a-zA-Z0-9_.]{1,15}$/.test(iface.name))
            bad('peer interface reference mismatch');
        else if (p.backbone === 'primary' ? (iface.management.mode !== 'managed' || !['native', 'wireguard'].includes(iface.management.provider)) : (iface.management.mode !== 'external' || iface.management.provider !== 'cloudflare'))
            bad('backbone ownership mismatch');
        if(net?.kind==='network' && net.routingDomainId) routingDomains.add(net.routingDomainId);
        const domain = net?.kind === 'network' && net.routingDomainId ? rs.get(net.routingDomainId) : undefined;
        if (domain?.kind !== 'routing-domain' || domain.isolation !== 'global')
            bad('only explicit global routing domain supported');
        if (route?.kind !== 'route' || route.interfaceId !== p.interfaceId || route.table !== 254 || route.routingDomainId !== (net?.kind === 'network' ? net.routingDomainId : undefined) || !contains(route.destination, p.address))
            bad('peer lacks explicit reachability route');
        if (!registry.resources.some(r => r.kind === 'subnet' && r.networkId === p.networkId && contains(r.cidr, p.updateSource)))
            bad('update source lacks backbone subnet');
        prefixes(p.importSubnetIds, p.siteId, family);
    }
    for (const n of new Set(peers.map(p => p.nodeId + '|' + p.addressFamily)))
        if (!peers.some(p => p.nodeId + '|' + p.addressFamily === n && p.backbone === 'primary') || !peers.some(p => p.nodeId + '|' + p.addressFamily === n && p.backbone === 'secondary'))
            bad('each remote node requires both backbones');
    for(const ref of spec.exportSubnetIds) {
        const r=rs.get(ref); const sub=r?.kind==='subnet'?r:r?.kind==='address-pool'?rs.get(r.subnetId):undefined;
        const net=sub?.kind==='subnet'?rs.get(sub.networkId):undefined;
        if(net?.kind==='network' && net.routingDomainId) routingDomains.add(net.routingDomainId);
    }
    if(routingDomains.size!==1) bad('FRR configuration requires one consistent routing domain; multi-domain writers are unsupported');
    if (errors.length)
        return {
            ok: false, diagnostics: [...new Set(errors)].sort()
        };
    peers.sort((a, b) => compareNetworkText(a.address, b.address));
    const lines = ['! INCOMPLETE DRY-RUN TEMPLATE. Not authorized for execution.'];
    peers.forEach((p, i) => {
        const family = p.addressFamily === 'ipv4' ? 'ip' : 'ip6', cmd = family === 'ip' ? 'ip' : 'ipv6', ins = prefixes(p.importSubnetIds, p.siteId, family), outs = exports.filter(x => cidrRange(x)!.family === family);
        for (const [suffix, ps] of [['IN', ins], ['OUT', outs]] as const) {
            ps.forEach((prefix, j) => lines.push(`${cmd} prefix-list HP${i}${suffix} seq ${(j + 1) * 10} permit ${prefix}`));
            lines.push(`${cmd} prefix-list HP${i}${suffix} seq 65535 deny ${family === 'ip' ? '0.0.0.0/0 le 32' : '::/0 le 128'}`, `route-map HP${i}${suffix} permit 10`, ` match ${cmd} address prefix-list HP${i}${suffix}`);
            if (suffix === 'IN')
                lines.push(` set local-preference ${p.backbone === 'primary' ? 200 : 100}`);
            else
                lines.push(' match as-path HPLOCAL');
            lines.push(`route-map HP${i}${suffix} deny 65535`);
        }
    });
    lines.push('bgp as-path access-list HPLOCAL permit ^$', `router bgp ${spec.localAsn}`, ` bgp router-id ${spec.routerId}`, ' no bgp default ipv4-unicast', ' bgp ebgp-requires-policy', ' bgp network import-check');
    peers.forEach(p => lines.push(` neighbor ${p.address} remote-as ${p.remoteAsn}`, ` neighbor ${p.address} update-source ${p.updateSource}`, ` neighbor ${p.address} ebgp-multihop 2`, ...(p.bfd ? [` neighbor ${p.address} bfd`] : [])));
    for (const family of ['ipv4', 'ipv6'] as const) {
        const selected = peers.filter(p => p.addressFamily === family);
        if (!selected.length)
            continue;
        lines.push(` address-family ${family} unicast`);
        exports.filter(x => cidrRange(x)!.family === (family === 'ipv4' ? 'ip' : 'ip6')).forEach(x => lines.push(`  network ${x}`));
        selected.forEach(p => { const i = peers.indexOf(p); lines.push(`  neighbor ${p.address} activate`, `  neighbor ${p.address} route-map HP${i}IN in`, `  neighbor ${p.address} route-map HP${i}OUT out`); });
        lines.push(' exit-address-family');
    }
    const body = {
        schemaVersion: 1 as const, kind: 'frr-compilation' as const, mode: 'dry-run' as const, executable: false as const, registryRevision: registry.revision, inputDigest: networkDigest({
            ...(input.prefixPolicy?{prefixPolicy:normalizePrefixPolicy(input.prefixPolicy)}:{}), resources: [...registry.resources].sort((a, b) => compareNetworkText(a.id, b.id)), spec: {
                ...spec, exportSubnetIds: [...spec.exportSubnetIds].sort(), peers: peers.map(p => ({
                    ...p, importSubnetIds: [...p.importSubnetIds].sort()
                }))
            }
        }), nodeId: spec.nodeId, frrVersion: spec.frrVersion, template: lines.join('\n') + '\n', changedInterfaceIds: [] as [
        ], preconditions: ['Declared reachability is not independent connectivity evidence. Verify source binding, TCP/179 and hop limits independently.', 'Verify local origin routes in RIB and independently authenticate every prefix reachability and exposure reference.', 'BFD is optional syntax only; no session, forwarding or failover proof exists.', 'No approval, persistence, execution or rollback is provided.']
    };
    return {
        ok: true, artifact: {
            ...body, hash: networkDigest(body)
        }, diagnostics: []
    };
}
