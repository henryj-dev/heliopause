import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileFrr, type FrrSpec } from './network-frr.ts';
import type { NetworkInventoryResource } from './network-inventory.ts';
const v6 = (index: number, host: number) => ['fd20', index, '', host].join(':');
function fixture() {
    const b = {
        owner: 'ops', generation: 1, management: {
            mode: 'managed', provider: 'native', driver: 'frr'
        } as const
    };
    const resources: NetworkInventoryResource[] = [{
            ...b, id: 'rd', kind: 'routing-domain', name: 'global', isolation: 'global'
        }];
    for (let i = 0; i < 2; i++)
        resources.push({
            ...b, id: `s${i}`, kind: 'site'
        }, {
            ...b, id: `n${i}`, kind: 'node', siteId: `s${i}`
        }, {
            ...b, id: `g${i}`, kind: 'gateway', nodeId: `n${i}`
        }, {
            ...b, id: `lan${i}`, kind: 'network', scope: 'site-local', siteId: `s${i}`, routingDomainId: 'rd', purpose: 'infrastructure'
        }, {
            ...b, id: `sub${i}`, kind: 'subnet', networkId: `lan${i}`, cidr: `10.${i + 30}.0.0/24`
        }, {
            ...b, id: `sub6${i}`, kind: 'subnet', networkId: `lan${i}`, cidr: `fd30:${i}::/64`
        });
    const peers: FrrSpec['peers'] = [];
    for (const [i, backbone] of ['primary', 'secondary'].entries()) {
        resources.push({
            ...b, id: `bb${i}`, kind: 'network', scope: 'overlay', siteIds: ['s0', 's1'], routingDomainId: 'rd', purpose: 'backbone'
        }, {
            ...b, id: `tun${i}`, kind: 'subnet', networkId: `bb${i}`, cidr: `10.20.${i}.0/24`
        }, {
            ...b, id: `tun6${i}`, kind: 'subnet', networkId: `bb${i}`, cidr: `fd20:${i}::/64`
        }, {
            ...b, id: `if${i}`, kind: 'interface', nodeId: 'n0', networkId: `bb${i}`, name: `wg${i}`, management: i === 0 ? b.management : {
                mode: 'external', provider: 'cloudflare'
            }
        }, {
            ...b, id: `route${i}`, kind: 'route', interfaceId: `if${i}`, destination: `10.20.${i}.2/32`, table: 254, routingDomainId: 'rd'
        }, {
            ...b, id: `route6${i}`, kind: 'route', interfaceId: `if${i}`, destination: [v6(i, 2), '128'].join('/'), table: 254, routingDomainId: 'rd'
        });
        for (const af of ['ipv4', 'ipv6'] as const)
            peers.push({
                nodeId: 'n1', siteId: 's1', networkId: `bb${i}`, interfaceId: `if${i}`, remoteAsn: 4200000002, addressFamily: af, address: af === 'ipv4' ? `10.20.${i}.2` : v6(i, 2), updateSource: af === 'ipv4' ? `10.20.${i}.1` : v6(i, 1), backbone: backbone as 'primary' | 'secondary', importSubnetIds: [af === 'ipv4' ? 'sub1' : 'sub61'], reachabilityRouteId: af === 'ipv4' ? `route${i}` : `route6${i}`
            });
    }
    return {
        registry: {
            revision: 3, resources
        }, expectedRegistryRevision: 3, spec: {
            schemaVersion: 1, frrVersion: '10.2.1', nodeId: 'n0', siteId: 's0', routerId: '10.20.0.1', localAsn: 4200000001, exportSubnetIds: ['sub0', 'sub60'], peers
        } as FrrSpec
    };
}
test('dual backbone dry-run has exact IPv4/IPv6 policy and own-origin export only', () => {
    const r = compileFrr(fixture());
    assert.equal(r.ok, true, JSON.stringify(r));
    if (!r.ok)
        return;
    assert.equal(r.artifact.executable, false);
    assert.deepEqual(r.artifact.changedInterfaceIds, []);
    assert.match(r.artifact.template, /set local-preference 200/);
    assert.match(r.artifact.template, /set local-preference 100/);
    assert.match(r.artifact.template, /ipv6 prefix-list/);
    assert.match(r.artifact.template, /address-family ipv6 unicast/);
    assert.match(r.artifact.template, /match as-path HPLOCAL/);
    assert.match(r.artifact.template, /HPLOCAL permit \^\$/);
    assert.doesNotMatch(r.artifact.template, /redistribute|interface wg|neighbor .* bfd/);
});
test('stable artifact under input reordering and supported versions', () => { const f = fixture(), a = compileFrr(f); f.spec.peers.reverse(); f.spec.exportSubnetIds.reverse(); f.registry.resources.reverse(); assert.deepEqual(compileFrr(f), a); f.spec.frrVersion = '8.5.6'; assert.equal(compileFrr(f).ok, true); });
for (const [name, change] of [
    ['revision', (f: ReturnType<typeof fixture>) => { f.expectedRegistryRevision = 2; }],
    ['ASN', (f: ReturnType<typeof fixture>) => { f.spec.localAsn = 23456; }],
    ['version', (f: ReturnType<typeof fixture>) => { Object.assign(f.spec, {
            frrVersion: 'latest'
        }); }],
    ['self peer', (f: ReturnType<typeof fixture>) => { f.spec.peers[0]!.nodeId = 'n0'; }],
    ['duplicate', (f: ReturnType<typeof fixture>) => { f.spec.peers.push(f.spec.peers[0]!); }],
    ['raw authority', (f: ReturnType<typeof fixture>) => { Object.assign(f.spec, {
            approved: true
        }); }],
    ['service', (f: ReturnType<typeof fixture>) => {
            const n = f.registry.resources.find(r => r.id === 'lan0');
            if (n?.kind === 'network' && n.scope === 'site-local')
                n.purpose = 'kubernetes';
        }],
    ['management aggregate', (f: ReturnType<typeof fixture>) => { f.registry.resources.push({
            owner: 'ops', generation: 1, management: {
                mode: 'external', provider: 'operator'
            }, id: 'management', kind: 'address-pool', subnetId: 'sub0', cidr: '10.30.0.8/32', purpose: 'management', allocationAuthority: 'operator'
        }); }],
    ['route', (f: ReturnType<typeof fixture>) => { f.spec.peers[0]!.reachabilityRouteId = 'absent'; }],
    ['ownership', (f: ReturnType<typeof fixture>) => { f.registry.resources.find(r => r.id === 'if1')!.management = {
            mode: 'managed', provider: 'native', driver: 'frr'
        }; }],
    ['family', (f: ReturnType<typeof fixture>) => { f.spec.peers[0]!.addressFamily = 'ipv6'; }],
    ['one backbone', (f: ReturnType<typeof fixture>) => { f.spec.peers = f.spec.peers.filter(p => p.backbone === 'primary'); }],
] as const)
    test(`reject ${name}`, () => { const f = fixture(); change(f); assert.equal(compileFrr(f).ok, false); });
for (const address of ['0.0.0.0', '127.0.0.1', '169.254.1.1', '::', '::1', 'fe80::1', 'ff02::1']) {
    test(`reject unscoped or non-unicast peer ${address}`, () => {
        const f = fixture();
        f.spec.peers[0]!.address = address;
        assert.equal(compileFrr(f).ok, false);
    });
}
test('same revision with different resource generation changes content binding', () => {
    const f = fixture();
    const a = compileFrr(f);
    f.registry.resources[0]!.generation++;
    const b = compileFrr(f);
    assert.equal(a.ok && b.ok, true);
    if (a.ok && b.ok) assert.notEqual(a.artifact.inputDigest, b.artifact.inputDigest);
});
test('equivalent IPv6 spellings cannot impersonate two backbone neighbors', () => {
    const f = fixture();
    const secondary = f.spec.peers.find(p => p.backbone === 'secondary' && p.addressFamily === 'ipv6')!;
    secondary.address = ['fd20', '0', '0', '0', '0', '0', '0', '2'].join(':');
    const route0 = f.registry.resources.find(r => r.id === 'route60');
    const route1 = f.registry.resources.find(r => r.id === 'route61');
    if (route0?.kind === 'route') route0.destination = ['fd20', '', '/64'].join(':');
    if (route1?.kind === 'route') route1.destination = [v6(0, 2), '128'].join('/');
    const r = compileFrr(f);
    assert.equal(r.ok, false);
    if (!r.ok) assert.ok(r.diagnostics.includes('duplicate peer address'));
});
test('equivalent IPv6 source and neighbor spellings are self peers', () => {
    const f = fixture();
    const peer = f.spec.peers.find(p => p.addressFamily === 'ipv6')!;
    peer.updateSource = ['fd20', '0', '0', '0', '0', '0', '0', '2'].join(':');
    const r = compileFrr(f);
    assert.equal(r.ok, false);
    if (!r.ok) assert.ok(r.diagnostics.includes('self peer or address family conflict'));
});
