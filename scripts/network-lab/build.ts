import {writeFileSync} from 'node:fs';
import {networkLabInput,labPrefixEvidence} from '../../examples/network-lab.ts';
import {buildNetworkChangeSet} from '../../src/network-change-set.ts';
import {compileWireGuard} from '../../src/network-wireguard.ts';
import {compileFrr} from '../../src/network-frr.ts';
const input=networkLabInput();
for(let i=0;i<4;i++) {
  input.prefixPolicy!.permissions.push({id:`pods-grant-${i}`,resourceId:`pods${i}`,siteId:`s${i}`,prefix:`192.0.2.${i*64+32}/28`,role:'pod',owner:{nodeId:`n${i}`,provider:'native',driver:'frr'},evidence:labPrefixEvidence(input,i)},
  {id:`vip-grant-${i}`,resourceId:`services${i}`,siteId:`s${i}`,prefix:`192.0.2.${i*64+50}/32`,role:'service-vip',owner:{nodeId:`n${i}`,provider:'native',driver:'frr'},evidence:labPrefixEvidence(input,i),service:{cluster:'synthetic',namespace:'lab',name:`echo-${i}`,uid:`uid-${i}`,ready:true,exposureRef:'synthetic-lab-exposure',advertisement:'originate'}});
  input.wireguard.gateways[i]!.allowedPrefixes.push(`192.0.2.${i*64+32}/28`,`192.0.2.${i*64+50}/32`);
  input.frr[i]!.exportSubnetIds.push(`pods${i}`,`services${i}`);
}
for(const spec of input.frr) for(const p of spec.peers) {
  const i=Number(p.nodeId.slice(1));p.importSubnetIds.push(`pods${i}`,`services${i}`);
}
const version=process.argv[3];if(version!=='8.5.6'&&version!=='10.2.1')throw new Error('explicit supported FRR version required');
for(const spec of input.frr) spec.frrVersion=version;
const wg=compileWireGuard({registry:input.registry,expectedRegistryRevision:1,spec:input.wireguard,prefixPolicy:input.prefixPolicy});
if(!wg.ok)throw new Error(wg.diagnostics.join('; '));
const frr=input.frr.map(spec=>{const r=compileFrr({registry:input.registry,expectedRegistryRevision:1,spec,prefixPolicy:input.prefixPolicy});if(!r.ok)throw new Error(r.diagnostics.join('; '));return r.artifact;});
// IPv6+BFD parser coverage is separate from the IPv4 packet-forwarding topology.
const v6=structuredClone(input),base=v6.registry.resources[0]!;
for(const [id,cidr] of [['primary','2001:db8:100::/64'],['secondary','2001:db8:200::/64']]) v6.registry.resources.push({...base,id:`${id}-v6`,kind:'subnet',networkId:id!,cidr:cidr!});
for(let i=0;i<4;i++) {
  v6.registry.resources.push({...base,id:`infra6-${i}`,kind:'subnet',networkId:`lan${i}`,cidr:`2001:db8:${i+10}::/64`});
  v6.prefixPolicy!.permissions.push({id:`infra6-grant-${i}`,resourceId:`infra6-${i}`,siteId:`s${i}`,prefix:`2001:db8:${i+10}::/64`,role:'infrastructure',owner:{nodeId:`n${i}`,provider:'native',driver:'frr'}});
  const spec=v6.frr[i]!;spec.exportSubnetIds=[`infra6-${i}`];
  for(const peer of spec.peers) {
    const remote=Number(peer.nodeId.slice(1)),prefix=peer.backbone==='primary'?'100':'200';
    peer.addressFamily='ipv6';peer.address=`2001:db8:${prefix}::${remote+1}`;peer.updateSource=`2001:db8:${prefix}::${i+1}`;peer.bfd=true;
    peer.importSubnetIds=[`infra6-${remote}`];peer.reachabilityRouteId=`route6-${prefix}-${i}-${remote}`;
    v6.registry.resources.push({...base,id:peer.reachabilityRouteId,kind:'route',interfaceId:peer.interfaceId,routingDomainId:'rd',destination:peer.address+'/128',table:254});
  }
}
const syntaxFrr=v6.frr.map(spec=>{const r=compileFrr({registry:v6.registry,expectedRegistryRevision:1,spec,prefixPolicy:v6.prefixPolicy});if(!r.ok)throw new Error(r.diagnostics.join('; '));return r.artifact;});
writeFileSync(process.argv[2]!,JSON.stringify({input,wireguard:wg.artifact,frr,syntaxFrr,changeSet:buildNetworkChangeSet(input)},null,2));
