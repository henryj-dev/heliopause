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
writeFileSync(process.argv[2]!,JSON.stringify({input,wireguard:wg.artifact,frr,changeSet:buildNetworkChangeSet(input)},null,2));
