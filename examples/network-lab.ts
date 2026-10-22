/** Synthetic documentation ranges only. These are not operational addresses or cryptographic lab keys. */
import type { NetworkInventoryResource } from '../src/network-inventory.ts';
import type { NetworkChangeSetInput } from '../src/network-change-set.ts';
import type { WireGuardSpec } from '../src/network-wireguard.ts';
import type { FrrSpec } from '../src/network-frr.ts';
import { networkDigest } from '../src/network-canonical.ts';
export function networkLabInput(): NetworkChangeSetInput & { wireguard: WireGuardSpec; frr: FrrSpec[] } {
  const now=Date.parse('2026-01-01T00:00:00Z'),at=new Date(now).toISOString();
  const management={mode:'managed',provider:'wireguard',driver:'wireguard'} as const;
  const base={owner:'lab',generation:1,management};
  const resources:NetworkInventoryResource[]=[{...base,id:'rd',kind:'routing-domain',name:'lab',isolation:'global'}];
  for(const [id,cidr] of [['primary','198.51.100.0/27'],['secondary','198.51.100.32/27']] as const) {
    resources.push({...base,id,kind:'network',scope:'overlay',siteIds:['s0','s1','s2','s3'],purpose:'backbone',routingDomainId:'rd'},
      {...base,id:`${id}-sub`,kind:'subnet',networkId:id,cidr},
      {...base,id:`${id}-pool`,kind:'address-pool',subnetId:`${id}-sub`,cidr,allocationAuthority:'operator',purpose:'tunnel'});
  }
  const gateways:WireGuardSpec['gateways']=[],frr:FrrSpec[]=[];
  for(let i=0;i<4;i++) {
    const lan=`192.0.2.${i*64}/26`,infra=`192.0.2.${i*64}/27`;
    resources.push({...base,id:`s${i}`,kind:'site'},{...base,id:`n${i}`,kind:'node',siteId:`s${i}`},{...base,id:`g${i}`,kind:'gateway',nodeId:`n${i}`},
      {...base,id:`lan${i}`,kind:'network',siteId:`s${i}`,scope:'site-local',purpose:'infrastructure',routingDomainId:'rd'},
      {...base,id:`site${i}`,kind:'subnet',networkId:`lan${i}`,cidr:lan},
      {...base,id:`infra${i}`,kind:'subnet',networkId:`lan${i}`,cidr:infra,parentSubnetId:`site${i}`},
      {...base,id:`pods${i}`,kind:'address-pool',subnetId:`site${i}`,cidr:`192.0.2.${i*64+32}/28`,allocationAuthority:'kubernetes',purpose:'kubernetes-pod'},
      {...base,id:`services${i}`,kind:'address-pool',subnetId:`site${i}`,cidr:`192.0.2.${i*64+48}/28`,allocationAuthority:'kubernetes',purpose:'kubernetes-service'},
      {...base,id:`eth${i}`,kind:'interface',nodeId:`n${i}`,networkId:`lan${i}`,name:'eth0'},
      {...base,id:`wg${i}`,kind:'interface',nodeId:`n${i}`,networkId:'primary',name:'wg0',mtu:1420},
      {...base,id:`cf${i}`,kind:'interface',nodeId:`n${i}`,networkId:'secondary',name:'cf0',management:{mode:'external',provider:'cloudflare'}});
    for(let j=0;j<4;j++) if(j!==i) for(const [bb,offset,iface] of [['p',0,'wg'],['s',32,'cf']] as const) resources.push({...base,id:`route-${bb}-${i}-${j}`,kind:'route',interfaceId:`${iface}${i}`,routingDomainId:'rd',destination:`198.51.100.${offset+j+1}/32`,table:254,nextHop:null,protocol:'boot',...(bb==='s'?{management:{mode:'external' as const,provider:'cloudflare'}}:{})});
    gateways.push({gatewayId:`g${i}`,interfaceId:`wg${i}`,underlayInterfaceId:`eth${i}`,address:`198.51.100.${i+1}/32`,listenPort:51820,endpoint:{address:`203.0.113.${i+1}`,port:51820},publicKey:Buffer.alloc(32,i+1).toString('base64'),privateKeyRef:{provider:'ephemeral-lab',reference:`key-${i}`},allowedPrefixes:[infra],mtu:1420});
    const peers:FrrSpec['peers']=[];
    for(let j=0;j<4;j++) if(i!==j) for(const [backbone,offset,iface,bb] of [['primary',0,'wg','p'],['secondary',32,'cf','s']] as const) peers.push({nodeId:`n${j}`,siteId:`s${j}`,networkId:backbone,interfaceId:`${iface}${i}`,remoteAsn:65100+j,address:`198.51.100.${offset+j+1}`,updateSource:`198.51.100.${offset+i+1}`,addressFamily:'ipv4',backbone,importSubnetIds:[`infra${j}`],reachabilityRouteId:`route-${bb}-${i}-${j}`});
    frr.push({schemaVersion:1,frrVersion:'10.2.1',nodeId:`n${i}`,siteId:`s${i}`,routerId:`198.51.100.${i+1}`,localAsn:65100+i,exportSubnetIds:[`infra${i}`],peers});
  }
  const observations=Array.from({length:4},(_,i)=>{
    const links=['eth0','wg0','cf0'].map((ifname,j)=>({ifindex:j+1,ifname,mtu:ifname==='wg0'?1420:1500}));
    const routes4=resources.flatMap(r=>r.kind==='route'&&rsNode(r.interfaceId)===`n${i}`?[{dst:r.destination,dev:r.interfaceId.startsWith('wg')?'wg0':'cf0',table:254,protocol:'boot'}]:[]);
    return {source:'lab-relay',host:`lab-host-${i}`,receivedAt:at,relayReceivedAt:at,report:{schemaVersion:1 as const,collectionId:`00000000-0000-4000-8000-${String(i+1).padStart(12,'0')}`,startedAt:at,completedAt:at,observations:{links:{status:'success' as const,startedAt:at,completedAt:at,data:links},addresses:{status:'success' as const,startedAt:at,completedAt:at,data:[]},routes4:{status:'success' as const,startedAt:at,completedAt:at,data:routes4}},capabilities:{links:{available:true,status:'success' as const},addresses:{available:true,status:'success' as const},routes4:{available:true,status:'success' as const}}}};
  });
  function rsNode(id:string){const r=resources.find(r=>r.id===id);return r?.kind==='interface'?r.nodeId:'';}
  return {id:'lab-review',now,expectedRegistryRevision:1,registry:{revision:1,resources},observations,bindings:Array.from({length:4},(_,i)=>({source:'lab-relay',host:`lab-host-${i}`,siteId:`s${i}`,nodeId:`n${i}`})),wireguard:{schemaVersion:1,backend:'wg-quick',networkId:'primary',gateways},frr,
    prefixPolicy:{schemaVersion:1,evaluatedAt:now,permissions:Array.from({length:4},(_,i)=>({id:`infra-grant-${i}`,resourceId:`infra${i}`,siteId:`s${i}`,prefix:`192.0.2.${i*64}/27`,role:'infrastructure',owner:{nodeId:`n${i}`,provider:'native',driver:'frr'}}))}};
}
/** Reference helper for synthetic attestations; never substitutes for an authenticated ingress path. */
export function labPrefixEvidence(input:ReturnType<typeof networkLabInput>,index=0) {
  const record=input.observations[index]!;
  return {source:record.source!,host:record.host,collectionId:record.report.collectionId,digest:networkDigest(record),observedAt:record.report.completedAt};
}
