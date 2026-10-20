/** Lab authority uses the same Registry, review builder, approval state machine and issuer as Manager. */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { NetworkRegistryStore } from '../../src/network-registry.ts';
import { buildNetworkChangeSet } from '../../src/network-change-set.ts';
import { networkDigest } from '../../src/network-canonical.ts';
import { emptyApprovals, propose, approve } from '../../src/approval.ts';
import { authorizeNetworkExecution, confirmNetworkExecution, networkExecutionHash, signNetworkMessage, NETWORK_CONFIRM_DOMAIN, NETWORK_VERIFY_DOMAIN, type NetworkExecutionDraft } from '../../src/network-execution.ts';
const [action,dir]=process.argv.slice(2) as [string,string];
const read=(name:string)=>JSON.parse(readFileSync(join(dir,name),'utf8'));
const save=(name:string,v:unknown)=>writeFileSync(join(dir,name),JSON.stringify(v),{mode:0o600});
if(action==='keys') {
  for(const kind of ['manager','verifier']) {
    const pair=generateKeyPairSync('ed25519');mkdirSync(join(dir,kind),{mode:0o700});
    writeFileSync(join(dir,kind+'.key'),pair.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
    writeFileSync(join(dir,kind,'public.pem'),pair.publicKey.export({format:'pem',type:'spki'}),{mode:0o600});
  }
} else if(action==='issue') {
  const facts=read('facts.json'),now=Date.now(),at=new Date(now).toISOString(),transactionId=randomBytes(16).toString('hex'),device='hp'+transactionId.slice(0,12);
  const management={mode:'managed',provider:'wireguard',driver:'wg-quick'};
  const base={owner:'lab',generation:1,management};
  const store=new NetworkRegistryStore(join(dir,'registry.json'));
  const resources=[{...base,id:'site',kind:'site'},{...base,id:'gateway',kind:'node',siteId:'site'}, {...base,id:'domain',kind:'routing-domain',name:'global',isolation:'global'},
    {...base,id:'backbone',kind:'network',scope:'overlay',siteIds:['site'],routingDomainId:'domain',purpose:'backbone'},
    {...base,id:'subnet',kind:'subnet',networkId:'backbone',cidr:'192.0.2.128/28'},
    {...base,id:'wg-new',kind:'interface',nodeId:'gateway',networkId:'backbone',name:device,mtu:1400},
    ...['192.0.2.130/32','198.51.100.6/32'].map((destination,i)=>({...base,id:'route'+i,kind:'route',interfaceId:'wg-new',routingDomainId:'domain',destination,table:254,nextHop:null,protocol:'static',metric:42760}))];
  const registry=store.mutate(0,'lab-authority',{action:'replace',resources});
  const observation={source:'lab',host:'gateway',receivedAt:at,report:{schemaVersion:1 as const,collectionId:'00000000-0000-4000-8000-000000000006',startedAt:at,completedAt:at,observations:{links:{status:'success' as const,startedAt:at,completedAt:at,data:facts.snapshot.links.map((l:any)=>({ifname:l.name,ifindex:l.index,mtu:l.mtu}))},addresses:{status:'success' as const,startedAt:at,completedAt:at,data:[]},routes4:{status:'success' as const,startedAt:at,completedAt:at,data:facts.snapshot.routes}},capabilities:{links:{available:true,status:'success' as const},addresses:{available:true,status:'success' as const},routes4:{available:true,status:'success' as const}}}};
  const review=buildNetworkChangeSet({id:'execution-review',registry,expectedRegistryRevision:registry.revision,now,observations:[observation],bindings:[{source:'lab',host:'gateway',nodeId:'gateway',siteId:'site'}]});
  const operation={driver:'linux-wireguard-v1' as const,interfaceId:'wg-new',interfaceName:device,address:'192.0.2.129/32',mtu:1400,listenPort:51820,secretRef:'gateway',publicKey:facts.publicKey,peers:[{publicKey:facts.peerPublicKey,endpoint:'203.0.113.2:51820',allowedIps:['192.0.2.130/32','198.51.100.6/32']}],routes:['192.0.2.130/32','198.51.100.6/32']};
  const draft:NetworkExecutionDraft={schemaVersion:1,transactionId,target:{source:'lab',host:'gateway',nodeId:'gateway'},registryRevision:registry.revision,resources:registry.resources.map(r=>({id:r.id,generation:r.generation})),desiredDigest:review.desiredDigest,reviewHash:review.contentHash,artifactHash:networkDigest(operation),observation:{digest:networkDigest(observation),collectedAt:now,maxAgeMs:30000},localPrecondition:networkDigest(facts.snapshot),operation,issuedAt:now,expiresAt:now+5000,rollbackAt:now+(facts.timeoutMs??12000)};
  const approvals=emptyApprovals(),hash=networkExecutionHash(draft);
  propose(approvals,{hash,generation:draft.transactionId,summary:{hosts:[{host:'gateway',stage:'gateway',ruleCount:1,rulesetHash:draft.artifactHash}]},by:'alice',now:new Date(now)});
  approve(approvals,{hash,by:'bob',now:new Date(now)});
  if(facts.mutateRegistry) store.mutate(registry.revision,'external',{action:'update',id:'wg-new',resource:{...registry.resources.find(r=>r.id==='wg-new'),mtu:1380}});
  const envelope=authorizeNetworkExecution(store,approvals,draft,'alice',createPrivateKey(readFileSync(join(dir,'manager.key'))),{observation,review},new Date(now));
  save('authorization.json',envelope);save('review.json',review);
} else if(action==='verify') {
  const envelope=read('authorization.json'),a=JSON.parse(Buffer.from(envelope.payload,'base64url').toString()),result=read('verification.json'),now=Date.now();
  save('receipt.json',signNetworkMessage(NETWORK_VERIFY_DOMAIN,{transactionId:a.transactionId,authorizationHash:networkDigest(a),artifactHash:a.artifactHash,observedAt:now,expiresAt:Math.min(now+5000,a.rollbackAt-1),nonce:randomBytes(16).toString('hex'),checks:result},createPrivateKey(readFileSync(join(dir,'verifier.key')))));
} else if(action==='confirm') {
  const envelope=read('authorization.json'),a=JSON.parse(Buffer.from(envelope.payload,'base64url').toString()),now=Date.now();
  save('confirmation.json',confirmNetworkExecution(envelope,read('receipt.json'),[createPublicKey(readFileSync(join(dir,'verifier/public.pem')))],createPrivateKey(readFileSync(join(dir,'manager.key'))),now));
} else if(action==='unsafe-confirm') {
  const envelope=read('authorization.json'),a=JSON.parse(Buffer.from(envelope.payload,'base64url').toString());
  save('confirmation.json',signNetworkMessage(NETWORK_CONFIRM_DOMAIN,{transactionId:a.transactionId,authorizationHash:networkDigest(a),artifactHash:a.artifactHash,expiresAt:Math.min(Date.now()+5000,a.rollbackAt-1),verification:read('receipt.json')},createPrivateKey(readFileSync(join(dir,'manager.key')))));
} else if(action==='tamper') {
  const env=read('authorization.json'),a=JSON.parse(Buffer.from(env.payload,'base64url').toString()),kind=process.argv[4];
  if(kind==='signature') env.signature='A'.repeat(86);
  else {
    if(kind==='target') a.target.host='other';
    if(kind==='expiry') a.expiresAt=1;
    if(kind==='hash') a.artifactHash='0'.repeat(64);
    if(kind==='approval') a.approval.approvedBy=a.approval.proposedBy;
    a.approval.planHash='sha256:'+networkDigest(Object.fromEntries(Object.entries(a).filter(([k])=>k!=='approval')));
    save('request-tampered.json',signNetworkMessage('heliopause-network-execution-v1',a,createPrivateKey(readFileSync(join(dir,'manager.key')))));process.exit(0);
  }
  save('request-tampered.json',env);
} else throw new Error('unsupported lab action');
