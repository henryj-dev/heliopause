/** TLS stays on loopback; fixed OpenSSL fixture commands only, all files in a private temp root. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { request, Agent } from 'node:https';
import { startManager } from './manager-server.ts';
import { NetworkRegistryStore } from './network-registry.ts';
import { networkLabInput } from '../examples/network-lab.ts';
import { createJournalArchive } from './network-journal-archive.ts';
import { artifactSigningKeyId } from './artifact-signature.ts';

test('mTLS two-person scope-A transition commits exact archive; restart rejects retired binding',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'hp-journal-api-')),agents:Agent[]=[];
  let manager:Awaited<ReturnType<typeof startManager>>|undefined;
  try{
    const ssl=(...args:string[])=>execFileSync('openssl',args,{cwd:dir,stdio:'pipe',timeout:10000});
    ssl('req','-x509','-newkey','ed25519','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=isolated-journal-ca');
    for(const name of ['server','alice','bob','reader']){
      ssl('req','-newkey','ed25519','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name);
      writeFileSync(join(dir,'leaf.ext'),'extendedKeyUsage='+(name==='server'?'serverAuth\nsubjectAltName=IP:127.0.0.1':'clientAuth')+'\n');
      ssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',name+'.pem','-days','1','-extfile','leaf.ext');
    }
    const read=(f:string)=>readFileSync(join(dir,f)),store=new NetworkRegistryStore(join(dir,'registry.json'));
    store.mutate(0,'alice',{action:'replace',resources:networkLabInput().registry.resources});store.initializeExecutions();
    const signer=generateKeyPairSync('ed25519'),verifier=generateKeyPairSync('ed25519'),journal='a'.repeat(32),target={source:'lab',host:'gateway',nodeId:'gateway'};
    const archives=join(dir,'archives');mkdirSync(archives,{mode:0o700});const archiveName='b'.repeat(32);
    const values={evidence:{schemaVersion:1,runs:[],files:{}},manager:store.read(),agent:{schemaVersion:2,journalId:journal,acceptedSequence:0,terminalSequence:0,lastClock:0,transactions:{}},identity:{journalId:journal},outbox:[],acknowledgments:{},trust:{manager:{[artifactSigningKeyId(signer.publicKey)]:signer.publicKey.export({format:'pem',type:'spki'}).toString()},verifier:{[artifactSigningKeyId(verifier.publicKey)]:verifier.publicKey.export({format:'pem',type:'spki'}).toString()}},config:{enabled:false,identity:target,journalId:journal,managerKeys:'/etc/heliopause/trust/manager',verifierKeys:'/etc/heliopause/trust/verifier',secrets:'/etc/heliopause/secrets',protectedAddresses:['192.0.2.1']}};
    createJournalArchive(join(archives,archiveName),Object.fromEntries(Object.entries(values).map(([k,v])=>[k,k==='manager'?readFileSync(store.path):Buffer.from(JSON.stringify(v))])) as any);
    const options={port:0,hostname:'127.0.0.1',relays:[],tls:{certFile:join(dir,'server.pem'),keyFile:join(dir,'server.key'),caFile:join(dir,'ca.pem')},operatorCNs:['alice','bob','reader'],writerCNs:['alice','bob'],log:()=>{},networkRegistryFile:store.path,networkJournalArchiveDirectory:archives,artifactSigning:{privateKey:signer.privateKey},networkVerifierKeys:[verifier.publicKey],networkExecutionTargets:[{...target,journalId:journal,certificateSha256:'f'.repeat(64)}]};
    manager=await startManager(options);let port=(manager.server.address() as any).port;
    const clients=Object.fromEntries(['alice','bob','reader','none'].map(who=>{const agent=new Agent({ca:read('ca.pem'),...(who==='none'?{}:{cert:read(who+'.pem'),key:read(who+'.key')}),keepAlive:false,maxCachedSessions:0});agents.push(agent);return[who,agent];}));
    const call=(action:string,who='alice',body:any={archiveName},method='POST',headers={})=>new Promise<{status:number;body:any}>((resolve,reject)=>{
      const req=request({host:'127.0.0.1',port,path:'/api/network/journal-transition/'+action,method,agent:clients[who],headers:{'content-type':'application/json',...headers},signal:AbortSignal.timeout(5000)},res=>{let data='';res.on('data',chunk=>data+=chunk);res.on('end',()=>resolve({status:res.statusCode!,body:JSON.parse(data)}));});req.on('error',reject);req.end(method==='GET'?undefined:JSON.stringify(body));
    });
    assert.equal((await call('propose','none')).status,401);
    assert.equal((await call('propose','reader')).status,403);
    assert.equal((await call('propose','alice',{archiveName},'POST',{origin:'https://foreign.invalid'})).status,403);
    assert.equal((await call('propose','alice',{archiveName:'../escape'})).status,409);
    const proposed=await call('propose');assert.equal(proposed.status,201);const hash=proposed.body.hash;
    assert.equal((await call('review?hash='+encodeURIComponent(hash),'reader',{},'GET')).status,200);
    assert.equal((await call('approve','alice',{archiveName,hash})).status,409);
    assert.equal((await call('authorize','alice',{archiveName,hash})).status,409);
    assert.equal((await call('approve','bob',{archiveName,hash})).status,200);
    const authorized=await call('authorize','alice',{archiveName,hash});assert.equal(authorized.status,200);
    assert.equal((await call('commit','alice',{archiveName})).status,409);
    const committed=await call('commit','bob',{archiveName,envelope:authorized.body.envelope});assert.equal(committed.status,200);
    const duplicate=await call('commit','bob',{archiveName,envelope:authorized.body.envelope});assert.deepEqual(duplicate,committed);
    assert.equal(store.executionStatus().records.length,0);const next=store.executionStatus().journalEpoch!.journalId;assert.notEqual(next,journal);
    await new Promise<void>(r=>manager!.server.close(()=>r()));manager=undefined;
    await assert.rejects(()=>startManager(options),/retired or ambiguous/);
    manager=await startManager({...options,networkExecutionTargets:[{...options.networkExecutionTargets[0]!,journalId:next}]});port=(manager.server.address() as any).port;
    assert.equal((await call('propose')).status,409);
  }finally{
    agents.forEach(a=>a.destroy());if(manager){manager.stopProblemWatch();await new Promise<void>(r=>manager!.server.close(()=>r()));}rmSync(dir,{recursive:true,force:true});
  }
});
