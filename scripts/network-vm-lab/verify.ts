/** Warm production signer around the independent peer collector; Agent never sees verifier keys. */
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, openSync, fstatSync, closeSync, constants } from 'node:fs';
import { createPrivateKey, randomBytes } from 'node:crypto';
import { signNetworkMessage, NETWORK_VERIFY_DOMAIN } from '../../src/network-execution.ts';
import { networkDigest } from '../../src/network-canonical.ts';
const base='/var/lib/heliopause-vm-lab',mode=process.argv[2],expectedTransaction=process.argv[3];
if(!['confirm','observe'].includes(mode??'')||process.getuid?.()!==0)throw new Error('marked peer verifier required');
const markerFd=openSync('/etc/heliopause-disposable-lab',constants.O_RDONLY|constants.O_NOFOLLOW);
try {
  const marker=fstatSync(markerFd);
  if(!marker.isFile()||marker.uid!==0||(marker.mode&0o777)!==0o600||JSON.parse(readFileSync(markerFd,'utf8')).role!=='peer')throw new Error('unsafe lab marker');
} finally { closeSync(markerFd); }
const authorization=JSON.parse(readFileSync(base+'/authorization.json','utf8'));
const a=JSON.parse(Buffer.from(authorization.payload,'base64url').toString());
// The authorization on disk is whatever was issued last. A case names its own transaction so a
// probe and its signed observation can never silently describe another one (2026-10-30 review).
if(expectedTransaction!==undefined&&a.transactionId!==expectedTransaction)throw new Error('authorization does not name the case transaction');
const verifier=createPrivateKey(readFileSync(base+'/verifier.key'));
const child=spawn('/usr/bin/python3',['/source/scripts/network-vm-lab/verifier.py',mode!],{stdio:['pipe','pipe','inherit']});
let buffer='',observed=false,delivered=false;
const timeout=setTimeout(()=>child.kill('SIGKILL'),45000);
child.stdout.on('data',(chunk:Buffer)=>{
  buffer+=chunk.toString();if(buffer.length>1024*1024){child.kill('SIGKILL');return;}
  while(buffer.includes('\n')){
    const line=buffer.slice(0,buffer.indexOf('\n'));buffer=buffer.slice(buffer.indexOf('\n')+1);
    const result=JSON.parse(line);
    if(result.kind==='probe'){
      if(observed||!Number.isSafeInteger(result.observedAt)||Date.now()-result.observedAt>2000||result.observedAt>Date.now()+100)throw new Error('stale collector result');
      if(Object.values(result.checks).every(value=>value===true)&&Date.now()-result.gateway.now*1000>10000)throw new Error('collector span exceeds proof freshness');
      observed=true;
      writeFileSync(base+'/current-probes.json',JSON.stringify(result),{mode:0o600});
      if(mode==='observe'){
        writeFileSync(base+'/boot-observation.json',JSON.stringify(signNetworkMessage('heliopause-network-boot-observation-v1',{authorizationHash:networkDigest(a),bootId:result.gateway.bootId,observedAt:result.observedAt,checks:result.checks},verifier)),{mode:0o600});
      }else{
        const receipt=signNetworkMessage(NETWORK_VERIFY_DOMAIN,{transactionId:a.transactionId,authorizationHash:networkDigest(a),artifactHash:a.artifactHash,observedAt:result.observedAt,expiresAt:Math.min(result.observedAt+10000,a.rollbackAt-1),nonce:randomBytes(16).toString('hex'),checks:result.checks},verifier);
        writeFileSync(base+'/receipt.json',JSON.stringify(receipt),{mode:0o600});
        child.stdin.end(JSON.stringify({receipt,hash:a.approval.planHash})+'\n');
      }
    }else if(result.kind==='delivered'){
      delivered=true;writeFileSync(base+'/confirmation.json',JSON.stringify(result.confirmation),{mode:0o600});
    }else throw new Error('unsupported collector result');
  }
});
child.on('exit',(code)=>{clearTimeout(timeout);if(code!==0||!observed||(mode==='confirm'&&!delivered)){process.exitCode=1;return;}console.log(mode==='confirm'?'independent-confirm-delivered':'fresh-boot-observation-recorded');});
