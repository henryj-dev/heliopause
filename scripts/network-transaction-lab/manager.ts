/** Production Manager in the independent management namespace. Fault hook drops only a response. */
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { createHash, X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import { join } from 'node:path';
import { startManager } from '../../src/manager-server.ts';
const dir=process.argv[2]!,cfg=JSON.parse(readFileSync(join(dir,'config.json'),'utf8'));
const pki=join(dir,'pki');
const manager=await startManager({hostname:'192.0.2.1',port:8443,relays:[],
  tls:{certFile:join(pki,'manager.pem'),keyFile:join(pki,'manager.key'),caFile:join(pki,'ca.pem')},
  revocationFile:cfg.lifecycleRevocations===true?join(dir,'lifecycle-revocations.json'):undefined,
  networkJournalArchiveDirectory:cfg.lifecycleJournalMaintenance===true?join(dir,'journal-archives'):undefined,
  operatorCNs:['alice','bob'],writerCNs:['alice','bob'],
  networkRegistryFile:join(dir,'registry.json'),networkObservationsDir:join(dir,'observations'),
  networkExecutionTargets:[{...cfg.identity,journalId:cfg.journalId,certificateSha256:createHash('sha256').update(new X509Certificate(readFileSync(join(pki,'gateway.pem'))).raw).digest('hex')}],
  artifactSigning:{privateKey:createPrivateKey(readFileSync(join(dir,'manager.key')))},
  // Explicit finite-overlap exercise; fixed public paths, missing next key fails closed.
  networkVerifierKeys:[createPublicKey(readFileSync(join(dir,'verifier/public.pem'))),...(cfg.lifecycleVerifierOverlap===true?[createPublicKey(readFileSync(join(dir,'verifier/next.pem')))]:[])],log:()=>{}});
manager.server.prependListener('request',(req,res)=>{
  const marker=req.url==='/api/network/execution/cancel'?'drop-cancel-response':'drop-terminal-response';
  if(['/api/network/execution/terminal','/api/network/execution/cancel'].includes(req.url??'')&&existsSync(join(dir,marker))) {
    unlinkSync(join(dir,marker));
    res.end=(()=>{process.kill(process.pid,'SIGKILL');return res;}) as typeof res.end;
  }
});
writeFileSync(join(dir,'manager-ready.json'),JSON.stringify({pid:process.pid}),{mode:0o600});
