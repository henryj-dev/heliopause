/** Signed transition attachment index. Integrity/completeness do not authenticate unsigned measurements. */
import { networkDigest } from './network-canonical.ts';
export const JOURNAL_EVIDENCE_ROLES=['report','inventory','packets','modules','history'] as const;
export type JournalEvidenceRole=typeof JOURNAL_EVIDENCE_ROLES[number];
export interface JournalEvidenceManifest {
  schemaVersion:1;
  runs:Array<{transactionId:string;authorizationHash:string;sourceCommit:string;imageSha256:string;moduleManifestSha256:string;files:Record<JournalEvidenceRole,string[]>}>;
  files:Record<string,{kind:JournalEvidenceRole;sha256:string;bytes:number}>;
}
const exact=(v:any,fields:string)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(' ')===fields.split(' ').sort().join(' ');
const hash=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function need(v:unknown,message:string):asserts v {if(!v)throw new Error(message);}
export function validateJournalEvidence(value:JournalEvidenceManifest,transactions?:Record<string,any>):void {
  need(exact(value,'schemaVersion runs files')&&value.schemaVersion===1&&Array.isArray(value.runs)&&value.runs.length<=1024&&value.files&&typeof value.files==='object'&&!Array.isArray(value.files),'invalid execution evidence manifest');
  const entries=Object.entries(value.files);need(entries.length<=4096,'execution evidence file capacity');let total=0;
  for(const [name,file] of entries){
    need(/^[a-z][a-z0-9-]{0,63}\.json$/.test(name)&&exact(file,'kind sha256 bytes')&&JOURNAL_EVIDENCE_ROLES.includes(file.kind)&&hash(file.sha256)&&Number.isSafeInteger(file.bytes)&&file.bytes>=1&&file.bytes<=4*1024*1024,'invalid execution evidence file');
    total+=file.bytes;
  }
  need(total<=128*1024*1024,'execution evidence total byte capacity');
  const ids=new Set<string>(),used=new Set<string>();
  for(const run of value.runs){
    need(exact(run,'transactionId authorizationHash sourceCommit imageSha256 moduleManifestSha256 files')&&/^[a-f0-9]{32}$/.test(run.transactionId)&&!ids.has(run.transactionId)&&hash(run.authorizationHash)&&/^[a-f0-9]{40}$/.test(run.sourceCommit)&&hash(run.imageSha256)&&hash(run.moduleManifestSha256)&&exact(run.files,JOURNAL_EVIDENCE_ROLES.join(' ')),'duplicate or invalid execution evidence run');ids.add(run.transactionId);
    for(const role of JOURNAL_EVIDENCE_ROLES){const names=run.files[role];need(Array.isArray(names)&&names.length>=1&&names.length<=64&&new Set(names).size===names.length,'missing or duplicate execution evidence role');for(const name of names){need(typeof name==='string'&&Object.hasOwn(value.files,name)&&value.files[name]!.kind===role,'unbound execution evidence attachment');used.add(name);}}
    need(value.files[run.files.modules[0]!]!.sha256===run.moduleManifestSha256,'deployed module evidence commitment mismatch');
    if(transactions){const row=transactions[run.transactionId];need(row&&networkDigest(row.authorization)===run.authorizationHash,'execution evidence authorization mismatch');}
  }
  need(used.size===entries.length,'unreferenced execution evidence files');
  if(transactions)need(ids.size===Object.keys(transactions).length&&Object.keys(transactions).every(id=>ids.has(id)),'missing execution evidence run');
}
