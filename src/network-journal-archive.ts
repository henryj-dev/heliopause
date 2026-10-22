import { journalRows } from './network-journal-rows.ts';
import { validateJournalEvidence, type JournalEvidenceManifest } from './network-journal-evidence.ts';
/** Restricted exact-byte snapshot archive; no secrets/recursive lab copy or ledger mutation. */
import { createHash } from 'node:crypto';
import { isUtf8 } from 'node:buffer';
import { constants, openSync, closeSync, fstatSync, lstatSync, fsyncSync, readSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { networkDigest } from './network-canonical.ts';
import type { JournalArchive } from './network-journal-transition.ts';
const files={manager:'manager.json',agent:'transactions.json',identity:'journal-identity.json',outbox:'terminal-results.json',acknowledgments:'terminal-acks.json',trust:'audit-public-keys.json',config:'network-executor-config.json',evidence:'execution-evidence.json'} as const;
type Name=keyof typeof files;
export type JournalArchiveBytes=Record<Name,Buffer>;
const digest=(bytes:Buffer)=>createHash('sha256').update(bytes).digest('hex');
/** Reject malformed bytes before toString can replace them. Preserve the existing BOM refusal. */
function archiveText(raw:Buffer):string {
  if(!isUtf8(raw))throw new Error('invalid archive UTF-8');
  return raw.toString('utf8');
}
/** JSON.parse alone silently accepts duplicate keys, unlike the production Agent decoder. */
export function parseArchiveJson(raw:string,integerToken:(path:readonly string[])=>boolean=()=>false):any {
  const parsed=JSON.parse(raw),stack:Array<{object:boolean;key:boolean;field?:string;path:string[];seen:Set<string>}>=[];
  const tokens=/"(?:[^"\\]|\\[\s\S])*"|[{}\[\]:,]|[^\s{}\[\]:,"]+/g;
  let token:RegExpExecArray|null;
  while((token=tokens.exec(raw))){
    const value=token[0],frame=stack.at(-1);
    // Python's canonical UTF-8 encoding cannot represent an unpaired surrogate.
    // Check decoded keys and values; the Unicode regexp treats a valid pair as one scalar.
    if(value.startsWith('"')&&/[\uD800-\uDFFF]/u.test(JSON.parse(value)))throw new Error('unpaired archive Unicode surrogate');
    if(value==='{'||value==='['){if(stack.length>=128)throw new Error('archive JSON depth bound');const path=frame?[...frame.path,frame.object?frame.field!:'[]']:[];stack.push({object:value==='{',key:true,path,seen:new Set()});}
    else if(value==='}'||value===']')stack.pop();
    else if(value===','&&frame?.object)frame.key=true;
    else if(value===':'&&frame?.object)frame.key=false;
    else if(value.startsWith('"')&&frame?.object&&frame.key){const key=JSON.parse(value);if(frame.seen.has(key))throw new Error('duplicate archive JSON key');frame.seen.add(key);frame.field=key;}
    else if(frame&&(!frame.object||!frame.key)&&/^-?\d/.test(value)&&integerToken([...frame.path,frame.object?frame.field!:'[]'])&&!/^-?(?:0|[1-9]\d*)$/.test(value))throw new Error('unsupported replay counter encoding: integer JSON token required');
  }
  return parsed;
}
/** Python's replay validator requires int, while JSON.parse collapses 1.0/1e0 to 1.
 * Check original counter and committed integer-contract tokens before that distinction is lost. This is
 * a storage encoding restriction, not a claim that those JSON numbers are malformed.
 * Other fields (including stored monotonic floating-point values) retain their encoding.
 */
export function parseReplayJournalJson(raw:string):any {
  return parseArchiveJson(raw,path=>(path.length===1&&['acceptedSequence','terminalSequence','lastClock'].includes(path[0]!))||
    (path.length>=4&&path[0]==='transactions'&&/^[a-f0-9]{32}$/.test(path[1]!)&&committedRowFields.includes(path[2]!)));
}
// All numeric values in these execution/cancellation/result contracts are integers.
// Their decoded copies must retain that encoding too: 1.0 changes Python's digest.
const committedRowFields=['authorization','cancellation','terminalResult','cancellationResponse'];
export function parseJournalArchiveFile(name:Name,raw:Buffer):any {
  if(name==='agent')return parseReplayJournalJson(archiveText(raw));
  return parseArchiveJson(archiveText(raw),path=>{
    if(name==='identity')return path.length>=3&&path[0]==='capacityCancellation'&&committedRowFields.includes(path[1]!)||path.join('/')==='capacityCancellation/history/[]/at';
    if(name==='outbox')return path.length>=2&&path[0]==='[]';
    if(name==='evidence')return path.join('/')==='schemaVersion'||(path.length===3&&path[0]==='files'&&path[2]==='bytes');
    if(name==='manager')return path.join('/')==='execution/records/[]/sequence'||
      (path.length>=5&&path.slice(0,3).join('/')==='execution/records/[]'&&['result','cancellationResponse'].includes(path[3]!));
    return false;
  });
}
function ancestry(path:string):void {
  let current=resolve(path);
  while(true){const s=lstatSync(current);if(s.isSymbolicLink()||!s.isDirectory())throw new Error('archive path symlink/non-directory refused');const parent=dirname(current);if(current===parent)break;current=parent;}
}
function privateDirectory(path:string):void {
  ancestry(path);const s=lstatSync(path);if(s.uid!==process.geteuid?.()||(s.mode&0o777)!==0o700)throw new Error('owned0700 archive directory required');
}
function read(path:string,maximum:number):Buffer {
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{const s=fstatSync(fd);if(!s.isFile()||s.uid!==process.geteuid?.()||(s.mode&0o777)!==0o600||s.nlink!==1||s.size>maximum)throw new Error('bounded owned0600 archive file required');const buffer=Buffer.alloc(maximum+1);let length=0;while(length<buffer.length){const count=readSync(fd,buffer,length,buffer.length-length,null);if(!count)break;length+=count;}const after=fstatSync(fd);if(length>maximum||after.size!==length||s.size!==after.size||s.mtimeMs!==after.mtimeMs||s.ctimeMs!==after.ctimeMs)throw new Error('archive file growth/change bound');fsyncSync(fd);return buffer.subarray(0,length);}finally{closeSync(fd);}
}
function seal(path:string):void {const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);try{fsyncSync(fd);}finally{closeSync(fd);}}
function refuseCredentials(value:unknown):void {
  if(typeof value==='string'&&/-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----/.test(value))throw new Error('private key archive refused');
  if(Array.isArray(value)){value.forEach(refuseCredentials);return;}
  if(value&&typeof value==='object')for(const [key,child] of Object.entries(value)){
    if(['privatekey','password','token','clientsecret','presharedkey','cookie'].includes(key.toLowerCase().replace(/[_-]/g,'')))throw new Error('credential field archive refused');
    refuseCredentials(child);
  }
}
export function createJournalArchive(directory:string,bytes:JournalArchiveBytes,attachments:Record<string,Buffer>={}):JournalArchive {
  for(const [name] of Object.entries(files) as [Name,string][]){const raw=bytes[name];if(!Buffer.isBuffer(raw)||raw.length>(name==='manager'?4:8)*1024*1024)throw new Error('snapshot archive size bound');refuseCredentials(parseJournalArchiveFile(name,raw));}
  const evidence=parseJournalArchiveFile('evidence',bytes.evidence) as JournalEvidenceManifest;validateJournalEvidence(evidence,journalRows(parseReplayJournalJson(archiveText(bytes.agent)),parseArchiveJson(archiveText(bytes.identity))));
  if(Object.keys(attachments).sort().join(' ')!==Object.keys(evidence.files).sort().join(' '))throw new Error('missing/extra execution evidence attachments');
  for(const [name,entry] of Object.entries(evidence.files)){const raw=attachments[name]!;if(!Buffer.isBuffer(raw)||raw.length!==entry.bytes||digest(raw)!==entry.sha256)throw new Error('execution evidence attachment mismatch');refuseCredentials(parseArchiveJson(archiveText(raw)));}
  privateDirectory(dirname(resolve(directory)));mkdirSync(directory,{mode:0o700});
  const manifest:{schemaVersion:1;files:Record<string,{sha256:string;bytes:number}>}={schemaVersion:1,files:{}};
  for(const [name,file] of Object.entries(files) as [Name,string][]) {
    const raw=bytes[name];if(!Buffer.isBuffer(raw)||raw.length>(name==='manager'?4:8)*1024*1024)throw new Error('snapshot archive size bound');
    if(/-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----/.test(archiveText(raw)))throw new Error('private key archive refused');
    writeFileSync(join(directory,file),raw,{flag:'wx',mode:0o600});read(join(directory,file),8*1024*1024);manifest.files[file]={sha256:digest(raw),bytes:raw.length};
  }
  const evidenceDirectory=join(directory,'evidence');mkdirSync(evidenceDirectory,{mode:0o700});
  for(const [name,raw] of Object.entries(attachments)){if(!/^[a-z][a-z0-9-]{0,63}\.json$/.test(name))throw new Error('unsafe execution evidence filename');writeFileSync(join(evidenceDirectory,name),raw,{flag:'wx',mode:0o600});read(join(evidenceDirectory,name),4*1024*1024);}
  seal(evidenceDirectory);
  writeFileSync(join(directory,'manifest.json'),JSON.stringify(manifest)+'\n',{flag:'wx',mode:0o600});read(join(directory,'manifest.json'),16384);seal(directory);seal(dirname(directory));return loadJournalArchive(directory);
}
export function loadJournalArchive(directory:string):JournalArchive {
  privateDirectory(directory);const manifest=parseArchiveJson(archiveText(read(join(directory,'manifest.json'),16384)));
  if(manifest.schemaVersion!==1||Object.keys(manifest).sort().join(' ')!=='files schemaVersion'||Object.keys(manifest.files).sort().join(' ')!==Object.values(files).sort().join(' ')||readdirSync(directory).sort().join(' ')!==[...Object.values(files),'manifest.json','evidence'].sort().join(' '))throw new Error('invalid/incomplete snapshot archive manifest');
  const rawFiles={} as JournalArchive['rawFiles'],parsed={} as Record<Name,any>;
  for(const [name,file] of Object.entries(files) as [Name,string][]) {
    const raw=read(join(directory,file),(name==='manager'?4:8)*1024*1024),entry=manifest.files[file];
    if(!entry||Object.keys(entry).sort().join(' ')!=='bytes sha256'||entry.sha256!==digest(raw)||entry.bytes!==raw.length)throw new Error('snapshot archive hash mismatch');
    rawFiles[name]=raw.toString('base64url');parsed[name]=parseJournalArchiveFile(name,raw);refuseCredentials(parsed[name]);
  }
  validateJournalEvidence(parsed.evidence,journalRows(parsed.agent,parsed.identity));readJournalEvidenceAttachments(directory,parsed.evidence);
  seal(directory);return {schemaVersion:1,rawFiles,...parsed};
}
export const journalArchiveCommitment=(archive:JournalArchive)=>networkDigest(archive.rawFiles);

/** Exact fixed-name inputs, staged while writers are stopped. Live hashes are rechecked at commit. */
export function readJournalSnapshot(directory:string):JournalArchiveBytes {
  privateDirectory(directory);
  if(readdirSync(directory).sort().join(' ')!==[...Object.values(files),'evidence'].sort().join(' '))throw new Error('exact eight staged snapshot files and evidence directory required');
  return Object.fromEntries((Object.entries(files) as [Name,string][]).map(([name,file])=>[name,read(join(directory,file),(name==='manager'?4:8)*1024*1024)])) as JournalArchiveBytes;
}

/** Fixed flat relative attachments only; no recursive export, hardlinks, symlinks or overwrite. */
export function readJournalEvidenceAttachments(directory:string,manifest:JournalEvidenceManifest):Record<string,Buffer>{
  validateJournalEvidence(manifest);const path=join(directory,'evidence');privateDirectory(path);
  if(readdirSync(path).sort().join(' ')!==Object.keys(manifest.files).sort().join(' '))throw new Error('missing/extra execution evidence files');
  const result:Record<string,Buffer>={};
  for(const [name,entry] of Object.entries(manifest.files)){if(!/^[a-z][a-z0-9-]{0,63}\.json$/.test(name))throw new Error('unsafe execution evidence filename');const raw=read(join(path,name),4*1024*1024);if(raw.length!==entry.bytes||digest(raw)!==entry.sha256)throw new Error('execution evidence hash mismatch');refuseCredentials(parseArchiveJson(archiveText(raw)));result[name]=raw;}
  seal(path);return result;
}
