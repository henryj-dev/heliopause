/** Restricted exact-byte snapshot archive; no secrets/recursive lab copy or ledger mutation. */
import { createHash } from 'node:crypto';
import { constants, openSync, closeSync, fstatSync, lstatSync, fsyncSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, resolve, parse, join } from 'node:path';
import { networkDigest } from './network-canonical.ts';
import type { JournalArchive } from './network-journal-transition.ts';
const files={manager:'manager.json',agent:'transactions.json',identity:'journal-identity.json',outbox:'terminal-results.json',acknowledgments:'terminal-acks.json'} as const;
type Name=keyof typeof files;
export type JournalArchiveBytes=Record<Name,Buffer>;
const digest=(bytes:Buffer)=>createHash('sha256').update(bytes).digest('hex');
function ancestry(path:string):void {
  let current=resolve(path);
  while(true){const s=lstatSync(current);if(s.isSymbolicLink()||!s.isDirectory())throw new Error('archive path symlink/non-directory refused');const parent=dirname(current);if(current===parent)break;current=parent;}
}
function privateDirectory(path:string):void {
  ancestry(path);const s=lstatSync(path);if(s.uid!==process.geteuid?.()||(s.mode&0o777)!==0o700)throw new Error('owned0700 archive directory required');
}
function read(path:string,maximum:number):Buffer {
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{const s=fstatSync(fd);if(!s.isFile()||s.uid!==process.geteuid?.()||(s.mode&0o777)!==0o600||s.nlink!==1||s.size>maximum)throw new Error('bounded owned0600 archive file required');const raw=readFileSync(fd);if(raw.length>maximum)throw new Error('archive file growth bound');fsyncSync(fd);return raw;}finally{closeSync(fd);}
}
function seal(path:string):void {const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);try{fsyncSync(fd);}finally{closeSync(fd);}}
export function createJournalArchive(directory:string,bytes:JournalArchiveBytes):JournalArchive {
  privateDirectory(dirname(resolve(directory)));mkdirSync(directory,{mode:0o700});
  const manifest:{schemaVersion:1;files:Record<string,{sha256:string;bytes:number}>}={schemaVersion:1,files:{}};
  for(const [name,file] of Object.entries(files) as [Name,string][]) {
    const raw=bytes[name];if(!Buffer.isBuffer(raw)||raw.length>(name==='manager'?4:8)*1024*1024)throw new Error('snapshot archive size bound');
    if(/-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----/.test(raw.toString()))throw new Error('private key archive refused');
    writeFileSync(join(directory,file),raw,{flag:'wx',mode:0o600});read(join(directory,file),8*1024*1024);manifest.files[file]={sha256:digest(raw),bytes:raw.length};
  }
  writeFileSync(join(directory,'manifest.json'),JSON.stringify(manifest)+'\n',{flag:'wx',mode:0o600});read(join(directory,'manifest.json'),16384);seal(directory);seal(dirname(directory));return loadJournalArchive(directory);
}
export function loadJournalArchive(directory:string):JournalArchive {
  privateDirectory(directory);const manifest=JSON.parse(read(join(directory,'manifest.json'),16384).toString());
  if(manifest.schemaVersion!==1||Object.keys(manifest).sort().join(' ')!=='files schemaVersion'||Object.keys(manifest.files).sort().join(' ')!==Object.values(files).sort().join(' ')||readdirSync(directory).sort().join(' ')!==[...Object.values(files),'manifest.json'].sort().join(' '))throw new Error('invalid/incomplete snapshot archive manifest');
  const rawFiles={} as JournalArchive['rawFiles'],parsed={} as Record<Name,any>;
  for(const [name,file] of Object.entries(files) as [Name,string][]) {
    const raw=read(join(directory,file),(name==='manager'?4:8)*1024*1024),entry=manifest.files[file];
    if(entry.sha256!==digest(raw)||entry.bytes!==raw.length)throw new Error('snapshot archive hash mismatch');
    rawFiles[name]=raw.toString('base64url');parsed[name]=JSON.parse(raw.toString());
  }
  seal(directory);return {schemaVersion:1,rawFiles,...parsed};
}
export const journalArchiveCommitment=(archive:JournalArchive)=>networkDigest(archive.rawFiles);
