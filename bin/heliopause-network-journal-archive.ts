#!/usr/bin/env node
/** Read-only exact-byte archive plan unless --apply and the expected commitment are supplied. */
import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { readJournalSnapshot, createJournalArchive } from '../src/network-journal-archive.ts';
import { networkDigest } from '../src/network-canonical.ts';
const {values}=parseArgs({options:{snapshot:{type:'string'},output:{type:'string'},'expected-hash':{type:'string'},apply:{type:'boolean',default:false}}});
if(!values.snapshot||!values.output)throw new Error('--snapshot and --output required');
if(resolve(values.snapshot)===resolve(values.output))throw new Error('new distinct archive destination required');
const bytes=readJournalSnapshot(values.snapshot),rawFiles=Object.fromEntries(Object.entries(bytes).map(([name,raw])=>[name,raw.toString('base64url')])),archiveHash=networkDigest(rawFiles);
if(values.apply){
  if(values['expected-hash']!==archiveHash)throw new Error('exact expected archive hash required');
  createJournalArchive(values.output,bytes);
}
console.log(JSON.stringify({readOnly:!values.apply,archiveHash,files:Object.fromEntries(Object.entries(bytes).map(([name,raw])=>[name,{bytes:raw.length}])),scope:'quiescent-without-confirmed-v1',transitionPerformed:false}));
