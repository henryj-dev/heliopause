import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createJournalArchive, parseArchiveJson, parseReplayJournalJson, parseJournalArchiveFile } from './network-journal-archive.ts';

test('replay counter encoding preserves floating monotonic history and escaped keys',()=>{
 const raw='{"acceptedSequence":1,"terminalSequence":1,"lastClock":9007199254740991,"transactions":{"x":{"mono":1.25,"diagnostic":"lastClock:1e0"}}}';
 assert.deepEqual(parseReplayJournalJson(raw),JSON.parse(raw));
 assert.throws(()=>parseReplayJournalJson('{"lastCl\\u006fck":1e0}'),/integer JSON token/);
 assert.equal(parseArchiveJson('{"lastClock":1e0}').lastClock,1);
 const tx='a'.repeat(32);
 assert.throws(()=>parseReplayJournalJson(JSON.stringify({transactions:{[tx]:{authorization:{values:['integer-array-placeholder']}}}}).replace('"integer-array-placeholder"','1.0')),/integer JSON token/);
 assert.doesNotThrow(()=>parseReplayJournalJson(JSON.stringify({transactions:{[tx]:{history:[{measurements:[1.25]}],mono:1.5}}})));
});
for(const raw of ['{"a":1,"a":2}','{"a":{"escaped":1,"escap\\u0065d":2}}','[{"a":1,"a":2}]'])test('archive refuses duplicate object keys: '+raw,()=>assert.throws(()=>parseArchiveJson(raw),/duplicate archive JSON/));
test('archive parser accepts repeated keys in distinct objects and punctuation inside strings',()=>{
  const value={rows:[{key:'{},:"'},{key:'escaped\\"'}],nested:{value:0.00001},a:true};
  assert.deepEqual(parseArchiveJson(JSON.stringify(value)),value);
});
test('archive parser refuses malformed input and excessive nesting',()=>{
  assert.throws(()=>parseArchiveJson('{"a":}'));
  assert.throws(()=>parseArchiveJson('['.repeat(129)+'0'+']'.repeat(129)),/depth bound/);
});

for(const field of ['privateKey','private_key','password','token','presharedKey'])test('archive refuses credential field before creating any output: '+field,()=>{
 const root=mkdtempSync(join(tmpdir(),'hp-archive-secrets-'));try{
  const values=Object.fromEntries(['manager','agent','identity','outbox','acknowledgments','trust','config'].map(k=>[k,Buffer.from('{}')]));
  values.config=Buffer.from(JSON.stringify({[field]:'synthetic-secret-marker'}));const output=join(root,'archive');
  assert.throws(()=>createJournalArchive(output,values as any),/credential field/);assert.equal(existsSync(output),false);
 }finally{rmSync(root,{recursive:true,force:true});}
});

const utf8Contract=JSON.parse(readFileSync(new URL('../scripts/network-transaction-lab/fixtures/journal-validation-v1.json',import.meta.url),'utf8')).rawUtf8ArchiveCases;
for(const name of ['manager','agent','identity','outbox','acknowledgments','trust','config','evidence'] as const)test('archive refuses malformed UTF-8 before parsing '+name,()=>{
 for(const entry of utf8Contract){const raw=Buffer.from(entry.hex,'hex');if(entry.managerArchiveParserAccepted)assert.deepEqual(parseJournalArchiveFile(name,raw),entry.expected);else assert.throws(()=>parseJournalArchiveFile(name,raw),/UTF-8/);}
});
test('archive preserves valid Unicode including a real replacement character and retains BOM refusal',()=>{
 const value={diagnostic:'replacement \ufffd, 한글, \u{1f680}'};
 assert.deepEqual(parseJournalArchiveFile('agent',Buffer.from(JSON.stringify(value))),value);
 assert.throws(()=>parseJournalArchiveFile('agent',Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from('{}')])));
});
