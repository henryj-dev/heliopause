import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createJournalArchive, parseArchiveJson } from './network-journal-archive.ts';
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
