import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArchiveJson } from './network-journal-archive.ts';
for(const raw of ['{"a":1,"a":2}','{"a":{"escaped":1,"escap\\u0065d":2}}','[{"a":1,"a":2}]'])test('archive refuses duplicate object keys: '+raw,()=>assert.throws(()=>parseArchiveJson(raw),/duplicate archive JSON/));
test('archive parser accepts repeated keys in distinct objects and punctuation inside strings',()=>{
  const value={rows:[{key:'{},:"'},{key:'escaped\\"'}],nested:{value:0.00001},a:true};
  assert.deepEqual(parseArchiveJson(JSON.stringify(value)),value);
});
test('archive parser refuses malformed input and excessive nesting',()=>{
  assert.throws(()=>parseArchiveJson('{"a":}'));
  assert.throws(()=>parseArchiveJson('['.repeat(129)+'0'+']'.repeat(129)),/depth bound/);
});
