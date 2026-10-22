import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalNetworkJson, networkDigest } from "./network-canonical.ts";

test("evidence canonicalization preserves JSON semantics and sorted object fields", () => {
  assert.equal(canonicalNetworkJson({ z: [true, null, 2], a: "x", absent: undefined }), '{"a":"x","z":[true,null,2]}');
  assert.equal(networkDigest({b:2,a:1}),networkDigest({a:1,b:2}));
  assert.equal(canonicalNetworkJson(Object.assign(Object.create(null),{a:1})), '{"a":1}');
});
test("nonfinite values cannot collide with JSON null in evidence hashes", () => {
  assert.equal(canonicalNetworkJson(null),"null");
  for(const value of [NaN,Infinity,-Infinity]) {
    assert.throws(()=>networkDigest(value),/finite/);
    assert.throws(()=>networkDigest({value}),/finite/);
  }
});
test("sparse or undefined arrays cannot become invalid or misleading canonical evidence", () => {
  for(const value of [Array(2),[undefined],Object.assign([1],{extra:2})]) assert.throws(()=>networkDigest(value),/JSON|dense/);
});
test("custom serializers and non JSON types never run while hashing evidence", () => {
  for(const value of [new Date(),()=>1,Symbol("x"),1n,{toJSON(){throw new Error("called");}}]) assert.throws(()=>networkDigest(value),/JSON|plain/);
  let called=false;assert.throws(()=>networkDigest({get a(){called=true;return 1;}}),/accessor/);assert.equal(called,false);
  assert.throws(()=>networkDigest({[Symbol("hidden")]:1}),/symbol/);
});
test("cycles and excessive depth fail while repeated noncyclic references remain valid", () => {
  const value:{self?:unknown}={};value.self=value;assert.throws(()=>networkDigest(value),/cycles/);
  let deep:unknown=0;for(let i=0;i<66;i++)deep={deep};assert.throws(()=>networkDigest(deep),/depth/);
  const shared={a:1};assert.equal(canonicalNetworkJson([shared,shared]),'[{"a":1},{"a":1}]');
});
