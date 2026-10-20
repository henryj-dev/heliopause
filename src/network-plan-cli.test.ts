import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("offline CLI emits a blocked versioned dry-run and rejects apply flags", () => {
  const dir = mkdtempSync(join(tmpdir(), "hp-network-cli-"));
  try {
    const path = join(dir, "input.json");
    writeFileSync(path, JSON.stringify({ id: "review-1", registry: { revision: 0, resources: [] }, expectedRegistryRevision: 0, observations: [], bindings: [], now: Date.parse("2026-01-01T00:00:00Z") }));
    const run = () => spawnSync(process.execPath, ["bin/heliopause-network-plan.ts", path], { encoding: "utf8", timeout: 10000 });
    const first = run();
    assert.equal(first.status, 2, first.stderr);
    const plan = JSON.parse(first.stdout);
    assert.equal(plan.kind, "network-plan");
    assert.equal(plan.schemaVersion, 1);
    assert.equal(plan.mode, "dry-run");
    assert.equal(plan.executable, false);
    assert.ok(plan.blockers.some((b: { code: string }) => b.code === "management-reachability-unknown"));
    assert.equal(run().stdout, first.stdout);
    const apply = spawnSync(process.execPath, ["bin/heliopause-network-plan.ts", path, "--apply"], { encoding: "utf8", timeout: 10000 });
    assert.equal(apply.status, 1);
    assert.equal(apply.stdout, "");
    writeFileSync(path, JSON.stringify({ id: "bad", apply: true }));
    const bad = run();
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /unknown plan input field/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("offline compiler refuses raw secrets and has no apply flag", () => {
  const dir = mkdtempSync(join(tmpdir(), "hp-compile-cli-"));
  try {
    const path = join(dir, "input.json");
    writeFileSync(path, JSON.stringify({ registry: { revision: 0, resources: [] }, expectedRegistryRevision: 0, spec: { schemaVersion: 1, privateKey: "secret-must-not-be-echoed" } }));
    for (const compiler of ["wireguard", "frr"]) {
      const refused = spawnSync(process.execPath, ["bin/heliopause-network-compile.ts", compiler, path], { encoding: "utf8", timeout: 10000 });
      assert.equal(refused.status, 2, refused.stderr);
      assert.equal(JSON.parse(refused.stdout).ok, false);
      assert.doesNotMatch(refused.stdout + refused.stderr, /secret-must-not-be-echoed/);
      const apply = spawnSync(process.execPath, ["bin/heliopause-network-compile.ts", compiler, path, "--apply"], { encoding: "utf8", timeout: 10000 });
      assert.equal(apply.status, 1);
      assert.equal(apply.stdout, "");
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("documented example exposes MTU drift as a blocked update proposal", () => {
  const result = spawnSync(process.execPath, ["bin/heliopause-network-plan.ts", "examples/network-plan.json"], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 2, result.stderr);
  const plan = JSON.parse(result.stdout);
  assert.equal(plan.executable, false);
  assert.deepEqual(plan.proposals.map((p: { resourceId: string; action: string }) => [p.resourceId, p.action]), [["example-interface", "update"]]);
  assert.ok(plan.blockers.some((b: { code: string }) => b.code === "writer-capability-unavailable"));
});

test("unified offline CLI composes both compilers while retaining disabled execution", async () => {
  const {networkLabInput}=await import('../examples/network-lab.ts');
  const dir=mkdtempSync(join(tmpdir(),'hp-unified-cli-'));
  try {
    const path=join(dir,'input.json');writeFileSync(path,JSON.stringify(networkLabInput()));
    const r=spawnSync(process.execPath,['bin/heliopause-network-plan.ts','--unified',path],{encoding:'utf8',timeout:10000});
    assert.equal(r.status,2,r.stderr);const plan=JSON.parse(r.stdout);
    assert.equal(plan.kind,'network-change-set');assert.equal(plan.executable,false);assert.equal(plan.artifacts.length,5);
  }finally{rmSync(dir,{recursive:true,force:true});}
});
