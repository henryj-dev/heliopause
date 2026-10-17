import { execFileSync, spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";

const cli = resolve("bin/heliopause-pki.ts");
const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

// EKU is compared by openssl's printed name. The dotted OIDs read as IPv4 addresses to the
// public-history leak scan, so they are not written here.
const CLIENT_AUTH = "TLS Web Client Authentication";
const SERVER_AUTH = "TLS Web Server Authentication";

const pki = (...a: string[]) =>
  spawnSync(process.execPath, [cli, ...a], { encoding: "utf8" });

function pkiOk(...a: string[]): void {
  const r = pki(...a);
  assert.equal(r.status, 0, r.stderr);
}

function ekus(ca: string, file: string): string[] {
  const text = execFileSync("openssl", ["x509", "-in", join(ca, file), "-noout", "-text"], { encoding: "utf8" });
  const line = text.split("\n").findIndex((l) => l.includes("X509v3 Extended Key Usage"));
  return (text.split("\n")[line + 1] ?? "").split(",").map((v) => v.trim());
}

const read = (ca: string, file: string) => new X509Certificate(readFileSync(join(ca, file)));

/**
 * Three certificates are short-lived (`--days=10`, inside the 30-day renewal window) and therefore
 * due: operator-alice, relay-gw and operator-shared. `agent-shared` carries the same name as the
 * operator certificate but is issued with the default validity, so it is **not** due. That is what
 * makes "renewing the operator must not touch the agent" observable — `--force` would reissue
 * everything and the agent's change would be indistinguishable from the bug.
 */
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "heliopause-renew-test-"));
  dirs.push(root);
  const ca = join(root, "ca");
  pkiOk("init", ca);
  pkiOk("issue", ca, "alice", "--role=operator", "--days=10");
  pkiOk("issue", ca, "gw", "--role=relay", "--san=10.0.0.5,relay.test", "--days=10");
  pkiOk("issue", ca, "shared", "--role=operator", "--days=10");
  pkiOk("issue", ca, "shared", "--role=agent");
  const bytes = (f: string) => readFileSync(join(ca, f));
  const before = {
    operatorAlice: read(ca, "operator-alice.pem"),
    relay: read(ca, "relay-gw.pem"),
    operatorShared: read(ca, "operator-shared.pem"),
    agentShared: read(ca, "agent-shared.pem"),
    agentSharedBytes: bytes("agent-shared.pem"),
    files: readdirSync(ca).sort(),
  };
  return { ca, before };
}

describe("renew keeps each certificate's role", () => {
  it("reissues operator and relay certificates under their own filenames, role and EKU", () => {
    const { ca, before } = fixture();
    const r = pki("renew", ca);
    assert.equal(r.status, 0, r.stderr);

    // The files that were due are replaced by the same names — not by an agent-* sibling.
    const files = readdirSync(ca);
    for (const f of ["operator-alice.pem", "relay-gw.pem", "operator-shared.pem", "agent-shared.pem"]) {
      assert.ok(files.includes(f), `${f} missing after renew`);
    }
    assert.deepEqual(files.sort(), before.files, "renew must not add or drop any file");
    assert.ok(!files.includes("agent-alice.pem"), "operator-alice was reissued as an agent");
    assert.ok(!files.includes("agent-alice.key"), "operator-alice was reissued as an agent");
    assert.ok(!files.includes("agent-gw.pem"), "relay-gw was reissued as an agent");

    const operator = read(ca, "operator-alice.pem");
    assert.notEqual(operator.serialNumber, before.operatorAlice.serialNumber);
    assert.equal(operator.subject, "CN=alice");
    assert.deepEqual(ekus(ca, "operator-alice.pem"), [CLIENT_AUTH]);
    assert.equal(operator.subjectAltName, undefined);
    assert.equal(operator.ca, false);

    const relay = read(ca, "relay-gw.pem");
    assert.notEqual(relay.serialNumber, before.relay.serialNumber);
    assert.equal(relay.subject, "CN=gw");
    assert.deepEqual(ekus(ca, "relay-gw.pem"), [SERVER_AUTH]);
    assert.match(relay.subjectAltName ?? "", /IP Address:10\.0\.0\.5/);
    assert.match(relay.subjectAltName ?? "", /DNS:relay\.test/);

    // Both chain to the unchanged CA.
    const caCert = read(ca, "ca.pem");
    assert.ok(operator.verify(caCert.publicKey));
    assert.ok(relay.verify(caCert.publicKey));
  });

  it("renewing an operator leaves an agent certificate with the same name alone", () => {
    const { ca, before } = fixture();
    pkiOk("renew", ca);

    const operator = read(ca, "operator-shared.pem");
    assert.notEqual(operator.serialNumber, before.operatorShared.serialNumber);
    assert.deepEqual(ekus(ca, "operator-shared.pem"), [CLIENT_AUTH]);

    const agent = read(ca, "agent-shared.pem");
    assert.equal(agent.serialNumber, before.agentShared.serialNumber);
    assert.ok(readFileSync(join(ca, "agent-shared.pem")).equals(before.agentSharedBytes));
  });

  it("reports nothing due after the due certificates are renewed", () => {
    const { ca, before } = fixture();
    pkiOk("renew", ca);
    // A second pass sees 90-day certificates only: the earlier reissue used the default validity.
    const r = pki("renew", ca);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /nothing due for renewal/);
    assert.notEqual(read(ca, "operator-alice.pem").serialNumber, before.operatorAlice.serialNumber);
  });
});
