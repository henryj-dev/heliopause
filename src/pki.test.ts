// PKI policy tests.
//
// These are about what a certificate is *allowed to do*. The relay decides which host an agent is
// by reading its certificate CN, so the shape of these certificates is the boundary the whole
// control channel rests on — a mistake here does not produce a broken handshake, it produces a
// working handshake for the wrong party.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains } from "./test-util.ts";
import {
  wrongCaHint,
  CA_DAYS,
  LEAF_DAYS,
  PkiError,
  RENEW_BEFORE_DAYS,
  certStatus,
  fileBaseFor,
  planCert,
  requiredCerts,
  roleFromFileBase,
  subjectFor,
} from "./pki.ts";

const ext = (lines: string[]) => lines.join("\n");

describe("planCert — roles", () => {
  it("gives the CA the right to sign leaves and nothing else", () => {
    const p = planCert({ name: "heliopause-ca", role: "ca" });
    contains(ext(p.extensions), "CA:TRUE");
    contains(ext(p.extensions), "keyCertSign");
    assert.equal(p.days, CA_DAYS);
  });

  // Without pathlen:0 a leaked leaf that happened to carry CA:TRUE could mint further identities.
  it("forbids the CA from signing another CA", () => {
    contains(ext(planCert({ name: "ca", role: "ca" }).extensions), "pathlen:0");
  });

  it("marks leaves as non-CA, critically", () => {
    for (const role of ["relay", "agent"] as const) {
      const p = planCert({ name: "h", role, sans: role === "relay" ? ["10.0.0.1"] : undefined });
      contains(ext(p.extensions), "basicConstraints=critical,CA:FALSE");
      assert.equal(p.days, LEAF_DAYS);
    }
  });

  // The separation that matters. Whatever an agent accepts as its relay gets to set that host's
  // firewall, so `serverAuth` is not handed out as a side effect of simplifying issuance.
  it("never gives an agent serverAuth", () => {
    const p = planCert({ name: "k3s-01.dev", role: "agent" });
    contains(ext(p.extensions), "extendedKeyUsage=critical,clientAuth");
    assert.ok(!ext(p.extensions).includes("serverAuth"), "an agent must not be able to act as a relay");
  });

  it("never gives a relay clientAuth", () => {
    const p = planCert({ name: "gw", role: "relay", sans: ["10.17.0.1"] });
    contains(ext(p.extensions), "extendedKeyUsage=critical,serverAuth");
    assert.ok(!ext(p.extensions).includes("clientAuth"));
  });
});

describe("planCert — subjectAltName", () => {
  // Modern clients ignore CN for hostname verification. A SAN-less relay certificate is refused by
  // every agent, and the agent has no unverified mode to fall back to.
  it("refuses a relay certificate with no SAN", () => {
    assert.throws(() => planCert({ name: "gw", role: "relay" }), /needs at least one subjectAltName/);
  });

  it("distinguishes IP from DNS SANs", () => {
    const p = planCert({ name: "gw", role: "relay", sans: ["10.17.0.1", "gw.example"] });
    contains(ext(p.extensions), "IP:10.17.0.1");
    contains(ext(p.extensions), "DNS:gw.example");
  });

  // An agent is identified by CN. A SAN on an agent certificate would be a second identity that
  // nothing checks, so it is refused rather than ignored.
  it("refuses a SAN on an agent certificate", () => {
    assert.throws(
      () => planCert({ name: "k3s", role: "agent", sans: ["10.17.0.10"] }),
      /must not carry a subjectAltName/,
    );
  });

  it("refuses a SAN on the CA", () => {
    assert.throws(() => planCert({ name: "ca", role: "ca", sans: ["x"] }), PkiError);
  });
});

describe("subjectFor", () => {
  it("accepts the host ids this fleet uses", () => {
    for (const n of ["k3s-01.dev", "gw-01.dev", "mailer-01.dev", "10.17.0.1"]) {
      assert.equal(subjectFor(n), `/CN=${n}`);
    }
  });

  // The relay compares the heartbeat's `host` against this CN and 403s a mismatch. That comparison
  // is the only thing stopping a valid certificate holder from collecting another host's ruleset,
  // so a CN that could introduce a second RDN would make the subject ambiguous.
  it("refuses characters that would restructure the subject", () => {
    for (const n of ["a,CN=b", "a/CN=b", "a=b", "a b", ""]) {
      assert.throws(() => subjectFor(n), PkiError, `should refuse ${JSON.stringify(n)}`);
    }
  });

  it("refuses a name that is only punctuation at the edges", () => {
    assert.throws(() => subjectFor("-abc"), PkiError);
    assert.throws(() => subjectFor("abc."), PkiError);
  });
});

// A gateway runs the relay *and* its own agent, so it needs two certificates whose CN is the same
// string. Naming files after the CN made the second overwrite the first — and the survivor was the
// agent's `clientAuth` certificate with no SAN, which every agent in the VPC then refuses as a
// relay. The firewall would already be applied, with no way to fetch the fix.
describe("file naming", () => {
  it("keeps a gateway's relay and agent certificates apart", () => {
    const relay = planCert({ name: "gw-01.dev", role: "relay", sans: ["10.17.0.1"] });
    const agent = planCert({ name: "gw-01.dev", role: "agent" });
    assert.equal(relay.name, agent.name, "same CN — that is the situation being handled");
    assert.notEqual(relay.fileBase, agent.fileBase, "but they must not share a filename");
  });

  it("round-trips the role through the filename", () => {
    for (const [name, role] of [["gw-01.dev", "relay"], ["k3s-01.dev", "agent"]] as const) {
      assert.deepEqual(roleFromFileBase(fileBaseFor(name, role)), { name, role });
    }
  });

  // Renewal reads the role from the filename. Guessing it from the certificate's contents would
  // work today and silently hand an agent a serverAuth certificate the first time one arrives from
  // somewhere else.
  it("reports a filename it did not write rather than guessing", () => {
    assert.equal(roleFromFileBase("something-else"), null);
  });
});

describe("certStatus", () => {
  const now = new Date("2026-07-31T00:00:00Z");
  const inDays = (d: number) => new Date(now.getTime() + d * 86_400_000);

  it("is fine well before expiry", () => {
    const s = certStatus("c", inDays(LEAF_DAYS), now);
    assert.equal(s.dueForRenewal, false);
    assert.equal(s.expired, false);
  });

  it("asks for renewal inside the window", () => {
    assert.equal(certStatus("c", inDays(RENEW_BEFORE_DAYS - 1), now).dueForRenewal, true);
  });

  // Expired must also read as due, or `renew` would skip exactly the certificate that needs it.
  it("treats an expired certificate as due", () => {
    const s = certStatus("c", inDays(-1), now);
    assert.equal(s.expired, true);
    assert.equal(s.dueForRenewal, true);
  });
});

describe("requiredCerts", () => {
  // Derived from the site module the publisher renders, so a host cannot be in one and absent from
  // the other. A host with a ruleset and no certificate cannot heartbeat, and a host that cannot
  // heartbeat never receives another generation.
  it("covers every host plus the relay", () => {
    const reqs = requiredCerts(["a", "b"], "gw", ["10.0.0.1"]);
    assert.deepEqual(reqs.map((r) => `${r.role}:${r.name}`), ["relay:gw", "agent:a", "agent:b"]);
  });

  it("refuses a site with no hosts", () => {
    assert.throws(() => requiredCerts([], "gw", ["10.0.0.1"]), /names no hosts/);
  });

  it("refuses a duplicated host", () => {
    assert.throws(() => requiredCerts(["a", "a"], "gw", ["10.0.0.1"]), /twice/);
  });
});

describe("wrongCaHint", () => {
  // The failure this explains: every VPC has a CA named `CN=heliopause-ca`, and they are different
  // keys. Measured 2026-08-10 — dev's CA was issued 2026-07-31, prod's and util's 2026-08-02, three
  // distinct fingerprints. An operator certificate therefore authenticates to exactly one VPC.
  const DIR = "/w/pki";

  it("explains a chain failure against a relay and names the directory that was trusted", () => {
    // Naming the directory matters: the operator's next move is to check *which* ca.pem they used,
    // and the message is the only place that appears.
    const hint = wrongCaHint("SELF_SIGNED_CERT_IN_CHAIN", false, DIR);
    assert.ok(hint.includes(DIR), hint);
    assert.match(hint, /each vpc has its own ca/i);
    assert.match(hint, /--site/, "must point at the path that does work");
  });

  it("also explains the other OpenSSL spelling of the same fault", () => {
    // Node reports this one when the chain is incomplete rather than self-signed. Same cause, same
    // fix; catching only the first spelling would leave half the cases bare.
    assert.notEqual(wrongCaHint("UNABLE_TO_GET_ISSUER_CERT_LOCALLY", false, DIR), "");
  });

  it("says nothing in --site mode", () => {
    // The advice this hint gives is "ask the manager". When the manager is the thing that failed,
    // repeating it sends the operator in a circle.
    assert.equal(wrongCaHint("SELF_SIGNED_CERT_IN_CHAIN", true, DIR), "");
  });

  it("says nothing about an unrelated network error", () => {
    // The known negative. A hint that fires on ECONNREFUSED or ETIMEDOUT would attribute an outage
    // to certificates and send someone to reissue a working one — the exact misdiagnosis this
    // function exists to prevent, inverted.
    for (const code of ["ECONNREFUSED", "ETIMEDOUT", "ENOTFOUND", "ECONNRESET", undefined]) {
      assert.equal(wrongCaHint(code, false, DIR), "", `expected silence for ${code}`);
    }
  });
});
