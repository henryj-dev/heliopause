// The cert-api client, against a fake dispatcher and real key material.
//
// The bundle this fetches becomes a TLS context. A wrong one does not fail here — it fails per
// handshake, later, as an error the client sees and the server says nothing about. So the known
// positive is a real certificate and its real key, and every other case breaks exactly one thing.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CertApiError, MAX_CERT_BUNDLE_BYTES, daysUntilExpiry, fetchCert } from "./cert-api.ts";

const dir = mkdtempSync(join(tmpdir(), "hp-certapi-"));
const run = (...a: string[]) => execFileSync("openssl", a, { cwd: dir, stdio: "pipe" });

// Two unrelated pairs. The second exists only to be mismatched against the first.
for (const n of ["a", "b"]) {
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${n}.key`, "-out", `${n}.pem`,
      "-days", "30", "-subj", `/CN=${n}.example.invalid`);
}
// A third pair, this one carrying SANs — including one entry that is not a DNS name, because
// `subjectAltName` is a display string holding several kinds and only the DNS ones are names a
// caller can be answered for.
run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "san.key", "-out", "san.pem",
    "-days", "30", "-subj", "/CN=first.example.invalid",
    "-addext", "subjectAltName=DNS:Second.example.invalid,DNS:first.example.invalid,IP:10.0.0.1");

const read = (f: string) => readFileSync(join(dir, f), "utf8");
const TOKEN = "stcert_" + "0".repeat(32);
const OPTS = { baseUrl: "https://dispatcher.example.invalid", name: "heliopause-web", token: TOKEN };

/** A dispatcher that answers with whatever the test gives it. */
function server(body: unknown, status = 200) {
  const calls: { url: string; auth: string }[] = [];
  const impl = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ url: String(url), auth: String((init?.headers as Record<string, string>)?.authorization ?? "") });
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

// ## The bundle is bounded
//
// This file's header states the failure direction it chose: if the dispatcher is unreachable the
// manager must still start, because the operator CLI does not need this at all, so a fetch failure
// may cost the browser path and nothing else. That only holds if the failure is a thrown
// `CertApiError` — a pod that runs out of memory reading the answer costs everything.
//
// The read was `res.json()`, which buffers whatever arrives. `AbortSignal.timeout` bounds the
// duration and not the size, and this process holds the artifact signing key in a single pod.
describe("the size of the dispatcher's answer", () => {
  it("refuses a bundle larger than the bound instead of buffering it", async () => {
    const s = server({ cert: "x".repeat(MAX_CERT_BUNDLE_BYTES), key: "y" });
    await assert.rejects(() => fetchCert(OPTS, s.impl), CertApiError);
    await assert.rejects(() => fetchCert(OPTS, s.impl), /exceeds/);
  });

  it("keeps the bound small enough to be one", () => {
    // The test above is written relative to the constant and follows it anywhere; the value is the
    // whole protection. A cert plus a key is a few kilobytes, and a chain with several intermediates
    // is still well under a hundred.
    assert.ok(
      MAX_CERT_BUNDLE_BYTES <= 4 * 1024 * 1024,
      `a certificate bundle is kilobytes; ${MAX_CERT_BUNDLE_BYTES} bytes is not a bound on one`,
    );
  });

  it("still fetches a bundle of ordinary size", async () => {
    // The known positive for the bound. Without it a reader that refused every body would pass the
    // refusal above and take the console's certificate away on every start.
    const s = server({ cert: read("a.pem"), key: read("a.key") });
    assert.match((await fetchCert(OPTS, s.impl)).cert, /BEGIN CERTIFICATE/);
  });
});

describe("fetching the public certificate", () => {
  it("returns a matching cert and key — the known positive", async () => {
    const s = server({ cert: read("a.pem"), key: read("a.key"), chain: "" });
    const b = await fetchCert(OPTS, s.impl);
    assert.match(b.cert, /BEGIN CERTIFICATE/);
    assert.match(b.key, /PRIVATE KEY/);
    assert.match(b.fingerprint, /^[0-9A-F]{2}(:[0-9A-F]{2})+$/, "a fingerprint is what decides a rotation happened");
  });

  it("asks the scoped path with a bearer token", async () => {
    const s = server({ cert: read("a.pem"), key: read("a.key") });
    await fetchCert(OPTS, s.impl);
    assert.equal(s.calls[0]!.url, "https://dispatcher.example.invalid/cert-api/v1/certs/heliopause-web");
    assert.equal(s.calls[0]!.auth, `Bearer ${TOKEN}`);
  });

  it("gives a different fingerprint for a different certificate", async () => {
    // This is what makes rotation detectable without comparing whole PEMs, and what stops the
    // manager rebuilding its TLS context once an hour for no reason.
    const a = await fetchCert(OPTS, server({ cert: read("a.pem"), key: read("a.key") }).impl);
    const b = await fetchCert(OPTS, server({ cert: read("b.pem"), key: read("b.key") }).impl);
    assert.notEqual(a.fingerprint, b.fingerprint);
  });

  it("refuses a key that does not belong to the certificate", async () => {
    // Both halves are individually valid. Node installs this pair into a SecureContext without
    // complaint and every handshake for the name then fails — which reads like a network fault.
    const s = server({ cert: read("a.pem"), key: read("b.key") });
    await assert.rejects(() => fetchCert(OPTS, s.impl), /does not match its certificate/);
  });

  it("refuses a certificate that does not parse", async () => {
    await assert.rejects(
      () => fetchCert(OPTS, server({ cert: "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----", key: read("a.key") }).impl),
      /does not parse/);
  });

  it("refuses a key that does not parse", async () => {
    await assert.rejects(() => fetchCert(OPTS, server({ cert: read("a.pem"), key: "not a key" }).impl), /does not parse/);
  });

  it("refuses to send the token over plaintext", async () => {
    // The response carries a private key, and the request carries a credential that fetches it.
    await assert.rejects(
      () => fetchCert({ ...OPTS, baseUrl: "http://dispatcher.example.invalid" }, server({}).impl), /plaintext/);
  });

  it("refuses a token of the wrong shape before making a request", async () => {
    const s = server({ cert: read("a.pem"), key: read("a.key") });
    await assert.rejects(() => fetchCert({ ...OPTS, token: "hunter2" }, s.impl), /stcert_/);
    assert.equal(s.calls.length, 0, "a malformed token must not be sent anywhere");
  });

  it("says what to check on 401", async () => {
    // The dispatcher answers 401 for revoked, expired and out-of-scope alike. The operator has to
    // be told which three things to look at, because the server cannot say which one it was.
    await assert.rejects(() => fetchCert(OPTS, server({ error: "unauthorized" }, 401).impl),
      /revoked, expired, or not scoped/);
  });

  it("surfaces other HTTP failures with their status", async () => {
    await assert.rejects(() => fetchCert(OPTS, server({}, 503).impl), /answered 503/);
  });

  it("refuses a response with no cert or key", async () => {
    await assert.rejects(() => fetchCert(OPTS, server({ chain: "" }).impl), /no cert\/key/);
  });

  it("carries the HTTP status on the error", async () => {
    await fetchCert(OPTS, server({}, 404).impl).catch((e) => {
      assert.ok(e instanceof CertApiError);
      assert.equal((e as CertApiError).status, 404);
    });
  });
});

describe("expiry", () => {
  it("reports days remaining rather than refusing", async () => {
    // Deliberately not enforced in `fetchCert`: rejecting an expired certificate would take the
    // browser path down at exactly the moment somebody needs the console to find out why renewal
    // stopped. It is reported so a caller can log it.
    //
    // ## Whole days, and this assertion used to allow a fraction
    //
    // It read `d > 29 && d <= 30` against a thirty-day fixture — which passes for `29.99…`, and
    // that value was what the manager printed: `expires in 29.995162037037036 day(s)`. The
    // function floors now, so a certificate with just under thirty days left reports 29.
    const d = daysUntilExpiry(read("a.pem"));
    assert.equal(d, 29, `a 30-day certificate has 29 whole days left, got ${d}`);
    assert.ok(Number.isInteger(d), "the value is printed directly and must be a whole number");
  });

  // Floor rather than round, and the threshold is why. `manager-server.ts` warns at `days <= 15`
  // because cert-manager renews fifteen days out, so the question is "have fifteen whole days of
  // validity gone by without a renewal". Rounding would answer that a day late — 15.6 days left
  // would report 16 and stay quiet — and this alarm is the only thing that says renewal stopped.
  it("floors rather than rounds, so the renewal alarm fires a day early rather than a day late", () => {
    const almost15 = new Date(Date.now() + (30 - 15.6) * 86_400_000);
    assert.equal(daysUntilExpiry(read("a.pem"), almost15), 15);
  });

  it("goes negative once the certificate has expired", () => {
    const far = new Date(Date.now() + 400 * 86_400_000);
    assert.ok(daysUntilExpiry(read("a.pem"), far) < 0);
  });
});

process.on("exit", () => rmSync(dir, { recursive: true, force: true }));

describe("the names a certificate actually carries", () => {
  // ## Why the bundle reports its own SANs
  //
  // The manager's startup line used to print the SNI allowlist introduced as "the public
  // certificate for …". On 2026-08-11 a name was removed from that allowlist; the line changed at
  // once while the certificate in memory kept the name for another hour, and **both teams read the
  // line as the certificate's SAN** and recorded the removal as verified. It was caught by someone
  // noticing the fingerprint had not moved.
  //
  // The two lists are equal almost always. That is what lets the conflation survive: it is only
  // wrong in the window where one of them changed — which is exactly when someone reads the log to
  // find out whether a change landed.

  it("reports the DNS names, lowercased and sorted", async () => {
    // Lowercased because SNI matching is case-insensitive and the allowlist is stored lowercased;
    // comparing the two lists is the point, and a case difference would produce a false mismatch.
    const b = await fetchCert(OPTS, server({ cert: read("san.pem"), key: read("san.key") }).impl);
    assert.deepEqual(b.sans, ["first.example.invalid", "second.example.invalid"]);
  });

  it("drops entries that are not DNS names", async () => {
    // `subjectAltName` reads `DNS:a, IP Address:10.0.0.1`. An IP is not something a caller asks for
    // by SNI, and including it would make the allowlist comparison report a name nobody can use.
    const b = await fetchCert(OPTS, server({ cert: read("san.pem"), key: read("san.key") }).impl);
    assert.ok(!b.sans.some((n) => n.includes("10.0.0.1")), b.sans.join(","));
  });

  it("says [] for a certificate with no subjectAltName rather than failing", async () => {
    // Reporting is not enforcement. A certificate with no SAN is unusual and still serviceable, and
    // taking the manager's public path down over a description would trade a small oddity for an
    // outage.
    const b = await fetchCert(OPTS, server({ cert: read("a.pem"), key: read("a.key") }).impl);
    assert.deepEqual(b.sans, []);
  });
});
