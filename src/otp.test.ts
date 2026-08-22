// TOTP verification against a fake IdP.
//
// The case worth the file is the pair of 401s. KeyStone answers 401 both for a wrong code and for a
// refused service token, and the two send an operator to completely different places — one retypes
// six digits, the other looks at a mounted secret. A client that reports them the same way makes the
// second failure look like user error for as long as nobody checks.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { statusFor, verifyOtp, type OtpResult } from "./otp.ts";

const OPTS = {
  baseUrl: "https://idp.example.invalid",
  serviceToken: "svc-token",
  userId: "user-1",
  code: "123456",
};

/** An IdP that answers with whatever the test says, and records what it was asked. */
function idp(status: number, body: unknown) {
  const calls: { url: string; auth: string; body: unknown }[] = [];
  const impl = (async (url: string | URL, init?: RequestInit) => {
    calls.push({
      url: String(url),
      auth: String((init?.headers as Record<string, string>)?.authorization ?? ""),
      body: JSON.parse(String(init?.body ?? "{}")),
    });
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const fail = (r: OtpResult) => (r.ok ? assert.fail("expected a refusal") : r);

describe("verifying a one-time code", () => {
  it("accepts a code the IdP confirms — the known positive", async () => {
    const r = await verifyOtp(OPTS, idp(200, { ok: true, verifiedAt: "2026-08-06T00:00:00Z" }).impl);
    assert.equal(r.ok, true);
  });

  it("sends the user id and code to the right path with the service token", async () => {
    const s = idp(200, { ok: true });
    await verifyOtp(OPTS, s.impl);
    assert.equal(s.calls[0]!.url, "https://idp.example.invalid/api/totp/verify");
    assert.equal(s.calls[0]!.auth, "Bearer svc-token");
    assert.deepEqual(s.calls[0]!.body, { userId: "user-1", code: "123456" });
  });

  it("strips whitespace, because people type codes with a space in them", async () => {
    const s = idp(200, { ok: true });
    await verifyOtp({ ...OPTS, code: "123 456" }, s.impl);
    assert.deepEqual((s.calls[0]!.body as { code: string }).code, "123456");
  });

  it("tells a wrong code apart from a refused service token — both are 401", async () => {
    // The whole reason this module exists rather than a fetch at the call site.
    const wrong = fail(await verifyOtp(OPTS, idp(401, { ok: false }).impl));
    assert.equal(wrong.reason, "wrong-code");

    const svc = fail(await verifyOtp(OPTS, idp(401, "unauthorized").impl));
    assert.equal(svc.reason, "service-token");
    assert.match(svc.detail, /service token/);
  });

  it("reports an unenrolled account as its own failure", async () => {
    // Not a wrong code: no amount of retyping fixes it. The person has to enrol at the IdP.
    assert.equal(fail(await verifyOtp(OPTS, idp(404, "TOTP not enrolled").impl)).reason, "not-enrolled");
  });

  it("reports the IdP's rate limit rather than calling it a wrong code", async () => {
    assert.equal(fail(await verifyOtp(OPTS, idp(429, "slow down").impl)).reason, "rate-limited");
  });

  it("refuses a 200 that carries no verdict", async () => {
    // A proxy or error page answering 200 would otherwise approve a firewall change with no code.
    assert.equal(fail(await verifyOtp(OPTS, idp(200, { ok: false }).impl)).reason, "unavailable");
    assert.equal(fail(await verifyOtp(OPTS, idp(200, "<html>hello</html>").impl)).reason, "unavailable");
    assert.equal(fail(await verifyOtp(OPTS, idp(200, {}).impl)).reason, "unavailable");
  });

  it("treats an unreachable IdP as unavailable, never as a wrong code", async () => {
    // Failing the other way would let a network outage look like a refused approval — and then look
    // like a working one the moment somebody retried past it.
    const dead = (async () => { throw new Error("connect ECONNREFUSED"); }) as unknown as typeof fetch;
    const r = fail(await verifyOtp(OPTS, dead));
    assert.equal(r.reason, "unavailable");
    assert.match(r.detail, /ECONNREFUSED/);
  });

  it("refuses to send a code over plaintext", async () => {
    const s = idp(200, { ok: true });
    const r = fail(await verifyOtp({ ...OPTS, baseUrl: "http://idp.example.invalid" }, s.impl));
    assert.equal(r.reason, "unavailable");
    assert.equal(s.calls.length, 0, "nothing may leave the process over plaintext");
  });

  it("rejects a code that cannot be a TOTP without spending the rate limit", async () => {
    const s = idp(200, { ok: true });
    for (const code of ["", "12345", "abcdef", "1234567890"]) {
      assert.equal(fail(await verifyOtp({ ...OPTS, code }, s.impl)).reason, "wrong-code");
    }
    assert.equal(s.calls.length, 0, "the IdP limits attempts per user; do not spend them on nonsense");
  });

  it("accepts eight digits, because some enrolments use them", async () => {
    const s = idp(200, { ok: true });
    assert.equal((await verifyOtp({ ...OPTS, code: "12345678" }, s.impl)).ok, true);
  });
});

describe("mapping a failure to a status", () => {
  it("blames the caller only when it is the caller", () => {
    assert.equal(statusFor("wrong-code"), 401);
    assert.equal(statusFor("not-enrolled"), 403);
    assert.equal(statusFor("rate-limited"), 429);
  });

  it("answers 503 for this deployment's own faults", () => {
    // A retyped code will not fix either of these, and 401 would tell the operator it might.
    assert.equal(statusFor("service-token"), 503);
    assert.equal(statusFor("unavailable"), 503);
  });
});
