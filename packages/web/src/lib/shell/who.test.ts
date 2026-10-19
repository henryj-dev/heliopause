import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { loginHref, LOGOUT_PATH, logoutDestination, logoutHeaders, mayLabel, readWho, readWhoRefusal, shouldAskOtp, viaLabel } from "./who.ts";

describe("readWho", () => {
  it("reads the caller the chrome draws", () => {
    const read = readWho({ you: "ops-alice", canWrite: true, csrf: "tok" });
    assert.deepEqual(read, {
      ok: true,
      view: { you: "ops-alice", canWrite: true, csrf: "tok", pendingPlans: 0, pendingCsrs: 0, needsOtp: true, via: null, isAdmin: false },
    });
  });

  it("treats a certificate caller as having no session token", () => {
    const read = readWho({ you: "ops-alice", canWrite: false });
    assert.deepEqual(read, {
      ok: true,
      view: { you: "ops-alice", canWrite: false, csrf: null, pendingPlans: 0, pendingCsrs: 0, needsOtp: true, via: null, isAdmin: false },
    });
  });

  it("keeps a missing pending count as zero, not as unread", () => {
    const counted = readWho({ you: "ops-alice", canWrite: true, pendingPlans: 2, pendingCsrs: 3 });
    const missing = readWho({ you: "ops-alice", canWrite: true });
    const negative = readWho({ you: "ops-alice", canWrite: true, pendingPlans: -1, pendingCsrs: -1 });
    assert.equal(counted.ok && counted.view.pendingPlans, 2);
    assert.equal(counted.ok && counted.view.pendingCsrs, 3);
    assert.equal(missing.ok && missing.view.pendingPlans, 0);
    assert.equal(missing.ok && missing.view.pendingCsrs, 0);
    assert.equal(negative.ok && negative.view.pendingPlans, 0);
    assert.equal(negative.ok && negative.view.pendingCsrs, 0);
  });

  it("asks for a code when otp is configured, and when the field is missing", () => {
    const configured = readWho({ you: "ops-alice", canWrite: true, otp: { issuer: "https://idp.example" } });
    const none = readWho({ you: "ops-alice", canWrite: true, otp: null });
    const missing = readWho({ you: "ops-alice", canWrite: true });
    assert.equal(configured.ok && configured.view.needsOtp, true);
    assert.equal(none.ok && none.view.needsOtp, false);
    assert.equal(missing.ok && missing.view.needsOtp, true);
    assert.equal(shouldAskOtp(null), true);
    assert.equal(shouldAskOtp(none.ok ? none.view : null), false);
  });

  it("treats an empty csrf field as absent, not as a token", () => {
    const read = readWho({ you: "ops-alice", canWrite: true, csrf: "" });
    assert.equal(read.ok && read.view.csrf, null);
  });

  it("reads how the caller signed in and whether they administer members", () => {
    const admin = readWho({ you: "root", canWrite: true, via: "password", isAdmin: true });
    assert.equal(admin.ok && admin.view.via, "password");
    assert.equal(admin.ok && admin.view.isAdmin, true);
    const sso = readWho({ you: "rita", canWrite: false, via: "sso", isAdmin: false });
    assert.equal(sso.ok && sso.view.via, "sso");
    // Only `true` is an admin: a string or a missing field from an older manager is not.
    const loose = readWho({ you: "root", canWrite: true, via: "magic", isAdmin: "yes" });
    assert.equal(loose.ok && loose.view.via, null);
    assert.equal(loose.ok && loose.view.isAdmin, false);
  });

  it("refuses a body that does not name the caller", () => {
    assert.equal(readWho({ canWrite: true }).ok, false);
    assert.equal(readWho({ you: "", canWrite: true }).ok, false);
    assert.equal(readWho({ you: "ops-alice" }).ok, false);
  });
});

describe("the labels the bar draws", () => {
  it("says signed in only when there is a session to end", () => {
    assert.equal(viaLabel("tok"), "signed in");
    assert.equal(viaLabel(null), "client certificate");
    assert.equal(viaLabel("tok", "ko"), "로그인됨");
    assert.equal(viaLabel(null, "ko"), "클라이언트 인증서");
  });

  it("says read-only rather than offering a control that will 403", () => {
    assert.equal(mayLabel(true), "may change the fleet");
    assert.equal(mayLabel(false), "read-only");
    assert.equal(mayLabel(true, "ko"), "함대를 바꿀 수 있다");
    assert.equal(mayLabel(false, "ko"), "읽기 전용");
  });
});

describe("login and logout paths", () => {
  it("posts logout, never navigates to it", () => {
    assert.equal(LOGOUT_PATH, "/auth/logout");
  });

  // ## Where a sign-out lands
  //
  // Destroying this server's cookie ends nothing at the identity provider, and the next
  // authorization request is answered from **its** session — so sign-out then sign-in put the same
  // person back in with no credential asked for. The manager answers with where that session can be
  // ended; this is the parse of that answer.
  it("goes where the manager says the IdP session ends", () => {
    assert.equal(
      logoutDestination({ endSession: "https://idp.example.invalid/oidc/logout?client_id=x" }),
      "https://idp.example.invalid/oidc/logout?client_id=x",
    );
  });

  it("falls back to the login page for every answer that names nowhere", () => {
    // Each of these is a real shape. `null` is a provider offering no end-session endpoint;
    // `undefined` is a manager that predates this and answered 204 with no body; the rest are a
    // proxy or a bug. All of them mean the same thing to a browser whose session is already gone.
    for (const body of [{ endSession: null }, {}, undefined, null, "", [], { endSession: "" }, { endSession: 7 }]) {
      assert.equal(logoutDestination(body), "/", `${JSON.stringify(body)} must land on the login page`);
    }
  });

  it("carries the screen back after login and refuses to leave it raw in the query", () => {
    assert.equal(loginHref("/app/fleet"), "/app/login?next=%2Fapp%2Ffleet");
    assert.equal(loginHref("/app/policy?s=files"), "/app/login?next=%2Fapp%2Fpolicy%3Fs%3Dfiles");
  });

  it("sends the CSRF token with a sign-out when there is one", () => {
    assert.deepEqual(logoutHeaders("tok"), { "x-heliopause-csrf": "tok" });
    assert.deepEqual(logoutHeaders(null), {});
  });
});

describe("readWhoRefusal", () => {
  it("tells a password that must change apart from signed out and from a broken read", () => {
    assert.equal(readWhoRefusal(401, { error: "x" }), "unauth");
    assert.equal(readWhoRefusal(403, { error: "password change required", mustChange: true }), "mustChange");
    assert.equal(readWhoRefusal(403, { error: "not an operator" }), "error");
    assert.equal(readWhoRefusal(403, { mustChange: "true" }), "error");
    assert.equal(readWhoRefusal(503, null), "error");
  });
});
