import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { loginHref, LOGOUT_PATH, mayLabel, readWho, shouldAskOtp, viaLabel } from "./who.ts";

describe("readWho", () => {
  it("reads the caller the chrome draws", () => {
    const read = readWho({ you: "ops-henry", canWrite: true, csrf: "tok" });
    assert.deepEqual(read, {
      ok: true,
      view: { you: "ops-henry", canWrite: true, csrf: "tok", pendingPlans: 0, pendingCsrs: 0, needsOtp: true },
    });
  });

  it("treats a certificate caller as having no session token", () => {
    const read = readWho({ you: "ops-henry", canWrite: false });
    assert.deepEqual(read, {
      ok: true,
      view: { you: "ops-henry", canWrite: false, csrf: null, pendingPlans: 0, pendingCsrs: 0, needsOtp: true },
    });
  });

  it("keeps a missing pending count as zero, not as unread", () => {
    const counted = readWho({ you: "ops-henry", canWrite: true, pendingPlans: 2, pendingCsrs: 3 });
    const missing = readWho({ you: "ops-henry", canWrite: true });
    const negative = readWho({ you: "ops-henry", canWrite: true, pendingPlans: -1, pendingCsrs: -1 });
    assert.equal(counted.ok && counted.view.pendingPlans, 2);
    assert.equal(counted.ok && counted.view.pendingCsrs, 3);
    assert.equal(missing.ok && missing.view.pendingPlans, 0);
    assert.equal(missing.ok && missing.view.pendingCsrs, 0);
    assert.equal(negative.ok && negative.view.pendingPlans, 0);
    assert.equal(negative.ok && negative.view.pendingCsrs, 0);
  });

  it("asks for a code when otp is configured, and when the field is missing", () => {
    const configured = readWho({ you: "ops-henry", canWrite: true, otp: { issuer: "https://idp.example" } });
    const none = readWho({ you: "ops-henry", canWrite: true, otp: null });
    const missing = readWho({ you: "ops-henry", canWrite: true });
    assert.equal(configured.ok && configured.view.needsOtp, true);
    assert.equal(none.ok && none.view.needsOtp, false);
    assert.equal(missing.ok && missing.view.needsOtp, true);
    assert.equal(shouldAskOtp(null), true);
    assert.equal(shouldAskOtp(none.ok ? none.view : null), false);
  });

  it("treats an empty csrf field as absent, not as a token", () => {
    const read = readWho({ you: "ops-henry", canWrite: true, csrf: "" });
    assert.equal(read.ok && read.view.csrf, null);
  });

  it("refuses a body that does not name the caller", () => {
    assert.equal(readWho({ canWrite: true }).ok, false);
    assert.equal(readWho({ you: "", canWrite: true }).ok, false);
    assert.equal(readWho({ you: "ops-henry" }).ok, false);
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

  it("carries the screen back after login and refuses to leave it raw in the query", () => {
    assert.equal(loginHref("/app/fleet"), "/auth/login?next=%2Fapp%2Ffleet");
    assert.equal(loginHref("/app/policy?s=files"), "/auth/login?next=%2Fapp%2Fpolicy%3Fs%3Dfiles");
  });
});
