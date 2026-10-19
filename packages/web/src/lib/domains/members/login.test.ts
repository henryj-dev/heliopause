import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  afterSignIn, loginBody, nextStep, readLogin, readMethods, readResetRequest, readSsoOtp, readSsoParam, RESET_REQUEST_PATH, resetRequestBody,
  safeNext, SSO_NOTICE, ssoHref, ssoOtpBody,
} from "./login.ts";

describe("the SSO code step", () => {
  it("reads only the three values the callback sends", () => {
    assert.equal(readSsoParam("otp"), "otp");
    assert.equal(readSsoParam("unlinked"), "unlinked");
    assert.equal(readSsoParam("refused"), "refused");
    assert.equal(readSsoParam("OTP"), null);
    assert.equal(readSsoParam(null), null);
    assert.equal(SSO_NOTICE.unlinked, "m.loginSsoUnlinked");
  });

  it("signs in on 200 with where the login was headed, and otherwise means SSO again", () => {
    assert.equal(ssoOtpBody(" 123456 "), JSON.stringify({ otp: "123456" }));
    assert.deepEqual(readSsoOtp(200, { next: "/app/changes" }), { kind: "signedIn", next: "/app/changes" });
    assert.deepEqual(readSsoOtp(200, {}), { kind: "signedIn", next: null });
    const key = (status: number) => { const a = readSsoOtp(status, { error: "w" }); return a.kind === "refused" ? a.refusal.key : a.kind; };
    assert.equal(key(400), "m.loginSsoRestart");
    assert.equal(key(401), "m.loginSsoRestart");
    assert.equal(key(429), "m.loginTooMany");
    assert.equal(key(503), "m.loginUnavailable");
  });
});

describe("which sign-ins the page offers", () => {
  it("reads only booleans that are true, and offers nothing for an unreadable answer", () => {
    assert.deepEqual(readMethods({ password: true, sso: false }), { password: true, sso: false });
    assert.deepEqual(readMethods({ password: "yes", sso: 1 }), { password: false, sso: false });
    assert.deepEqual(readMethods(null), { password: false, sso: false });
  });
});

describe("the sign-in answers", () => {
  it("signs in, carrying mustChange only when it is true", () => {
    assert.deepEqual(readLogin(200, { you: "rita", mustChange: true }, false), { kind: "signedIn", mustChange: true });
    assert.deepEqual(readLogin(200, { you: "rita", mustChange: "true" }, false), { kind: "signedIn", mustChange: false });
  });

  it("asks for the code on 401 needOtp, and calls it a wrong code only when one was sent", () => {
    assert.deepEqual(readLogin(401, { error: "x", needOtp: true }, false), { kind: "needOtp", wrongCode: false });
    assert.deepEqual(readLogin(401, { error: "x", needOtp: true }, true), { kind: "needOtp", wrongCode: true });
  });

  it("maps each refusal by status, keeping the server's words as detail", () => {
    const key = (status: number, body: unknown = { error: "server words" }) => {
      const a = readLogin(status, body, false);
      return a.kind === "refused" ? [a.refusal.key, a.refusal.detail] : [a.kind, ""];
    };
    assert.deepEqual(key(401), ["m.loginInvalid", "server words"]);
    assert.deepEqual(key(429), ["m.loginTooMany", "server words"]);
    assert.deepEqual(key(403), ["m.loginNoOtpUser", "server words"]);
    assert.deepEqual(key(503), ["m.loginUnavailable", "server words"]);
    assert.deepEqual(key(502), ["m.loginUnavailable", "server words"]);
    assert.deepEqual(key(400), ["m.loginBadInput", "server words"]);
    assert.deepEqual(key(418, null), ["m.mbFailed", ""]);
  });

  it("goes to the code step on needOtp and back to the password on a wrong password", () => {
    assert.equal(nextStep("password", { kind: "needOtp", wrongCode: false }), "otp");
    assert.equal(nextStep("otp", { kind: "needOtp", wrongCode: true }), "otp");
    const invalid = readLogin(401, { error: "invalid" }, true);
    assert.equal(nextStep("otp", invalid), "password");
    assert.equal(nextStep("otp", readLogin(503, {}, true)), "otp");
  });

  it("sends the code only on the code step", () => {
    assert.equal(loginBody("rita", "pw", null), JSON.stringify({ username: "rita", password: "pw" }));
    assert.equal(loginBody("rita", "pw", "123456"), JSON.stringify({ username: "rita", password: "pw", otp: "123456" }));
  });
});

describe("where a sign-in goes next", () => {
  it("keeps a same-origin path", () => {
    assert.equal(safeNext("/app/changes?x=1", "/app"), "/app/changes?x=1");
    assert.equal(safeNext("/policy", "/app"), "/policy");
  });

  it("refuses what the server's safeReturnTo refuses", () => {
    for (const raw of ["https://evil.example/", "//evil.example/", "/\\evil.example", "javascript:alert(1)", "app/fleet", "/auth/login", "", null, `/${"a".repeat(600)}`,
      // The WHATWG URL parser drops tab, LF and CR and reads a backslash as `/`: each is `//evil` to a browser.
      "/\t/evil", "/\n/evil", "/\r\\evil", "/ /evil", "/\u0085/evil", "/\u00a0/evil",
      // Outside ASCII: the server's Location header would throw on these.
      "/a\u200b", "/\u2215evil", "/\uff0fevil"]) {
      assert.equal(safeNext(raw, "/app"), null, String(raw));
    }
  });

  it("refuses the sign-in, invitation and reset pages, which would loop or reopen a used link", () => {
    for (const raw of ["/app/login", "/app/login?next=/x", "/login", "/app/invite/hpmem_1", "/app/reset", "/reset/x"]) {
      assert.equal(safeNext(raw, "/app"), null, raw);
    }
    assert.equal(safeNext("/app/loginx", "/app"), "/app/loginx");
  });

  it("goes to /account while the password must change, whatever next says", () => {
    assert.equal(afterSignIn(true, "/app/changes", "/app"), "/app/account");
    assert.equal(afterSignIn(false, "/app/changes", "/app"), "/app/changes");
    assert.equal(afterSignIn(false, "https://evil.example/", "/app"), "/app/fleet");
    assert.equal(afterSignIn(false, null, "/app"), "/app/fleet");
  });

  it("carries a safe next to SSO and drops an unsafe one", () => {
    assert.equal(ssoHref("/app/fleet", "/app"), "/auth/login?next=%2Fapp%2Ffleet");
    assert.equal(ssoHref("//evil.example", "/app"), "/auth/login");
  });
});

describe("the forgot-password form", () => {
  it("posts the trimmed login to the reset-request route", () => {
    assert.equal(RESET_REQUEST_PATH, "/auth/password/reset-request");
    assert.equal(resetRequestBody("  rita@example.com "), JSON.stringify({ login: "rita@example.com" }));
  });

  it("shows the one confirmation for every 202, whatever the body says", () => {
    for (const body of [{ ok: true }, { ok: false, error: "x" }, null, "text"]) {
      assert.deepEqual(readResetRequest(202, body), { kind: "sent", minutes: null });
    }
  });

  it("takes the link lifetime from the server's answer, and only a positive whole number", () => {
    assert.deepEqual(readResetRequest(202, { ok: true, linkExpiresInMinutes: 30 }), { kind: "sent", minutes: 30 });
    assert.deepEqual(readResetRequest(202, { ok: true, linkExpiresInMinutes: 45 }), { kind: "sent", minutes: 45 });
    for (const m of ["30", 0, -5, 1.5, null]) {
      assert.deepEqual(readResetRequest(202, { linkExpiresInMinutes: m }), { kind: "sent", minutes: null });
    }
  });

  it("maps a refusal by status, never to the confirmation", () => {
    const key = (status: number) => {
      const a = readResetRequest(status, { error: "server words" });
      return a.kind === "refused" ? [a.refusal.key, a.refusal.detail] : [a.kind, ""];
    };
    assert.deepEqual(key(429), ["m.loginTooMany", "server words"]);
    assert.deepEqual(key(400), ["m.loginBadInput", "server words"]);
    assert.deepEqual(key(503), ["m.loginUnavailable", "server words"]);
    assert.deepEqual(key(403), ["m.mbFailed", "server words"]);
    assert.deepEqual(key(200), ["m.mbFailed", "server words"]);
  });
});
