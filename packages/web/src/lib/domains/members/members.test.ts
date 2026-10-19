import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readAdminWrite, readInviteAccept, readPasswordChange, readReset, repeatProblem } from "./answer.ts";
import { identityPath, linkResult, readLinkStart, readMe, readReauth, readSessions, reauthBody, reauthNeedsOtp, sessionPath } from "./account.ts";
import {
  actionsFor, certCnBody, inviteBody, inviteMailNote, memberPath, otpUserBody, planRequest, readLink, readMembers, rolesBody,
} from "./members.ts";
import { readFragmentToken, resetBody, withoutFragment } from "./token.ts";
import { CSRF_HEADER, writeHeaders } from "./write.ts";

describe("member writes", () => {
  it("carry the manager's CSRF header", () => {
    assert.equal(CSRF_HEADER, "x-heliopause-csrf");
    assert.equal(writeHeaders("tok")[CSRF_HEADER], "tok");
    assert.equal(writeHeaders(null)[CSRF_HEADER], undefined);
  });

  it("send the fields the admin routes accept, roles in store order", () => {
    assert.equal(inviteBody(" a@example.com ", ["admin", "reader"], "123456"),
      JSON.stringify({ email: "a@example.com", roles: ["reader", "admin"], otp: "123456" }));
    assert.equal(rolesBody(["writer", "bogus", "reader"], "1"), JSON.stringify({ roles: ["reader", "writer"], otp: "1" }));
    assert.equal(otpUserBody(" ks-1 ", "1"), JSON.stringify({ otpUserId: "ks-1", otp: "1" }));
    assert.equal(otpUserBody("  ", "1"), JSON.stringify({ otpUserId: null, otp: "1" }));
    assert.equal(otpUserBody(null, "1"), JSON.stringify({ otpUserId: null, otp: "1" }));
    assert.equal(certCnBody({ add: " ops-x " }, "1"), JSON.stringify({ add: "ops-x", otp: "1" }));
    assert.equal(certCnBody({ remove: "ops-x" }, "1"), JSON.stringify({ remove: "ops-x", otp: "1" }));
  });

  it("plans each panel request onto its route, naming the member in the code dialog", () => {
    const m = { id: "0b6f2a4e-1111-4222-8333-444455556666", username: "rita" };
    const reset = planRequest(m, { action: "password-reset" });
    assert.equal(reset.path, `/api/members/${m.id}/password-reset`);
    assert.equal(reset.link, "resetUrl");
    assert.equal(reset.body("9"), JSON.stringify({ otp: "9" }));
    assert.deepEqual(planRequest(m, { action: "delete" }).what, { key: "m.mmWhatDelete", params: { name: "rita" } });
    assert.equal(planRequest(m, { action: "otp-user", otpUserId: null }).what.key, "m.mmWhatOtpClear");
    assert.equal(planRequest(m, { action: "otp-user", otpUserId: "ks" }).what.key, "m.mmWhatOtpSet");
    assert.deepEqual(planRequest(m, { action: "cert-cns", change: { remove: "ops-x" } }).what,
      { key: "m.mmWhatCertRemove", params: { name: "rita", cn: "ops-x" } });
    assert.equal(planRequest(m, { action: "roles", roles: ["reader"] }).link, null);
    assert.equal(memberPath(m.id, "suspend"), `/api/members/${m.id}/suspend`);
  });

  it("offers suspend or lift by status, and nothing on a deleted member", () => {
    assert.ok(actionsFor({ status: "active" }).includes("suspend"));
    assert.ok(!actionsFor({ status: "active" }).includes("unsuspend"));
    assert.ok(actionsFor({ status: "suspended" }).includes("unsuspend"));
    assert.deepEqual(actionsFor({ status: "deleted" }), []);
  });

  it("shows a one-time link only when it is an https URL", () => {
    assert.equal(readLink({ inviteUrl: "https://h.example/app/invite/hpmem_1" }, "inviteUrl"), "https://h.example/app/invite/hpmem_1");
    assert.equal(readLink({ inviteUrl: "javascript:alert(1)" }, "inviteUrl"), null);
    assert.equal(readLink({ resetUrl: "https://h/x" }, "inviteUrl"), null);
  });
});

describe("member admin answers", () => {
  it("names a 409 as a conflict and a 403 as not allowed, keeping the server's words", () => {
    assert.deepEqual(readAdminWrite(409, { error: "would leave no active admin" }),
      { key: "m.mbConflict", detail: "would leave no active admin", problems: [] });
    assert.deepEqual(readAdminWrite(403, { error: "an admin cannot change their own roles" }),
      { key: "m.mbForbidden", detail: "an admin cannot change their own roles", problems: [] });
    assert.equal(readAdminWrite(200, {}), null);
    assert.equal(readAdminWrite(201, {}), null);
    assert.equal(readAdminWrite(503, {})?.key, "m.mbUnavailable");
    assert.equal(readAdminWrite(429, {})?.key, "m.mbTooMany");
  });

  it("lists members with deleted ones last, and skips a row it cannot read", () => {
    const rows = readMembers({ members: [
      { id: "1", username: "gone", status: "deleted" },
      { id: "2", username: "rita", status: "active", roles: ["reader"], certCNs: ["ops-r"], otpUserId: "", hasPassword: true },
      { username: "no-id" },
    ] });
    assert.deepEqual(rows.map((r) => r.username), ["rita", "gone"]);
    assert.equal(rows[0]!.otpUserId, null);
    assert.deepEqual(rows[0]!.certCNs, ["ops-r"]);
    assert.deepEqual(readMembers(null), []);
    assert.deepEqual([rows[0]!.soloApprove, rows[0]!.identities], [false, []]);
  });

  it("offers solo approval for a member who is not deleted, and sends it with the code", () => {
    assert.ok(actionsFor({ status: "active" }).includes("solo-approve"));
    assert.ok(!actionsFor({ status: "deleted" }).includes("solo-approve"));
    const on = planRequest({ id: "m1", username: "wade" }, { action: "solo-approve", soloApprove: true });
    assert.deepEqual([on.path, on.body("123456"), on.what.key], ["/api/members/m1/solo-approve", JSON.stringify({ soloApprove: true, otp: "123456" }), "m.mmWhatSoloOn"]);
    assert.equal(planRequest({ id: "m1", username: "wade" }, { action: "solo-approve", soloApprove: false }).what.key, "m.mmWhatSoloOff");
    const row = readMembers({ members: [{ id: "3", username: "wade", status: "active", soloApprove: true, identities: [{ id: "0123456789abcdef", issuer: "https://idp.example", subject: "…wade" }] }] })[0]!;
    assert.deepEqual([row.soloApprove, row.identities.map((i) => i.subject)], [true, ["…wade"]]);
  });
});

describe("account answers", () => {
  it("reads /api/me with its CSRF token", () => {
    const me = readMe({ username: "rita", principalName: "rita", email: "r@e", roles: ["reader", 3], mustChange: true, otpConfirmedAt: null, csrf: "tok" });
    // An older answer names no via, no hasPassword and no identities: only a password session could read it.
    assert.deepEqual(me, {
      username: "rita", principalName: "rita", email: "r@e", roles: ["reader"], mustChange: true, otpConfirmedAt: null, csrf: "tok",
      via: null, hasPassword: true, identities: [],
    });
    assert.equal(readMe({ username: "rita" }), null);
  });

  it("reads linked identities by their opaque id only, and says when there is no password", () => {
    const me = readMe({
      username: "rita", principalName: "rita", roles: ["reader"], via: "sso", hasPassword: false,
      identities: [
        { id: "0123456789abcdef", issuer: "https://idp.example", subject: "…rita", linkedAt: "t" },
        { id: "../x", issuer: "https://idp.example" },
        { id: "fedcba9876543210" },
      ],
    });
    assert.deepEqual([me?.via, me?.hasPassword], ["sso", false]);
    assert.deepEqual(me?.identities, [{ id: "0123456789abcdef", issuer: "https://idp.example", subject: "…rita", linkedAt: "t" }]);
    assert.equal(identityPath("0123456789abcdef"), "/api/me/identities/0123456789abcdef");
  });

  it("re-authenticates with the password, and with a code for a writer or admin", () => {
    assert.equal(reauthNeedsOtp(["reader"]), false);
    assert.equal(reauthNeedsOtp(["reader", "writer"]), true);
    assert.equal(reauthNeedsOtp(["admin"]), true);
    assert.equal(reauthBody("pw", null), JSON.stringify({ password: "pw" }));
    assert.equal(reauthBody("pw", " 123456 "), JSON.stringify({ password: "pw", otp: "123456" }));
    assert.equal(readReauth(200, {}), null);
    assert.equal(readReauth(403, { error: "the current password is not correct" })?.key, "m.mbCurrentWrong");
    assert.equal(readReauth(403, { error: "linking an SSO account needs a password session — sign in with your password" })?.key, "m.acSsoLinkNeedsPassword");
    assert.equal(readReauth(401, { error: "x" })?.key, "m.loginWrongCode");
    assert.equal(readReauth(409, { error: "x" })?.key, "m.acUnlinkNeedsPassword");
    assert.equal(readReauth(503, {})?.key, "m.mbUnavailable");
  });

  it("goes to the identity provider only by an https location, and reads the callback's link result", () => {
    assert.equal(readLinkStart({ location: "https://idp.example/authorize?x" }), "https://idp.example/authorize?x");
    assert.equal(readLinkStart({ location: "javascript:alert(1)" }), null);
    assert.equal(readLinkStart(null), null);
    assert.deepEqual(linkResult("ok"), { key: "m.acLinked", ok: true });
    assert.deepEqual(linkResult("taken"), { key: "m.acLinkTaken", ok: false });
    assert.deepEqual(linkResult("tombstone"), { key: "m.acLinkTombstone", ok: false });
    assert.deepEqual(linkResult("ended"), { key: "m.acLinkEnded", ok: false });
    assert.deepEqual(linkResult("something"), { key: "m.acLinkFailed", ok: false });
    assert.equal(linkResult(null), null);
  });

  it("reads sessions by their opaque id only", () => {
    const rows = readSessions({ sessions: [
      { id: "0123456789abcdef", createdAt: "a", lastSeenAt: "b", current: true },
      { id: "../../etc", createdAt: "a" },
    ] });
    assert.deepEqual(rows, [{ id: "0123456789abcdef", createdAt: "a", lastSeenAt: "b", current: true }]);
    assert.equal(sessionPath("0123456789abcdef"), "/api/me/sessions/0123456789abcdef");
  });

  it("shows the server's password reasons as sent, and names a wrong current password", () => {
    const refused = readPasswordChange(400, { error: "password refused", problems: ["must be at least 8 characters", 7] });
    assert.deepEqual(refused, { key: "m.mbPasswordRefused", detail: "password refused", problems: ["must be at least 8 characters"] });
    assert.equal(readPasswordChange(403, { error: "x" })?.key, "m.mbCurrentWrong");
    assert.equal(readPasswordChange(200, { ok: true }), null);
  });

  it("checks the repeat, and nothing about length or kinds", () => {
    assert.equal(repeatProblem("", ""), "m.mbPasswordEmpty");
    assert.equal(repeatProblem("abc", "abd"), "m.mbPasswordMismatch");
    assert.equal(repeatProblem("a", "a"), null);
  });
});

describe("token pages", () => {
  it("read a token from the fragment, of the server's shape and nothing else", () => {
    assert.equal(readFragmentToken("#hpmem_0a1b"), "hpmem_0a1b");
    for (const bad of ["", "#", "#a/b", "#a b", `#${"x".repeat(200)}`, "#%2e%2e"]) assert.equal(readFragmentToken(bad), null, bad);
  });

  it("leave the same page without its fragment", () => {
    assert.equal(withoutFragment("/app/invite", ""), "/app/invite");
    assert.equal(withoutFragment("/app/reset", "?lang=ko"), "/app/reset?lang=ko");
  });

  it("send the code on a reset only once the server asked for it", () => {
    assert.equal(resetBody("t", "pw", null), JSON.stringify({ token: "t", password: "pw" }));
    assert.equal(resetBody("t", "pw", "1"), JSON.stringify({ token: "t", password: "pw", otp: "1" }));
  });

  it("map invite and reset refusals", () => {
    assert.equal(readInviteAccept(201, { ok: true }), null);
    assert.equal(readInviteAccept(409, { error: "username is not available" })?.key, "m.mbUsernameTaken");
    assert.equal(readInviteAccept(400, { error: "token is invalid, used, or expired" })?.key, "m.mbLinkInvalid");
    assert.equal(readInviteAccept(400, { error: "password refused", problems: ["p"] })?.key, "m.mbPasswordRefused");
    assert.deepEqual(readReset(401, { needOtp: true }, false), { kind: "needOtp", wrongCode: false });
    assert.deepEqual(readReset(401, { needOtp: true }, true), { kind: "needOtp", wrongCode: true });
    assert.deepEqual(readReset(200, { ok: true }, false), { kind: "done" });
    const r = readReset(403, { error: "not confirmed" }, false);
    assert.equal(r.kind === "refused" && r.refusal.key, "m.mbResetOtpUnconfirmed");
    const c = readReset(409, {}, true);
    assert.equal(c.kind === "refused" && c.refusal.key, "m.mbResetChanged");
  });
});

describe("the invitation's mail note", () => {
  it("says mailed, failed at a step, or no mail set up", () => {
    const at = "2026-10-22T00:00:00.000Z";
    assert.deepEqual(inviteMailNote({ expiresAt: at, mailed: true }), { key: "m.mmInviteMailed", params: { at } });
    assert.deepEqual(inviteMailNote({ expiresAt: at, mailed: false, mailError: "rcpt-to" }), { key: "m.mmInviteMailFailed", params: { at, step: "rcpt-to" } });
    assert.deepEqual(inviteMailNote({ expiresAt: at, mailed: false }), { key: "m.mmInviteNoMail", params: { at } });
    // Refused at the end of the data: delivery cannot be confirmed either way.
    assert.deepEqual(inviteMailNote({ expiresAt: at, mailed: false, mailError: "data-end" }), { key: "m.mmInviteMailUnknown", params: { at } });
    assert.deepEqual(inviteMailNote({ mailed: "true" }), { key: "m.mmInviteNoMail", params: { at: "" } });
    assert.deepEqual(inviteMailNote(null), { key: "m.mmInviteNoMail", params: { at: "" } });
  });
});
