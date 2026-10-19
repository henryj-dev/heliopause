import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readAdminWrite, readInviteAccept, readPasswordChange, readReset, repeatProblem } from "./answer.ts";
import { readMe, readSessions, sessionPath } from "./account.ts";
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
  });
});

describe("account answers", () => {
  it("reads /api/me with its CSRF token", () => {
    const me = readMe({ username: "rita", principalName: "rita", email: "r@e", roles: ["reader", 3], mustChange: true, otpConfirmedAt: null, csrf: "tok" });
    assert.deepEqual(me, { username: "rita", principalName: "rita", email: "r@e", roles: ["reader"], mustChange: true, otpConfirmedAt: null, csrf: "tok" });
    assert.equal(readMe({ username: "rita" }), null);
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
