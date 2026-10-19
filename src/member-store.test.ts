import assert from "node:assert/strict";
import { scryptSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import {
  activeMember, bindCertCN, confirmOtp, consumeToken, createMember, deleteMember, emptyMemberDocument, findByCertCN, findByEmail,
  findByIdentity, findByUsername, initializeMemberDocument, issueToken, linkIdentity, loadMemberDocument, MEMBER_TOKEN_PREFIX,
  MemberError, saveMemberDocument, setOtpUserId, setPassword, setRoles, suspendMember, trimLoginAudit, unbindCertCN, unlinkIdentity,
  unsuspendMember, withMemberTransaction, type MemberDocument,
} from "./member-store.ts";

const root = mkdtempSync(join(tmpdir(), "heliopause-members-"));
after(() => rmSync(root, { recursive: true, force: true }));
let counter = 0;
const storePath = (): string => join(root, `members-${++counter}.json`);
const ctx = { actor: "cli" };
const ISS = "https://idp.example.test";
/** A valid encoded hash, made cheaply. The store only checks the format. */
const HASH = `scrypt$1024$8$1$${Buffer.alloc(16, 1).toString("base64url")}$${scryptSync("x", Buffer.alloc(16, 1), 32, { N: 1024 }).toString("base64url")}`;

const refuses = (fn: () => unknown, status: number, pattern?: RegExp): void => {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof MemberError, String(error));
    assert.equal(error.statusCode, status, error.message);
    if (pattern) assert.match(error.message, pattern);
    return true;
  });
};

function withAdmin(): { document: MemberDocument; adminId: string } {
  const document = emptyMemberDocument();
  const admin = createMember(document, { username: "root-admin", status: "active", roles: ["reader", "writer", "admin"] }, ctx);
  return { document, adminId: admin.id };
}

describe("member store file", () => {
  it("init creates an empty schema-1 store and refuses to overwrite it", () => {
    const path = storePath();
    initializeMemberDocument(path);
    assert.deepEqual(loadMemberDocument(path), emptyMemberDocument());
    refuses(() => initializeMemberDocument(path), 400, /refusing to overwrite/);
  });

  it("a missing store is 503 for load and for a transaction, and the transaction does not create it", () => {
    const path = storePath();
    refuses(() => loadMemberDocument(path), 503, /member store is unavailable/);
    refuses(() => withMemberTransaction(path, () => null), 503, /member store is unavailable/);
    assert.equal(existsSync(path), false);
  });

  it("a held lock makes a transaction fail with 503 after waitMs", () => {
    const path = storePath();
    initializeMemberDocument(path);
    writeFileSync(`${path}.lock`, "someone else");
    refuses(() => withMemberTransaction(path, () => null, { waitMs: 50 }), 503, /busy/);
    rmSync(`${path}.lock`);
  });

  it("refuses an unknown top-level field, an unknown member field, and another schemaVersion", () => {
    const path = storePath();
    const { document } = withAdmin();
    const base = JSON.parse(JSON.stringify(document));
    for (const broken of [
      { ...base, extra: [] },
      { ...base, schemaVersion: 2 },
      { ...base, members: [{ ...base.members[0], password: "hunter2" }] },
      { ...base, members: [{ ...base.members[0], status: "banned" }] },
      { ...base, members: [{ ...base.members[0], username: "Root-Admin" }] },
    ]) {
      writeFileSync(path, JSON.stringify(broken));
      refuses(() => loadMemberDocument(path), 400);
    }
  });

  it("a transaction that removes the last active admin is not saved", () => {
    const path = storePath();
    initializeMemberDocument(path);
    withMemberTransaction(path, (document) => {
      createMember(document, { username: "root-admin", status: "active", roles: ["admin"] }, ctx);
    });
    const before = readFileSync(path, "utf8");
    // Bypasses the mutation functions on purpose.
    refuses(() => withMemberTransaction(path, (document) => { document.members[0]!.status = "suspended"; }), 409, /no active admin/);
    assert.equal(readFileSync(path, "utf8"), before);
  });

  it("a transaction whose mutate returns a thenable is not saved", () => {
    const path = storePath();
    initializeMemberDocument(path);
    const before = readFileSync(path, "utf8");
    refuses(() => withMemberTransaction(path, async (document) => {
      createMember(document, { username: "late", roles: ["reader"] }, ctx);
    }), 500, /synchronous/);
    assert.equal(readFileSync(path, "utf8"), before);
  });

  it("a rejected promise from mutate does not become an unhandled rejection", async () => {
    const path = storePath();
    initializeMemberDocument(path);
    const unhandled: unknown[] = [];
    const listener = (reason: unknown): void => { unhandled.push(reason); };
    process.on("unhandledRejection", listener);
    try {
      refuses(() => withMemberTransaction(path, () => Promise.reject(new Error("late failure"))), 500, /synchronous/);
      await new Promise((resolveTick) => setImmediate(resolveTick));
      await new Promise((resolveTick) => setImmediate(resolveTick));
    } finally {
      process.off("unhandledRejection", listener);
    }
    assert.deepEqual(unhandled, []);
  });

  it("refuses a mutation that would write an invalid document, leaving the file unchanged", () => {
    const path = storePath();
    initializeMemberDocument(path);
    const before = readFileSync(path, "utf8");
    refuses(() => withMemberTransaction(path, (document) => {
      document.credentials.push({ memberId: "nobody", kind: "password", hash: HASH, changedAt: new Date().toISOString(), mustChange: false });
    }), 400, /unknown member/);
    assert.equal(readFileSync(path, "utf8"), before);
  });

  it("round-trips a populated document through save and load", () => {
    const path = storePath();
    const { document, adminId } = withAdmin();
    setPassword(document, adminId, HASH, { mustChange: false }, ctx);
    linkIdentity(document, { memberId: adminId, issuer: ISS, subject: "sub-1" }, ctx);
    issueToken(document, { kind: "invite", roles: ["reader"], email: "new@example.com" }, ctx);
    saveMemberDocument(path, document);
    assert.deepEqual(loadMemberDocument(path), document);
  });
});

describe("normalization and uniqueness", () => {
  it("normalizes username with NFKC and lowercase, and principalName defaults to it", () => {
    const document = emptyMemberDocument();
    const member = createMember(document, { username: "Ｈｅｎｒｙ", email: " H@Example.COM ", roles: ["reader"] }, ctx);
    assert.equal(member.username, "henry");
    assert.equal(member.principalName, "henry");
    assert.equal(member.email, "h@example.com");
    assert.equal(findByUsername(document, "HENRY")?.id, member.id);
    assert.equal(findByEmail(document, "h@EXAMPLE.com")?.id, member.id);
  });

  it("refuses names outside the character rule", () => {
    const document = emptyMemberDocument();
    for (const bad of ["a", "-henry", "hen ry", "henry!", "x".repeat(65)]) {
      refuses(() => createMember(document, { username: bad, roles: ["reader"] }, ctx), 400, /username/);
    }
  });

  it("refuses a duplicate username, principalName, email or certificate CN", () => {
    const document = emptyMemberDocument();
    createMember(document, { username: "alice", principalName: "ops-alice", email: "a@example.com", roles: ["reader"], certCNs: ["ops-alice"] }, ctx);
    refuses(() => createMember(document, { username: "ALICE", roles: ["reader"] }, ctx), 409, /username/);
    refuses(() => createMember(document, { username: "bob", principalName: "ops-alice", roles: ["reader"] }, ctx), 409, /principalName/);
    refuses(() => createMember(document, { username: "bob", email: "A@example.com", roles: ["reader"] }, ctx), 409, /email/);
    refuses(() => createMember(document, { username: "bob", roles: ["reader"], certCNs: ["ops-alice"] }, ctx), 409, /CN/);
  });

  it("refuses binding a certificate CN that another member holds", () => {
    const document = emptyMemberDocument();
    const a = createMember(document, { username: "alice", roles: ["reader"] }, ctx);
    const b = createMember(document, { username: "bob", roles: ["reader"] }, ctx);
    bindCertCN(document, a.id, "ops-alice", ctx);
    refuses(() => bindCertCN(document, b.id, "ops-alice", ctx), 409, /another member/);
    assert.equal(findByCertCN(document, "ops-alice")?.id, a.id);
    unbindCertCN(document, a.id, "ops-alice", ctx);
    bindCertCN(document, b.id, "ops-alice", ctx);
    assert.equal(findByCertCN(document, "ops-alice")?.id, b.id);
  });

  it("load refuses a store with a duplicate the mutation functions would have refused", () => {
    const path = storePath();
    const document = emptyMemberDocument();
    const a = createMember(document, { username: "alice", roles: ["reader"], certCNs: ["ops-x"] }, ctx);
    createMember(document, { username: "bob", roles: ["reader"] }, ctx);
    const raw = JSON.parse(JSON.stringify(document));
    raw.members[1].certCNs = ["ops-x"];
    writeFileSync(path, JSON.stringify(raw));
    refuses(() => loadMemberDocument(path), 409, /certificate CN/);
    raw.members[1].certCNs = []; raw.members[1].email = "a@example.com"; raw.members[0].email = "a@example.com";
    writeFileSync(path, JSON.stringify(raw));
    refuses(() => loadMemberDocument(path), 409, /email/);
    assert.ok(a.id);
  });

  it("refuses a principalName equal to another member's certificate CN, in either direction", () => {
    const document = emptyMemberDocument();
    const a = createMember(document, { username: "alice", principalName: "ops-alice", roles: ["reader"], certCNs: ["ops-alice", "ops-shared"] }, ctx);
    refuses(() => createMember(document, { username: "bob", principalName: "ops-shared", roles: ["reader"] }, ctx), 409, /certificate CN/);
    refuses(() => createMember(document, { username: "carol", roles: ["reader"], certCNs: ["ops-alice"] }, ctx), 409, /CN/);
    const b = createMember(document, { username: "bob", principalName: "ops-bob", roles: ["reader"] }, ctx);
    refuses(() => bindCertCN(document, a.id, "ops-bob", ctx), 409, /principalName/);
    // A member's own principalName may be its own CN.
    bindCertCN(document, b.id, "ops-bob", ctx);
  });

  it("load refuses a principalName that is another member's certificate CN", () => {
    const path = storePath();
    const document = emptyMemberDocument();
    createMember(document, { username: "alice", roles: ["reader"] }, ctx);
    createMember(document, { username: "bob", roles: ["reader"] }, ctx);
    const raw = JSON.parse(JSON.stringify(document));
    raw.members[1].certCNs = ["alice"];
    writeFileSync(path, JSON.stringify(raw));
    refuses(() => loadMemberDocument(path), 409, /another member's certificate CN/);
  });

  it("refuses control and bidi characters in an email or subject", () => {
    const { document, adminId } = withAdmin();
    for (const bad of ["a\u0085b@example.com", "a\u202eb@example.com", "a\u2066@example.com"]) {
      refuses(() => createMember(document, { username: "x-user", email: bad, roles: ["reader"] }, ctx), 400, /email/);
    }
    refuses(() => linkIdentity(document, { memberId: adminId, issuer: ISS, subject: "s\u202e" }, ctx), 400, /subject/);
  });

  it("requires a role for an active member", () => {
    const document = emptyMemberDocument();
    refuses(() => createMember(document, { username: "alice", status: "active", roles: [] }, ctx), 400, /role/);
    const invited = createMember(document, { username: "bob", roles: [] }, ctx);
    assert.equal(invited.status, "invited");
  });
});

describe("last-admin protection", () => {
  it("refuses suspending, deleting or demoting the only active admin", () => {
    const { document, adminId } = withAdmin();
    refuses(() => suspendMember(document, adminId, ctx), 409, /no active admin/);
    refuses(() => deleteMember(document, adminId, ctx), 409, /no active admin/);
    refuses(() => setRoles(document, adminId, ["reader", "writer"], ctx), 409, /no active admin/);
    assert.equal(activeMember(document, adminId)?.roles.includes("admin"), true);
  });

  it("allows it once another active admin exists, and a suspended admin does not count", () => {
    const { document, adminId } = withAdmin();
    const second = createMember(document, { username: "second", status: "active", roles: ["admin"] }, ctx);
    suspendMember(document, second.id, ctx);
    refuses(() => setRoles(document, adminId, ["reader"], ctx), 409, /no active admin/);
    unsuspendMember(document, second.id, ctx);
    setRoles(document, adminId, ["reader"], ctx);
    assert.deepEqual(document.members.find((m) => m.id === adminId)?.roles, ["reader"]);
  });

  it("does not block changes to non-admins when no admin exists", () => {
    const document = emptyMemberDocument();
    const reader = createMember(document, { username: "reader", status: "active", roles: ["reader"] }, ctx);
    suspendMember(document, reader.id, ctx);
    assert.equal(reader.status, "suspended");
  });
});

describe("soft delete", () => {
  it("clears personal data and authority, keeps the names, and blocks their reuse", () => {
    const { document } = withAdmin();
    const member = createMember(document, {
      username: "alice", principalName: "ops-alice", email: "a@example.com", emailVerified: true,
      status: "active", roles: ["writer"], soloApprove: true, otpUserId: "kid-1", certCNs: ["ops-alice", "alice-laptop"],
    }, ctx);
    setPassword(document, member.id, HASH, { mustChange: false }, ctx);
    linkIdentity(document, { memberId: member.id, issuer: ISS, subject: "s" }, ctx);
    issueToken(document, { kind: "password-reset", memberId: member.id }, ctx);
    deleteMember(document, member.id, ctx);

    assert.equal(member.status, "deleted");
    assert.deepEqual(
      [member.email, member.emailVerifiedAt, member.certCNs, member.roles, member.soloApprove, member.otpUserId],
      [null, null, [], [], false, null],
    );
    assert.equal(document.credentials.some((c) => c.memberId === member.id), false);
    // The identity stays, as a tombstone bound to the deleted member.
    assert.deepEqual(document.identities.filter((i) => i.memberId === member.id).map((i) => [i.issuer, i.subject]), [[ISS, "s"]]);
    assert.equal(document.tokens.some((t) => t.memberId === member.id), false);
    assert.equal(findByUsername(document, "alice")?.id, member.id);

    refuses(() => createMember(document, { username: "alice", roles: ["reader"] }, ctx), 409, /username/);
    refuses(() => createMember(document, { username: "other", principalName: "ops-alice", roles: ["reader"] }, ctx), 409, /principalName/);
    // The email and the extra CN were released; a CN equal to the kept principalName stays refused.
    createMember(document, { username: "carol", email: "a@example.com", roles: ["reader"], certCNs: ["alice-laptop"] }, ctx);
    refuses(() => createMember(document, { username: "dave", roles: ["reader"], certCNs: ["ops-alice"] }, ctx), 409, /principalName/);
    refuses(() => setPassword(document, member.id, HASH, { mustChange: false }, ctx), 409, /deleted/);
    refuses(() => unsuspendMember(document, member.id, ctx), 409, /deleted/);
  });

  it("removes invites addressed to the deleted member's email", () => {
    const { document } = withAdmin();
    const member = createMember(document, { username: "alice", email: "a@example.com", roles: ["reader"] }, ctx);
    issueToken(document, { kind: "invite", roles: ["reader"], email: "a@example.com" }, ctx);
    const other = issueToken(document, { kind: "invite", roles: ["reader"], email: "b@example.com" }, ctx);
    deleteMember(document, member.id, ctx);
    assert.equal(JSON.stringify(document).includes("a@example.com"), false);
    assert.deepEqual(document.tokens.map((t) => t.id), [other.row.id]);
  });

  it("the deleted shape survives save and load, and a deleted member with an email is refused", () => {
    const path = storePath();
    const { document } = withAdmin();
    const member = createMember(document, { username: "alice", email: "a@example.com", roles: ["reader"] }, ctx);
    deleteMember(document, member.id, ctx);
    saveMemberDocument(path, document);
    const raw = JSON.parse(readFileSync(path, "utf8"));
    raw.members[1].email = "a@example.com";
    writeFileSync(path, JSON.stringify(raw));
    refuses(() => loadMemberDocument(path), 400, /deleted member/);
  });
});

describe("otpUserId confirmation", () => {
  it("starts unconfirmed, is confirmed once, and resets when otpUserId changes or is cleared", () => {
    const { document } = withAdmin();
    const m = createMember(document, { username: "wade", status: "active", roles: ["writer"], otpUserId: "ks-1" }, ctx);
    assert.equal(m.otpConfirmedAt, null);
    confirmOtp(document, m.id, "ks-1", { ...ctx, now: new Date("2026-10-18T00:00:00.000Z") });
    confirmOtp(document, m.id, "ks-1", { ...ctx, now: new Date("2026-10-19T00:00:00.000Z") });
    assert.equal(m.otpConfirmedAt, "2026-10-18T00:00:00.000Z");
    assert.equal(document.audit.filter((a) => a.action === "member.otp.confirmed").length, 1);
    refuses(() => confirmOtp(document, m.id, "ks-other", ctx), 409, /changed/);
    setOtpUserId(document, m.id, "ks-1", ctx);
    assert.notEqual(m.otpConfirmedAt, null, "the same value keeps the confirmation");
    setOtpUserId(document, m.id, "ks-2", ctx);
    assert.equal(m.otpConfirmedAt, null);
    confirmOtp(document, m.id, "ks-2", ctx);
    setOtpUserId(document, m.id, null, ctx);
    assert.equal(m.otpConfirmedAt, null);
  });

  it("load refuses otpConfirmedAt without otpUserId, a deleted member carrying it, and a mistyped value", () => {
    const path = storePath();
    const { document } = withAdmin();
    const m = createMember(document, { username: "wade", status: "active", roles: ["writer"], otpUserId: "ks-1" }, ctx);
    confirmOtp(document, m.id, "ks-1", ctx);
    deleteMember(document, m.id, ctx);
    assert.equal(m.otpConfirmedAt, null);
    saveMemberDocument(path, document);
    const raw = JSON.parse(readFileSync(path, "utf8"));
    raw.members[1].otpConfirmedAt = "2026-10-18T00:00:00.000Z";
    writeFileSync(path, JSON.stringify(raw));
    refuses(() => loadMemberDocument(path), 400, /otpConfirmedAt without an otpUserId/);
    raw.members[1].otpUserId = "ks-1";
    writeFileSync(path, JSON.stringify(raw));
    refuses(() => loadMemberDocument(path), 400, /deleted member/);
    raw.members[1].otpUserId = null; raw.members[1].otpConfirmedAt = null;
    raw.members[0].otpConfirmedAt = 7;
    writeFileSync(path, JSON.stringify(raw));
    refuses(() => loadMemberDocument(path), 400, /otpConfirmedAt is not an ISO timestamp/);
  });

  it("reads a phase-A member without otpConfirmedAt as unconfirmed", () => {
    const path = storePath();
    const { document } = withAdmin();
    saveMemberDocument(path, document);
    const raw = JSON.parse(readFileSync(path, "utf8"));
    delete raw.members[0].otpConfirmedAt;
    writeFileSync(path, JSON.stringify(raw));
    assert.equal(loadMemberDocument(path).members[0]!.otpConfirmedAt, null);
  });

  it("refuses two members with one otpUserId, in a mutation and on load", () => {
    const path = storePath();
    const { document } = withAdmin();
    const a = createMember(document, { username: "anna", status: "active", roles: ["writer"], otpUserId: "ks-1" }, ctx);
    const b = createMember(document, { username: "bert", status: "active", roles: ["writer"] }, ctx);
    refuses(() => createMember(document, { username: "carl", status: "active", roles: ["writer"], otpUserId: "ks-1" }, ctx), 409, /otpUserId/);
    refuses(() => setOtpUserId(document, b.id, "ks-1", ctx), 409, /otpUserId/);
    saveMemberDocument(path, document);
    const raw = JSON.parse(readFileSync(path, "utf8"));
    raw.members.find((m: { id: string }) => m.id === b.id).otpUserId = "ks-1";
    writeFileSync(path, JSON.stringify(raw));
    refuses(() => loadMemberDocument(path), 409, /otpUserId is not unique/);
    deleteMember(document, a.id, ctx);
    setOtpUserId(document, b.id, "ks-1", ctx);
    assert.equal(b.otpUserId, "ks-1", "a deleted member's id is free again");
  });

  it("refuses to leave no admin who can sign in", () => {
    const { document, adminId } = withAdmin();
    setOtpUserId(document, adminId, "ks-root", ctx);
    confirmOtp(document, adminId, "ks-root", ctx);
    const other = createMember(document, { username: "second", status: "active", roles: ["admin"] }, ctx);
    // Another active admin exists, but cannot sign in: it has no confirmed code.
    refuses(() => setOtpUserId(document, adminId, null, ctx), 409, /no admin who can sign in/);
    refuses(() => setOtpUserId(document, adminId, "ks-new", ctx), 409, /no admin who can sign in/);
    refuses(() => suspendMember(document, adminId, ctx), 409, /no admin who can sign in/);
    setOtpUserId(document, other.id, "ks-second", ctx);
    confirmOtp(document, other.id, "ks-second", ctx);
    setOtpUserId(document, adminId, null, ctx);
    assert.equal(document.members.find((m) => m.id === adminId)!.otpUserId, null);
  });
});

describe("audit retention", () => {
  it("a transaction drops audit rows older than a year, of every kind", () => {
    const path = storePath();
    const { document } = withAdmin();
    const now = new Date("2026-10-18T00:00:00.000Z");
    const day = 86_400_000;
    const row = (action: string, ageMs: number) => ({ at: new Date(now.getTime() - ageMs).toISOString(), actor: "cli", action, target: "t", sourceIp: null });
    document.audit = [
      row("member.login", 366 * day), row("member.create", 365 * day + 1), row("member.suspend", 400 * day),
      row("member.login", 365 * day), row("member.create", 364 * day), row("member.delete", 1),
    ];
    saveMemberDocument(path, document);
    withMemberTransaction(path, () => undefined, { now });
    const kept = loadMemberDocument(path).audit.map((a) => [a.action, now.getTime() - Date.parse(a.at)]);
    assert.deepEqual(kept, [["member.login", 365 * day], ["member.create", 364 * day], ["member.delete", 1]]);
  });

  it("trimLoginAudit drops only the oldest sign-in rows beyond the cap", () => {
    const { document } = withAdmin();
    const row = (action: string, target: string) => ({ at: "2026-10-18T00:00:00.000Z", actor: "cli", action, target, sourceIp: null });
    document.audit = [row("member.login", "1"), row("member.create", "c"), row("member.login", "2"), row("member.login", "3"), row("member.login", "4")];
    trimLoginAudit(document, 3);
    assert.deepEqual(document.audit.map((a) => a.target), ["c", "2", "3", "4"]);
  });
});

describe("one-time tokens", () => {
  it("stores only the digest, never the plaintext", () => {
    const path = storePath();
    initializeMemberDocument(path);
    const issued = withMemberTransaction(path, (document) => {
      const member = createMember(document, { username: "alice", status: "active", roles: ["reader"] }, ctx);
      return issueToken(document, { kind: "password-reset", memberId: member.id }, ctx);
    });
    assert.match(issued.token, new RegExp(`^${MEMBER_TOKEN_PREFIX}[0-9a-f]{64}$`));
    const text = readFileSync(path, "utf8");
    assert.equal(text.includes(issued.token), false);
    assert.equal(text.includes(issued.token.slice(MEMBER_TOKEN_PREFIX.length)), false);
    assert.match(text, new RegExp(issued.row.digest));
  });

  it("is single use", () => {
    const { document } = withAdmin();
    const { token } = issueToken(document, { kind: "invite", roles: ["reader"] }, ctx);
    const row = consumeToken(document, { kind: "invite", token }, ctx);
    assert.ok(row.usedAt);
    refuses(() => consumeToken(document, { kind: "invite", token }, ctx), 400, /invalid, used, or expired/);
  });

  it("refuses an expired token and one of another kind", () => {
    const { document, adminId } = withAdmin();
    const now = new Date("2026-10-18T00:00:00.000Z");
    const { token } = issueToken(document, { kind: "password-reset", memberId: adminId }, { ...ctx, now });
    refuses(() => consumeToken(document, { kind: "email-verify", token }, ctx), 400);
    refuses(() => consumeToken(document, { kind: "password-reset", token }, { ...ctx, now: new Date(now.getTime() + 30 * 60_000) }), 400);
    consumeToken(document, { kind: "password-reset", token }, { ...ctx, now: new Date(now.getTime() + 30 * 60_000 - 1) });
  });

  it("issuing a new token of the same kind for the same member invalidates the earlier one", () => {
    const { document, adminId } = withAdmin();
    const first = issueToken(document, { kind: "password-reset", memberId: adminId }, ctx);
    const second = issueToken(document, { kind: "password-reset", memberId: adminId }, ctx);
    refuses(() => consumeToken(document, { kind: "password-reset", token: first.token }, ctx), 400);
    consumeToken(document, { kind: "password-reset", token: second.token }, ctx);
  });

  it("a reissued invite to the same email invalidates the earlier invite", () => {
    const { document } = withAdmin();
    const first = issueToken(document, { kind: "invite", roles: ["reader"], email: "n@example.com" }, ctx);
    issueToken(document, { kind: "invite", roles: ["reader"], email: "N@example.com" }, ctx);
    refuses(() => consumeToken(document, { kind: "invite", token: first.token }, ctx), 400);
  });

  it("refuses a reset token once its member is suspended", () => {
    const { document } = withAdmin();
    const member = createMember(document, { username: "alice", status: "active", roles: ["reader"] }, ctx);
    const { token } = issueToken(document, { kind: "password-reset", memberId: member.id }, ctx);
    suspendMember(document, member.id, ctx);
    refuses(() => consumeToken(document, { kind: "password-reset", token }, ctx), 400);
  });

  it("refuses an invite bound to a member who is no longer invited", () => {
    const { document } = withAdmin();
    const member = createMember(document, { username: "newcomer", roles: ["reader"] }, ctx);
    const { token } = issueToken(document, { kind: "invite", memberId: member.id, roles: ["reader"] }, ctx);
    member.status = "active";
    refuses(() => consumeToken(document, { kind: "invite", token }, ctx), 400);
    member.status = "invited";
    consumeToken(document, { kind: "invite", token }, ctx);
  });

  it("refuses malformed token text without looking anything up", () => {
    const { document } = withAdmin();
    for (const bad of ["", "hpmem_", `hpmem_${"g".repeat(64)}`, `stnode_${"0".repeat(64)}`]) {
      refuses(() => consumeToken(document, { kind: "invite", token: bad }, ctx), 400);
    }
  });

  it("keeps password hashes and token plaintext out of the audit log", () => {
    const { document, adminId } = withAdmin();
    const { token } = issueToken(document, { kind: "password-reset", memberId: adminId }, ctx);
    setPassword(document, adminId, HASH, { mustChange: true }, ctx);
    consumeToken(document, { kind: "password-reset", token }, ctx);
    const audit = JSON.stringify(document.audit);
    assert.equal(audit.includes(token), false);
    assert.equal(audit.includes(HASH), false);
  });
});

describe("linked identities", () => {
  it("keeps a deleted member's identities as tombstones that cannot be linked again", () => {
    const path = storePath();
    const { document, adminId } = withAdmin();
    const gone = createMember(document, { username: "gone", email: "g@example.com", status: "active", roles: ["reader"] }, ctx);
    linkIdentity(document, { memberId: gone.id, issuer: ISS, subject: "sub-gone" }, ctx);
    deleteMember(document, gone.id, ctx);
    // The deleted shape with its identity survives save and load.
    saveMemberDocument(path, document);
    const loaded = loadMemberDocument(path);
    assert.deepEqual(loaded.identities.map((i) => [i.memberId, i.subject]), [[gone.id, "sub-gone"]]);
    // A tombstone identifies no one.
    assert.equal(findByIdentity(loaded, ISS, "sub-gone"), null);
    // Neither another member nor a new one may take it.
    refuses(() => linkIdentity(loaded, { memberId: adminId, issuer: ISS, subject: "sub-gone" }, ctx), 409, /deleted member/);
    const fresh = createMember(loaded, { username: "fresh", email: "g@example.com", status: "active", roles: ["reader"] }, ctx);
    refuses(() => linkIdentity(loaded, { memberId: fresh.id, issuer: ISS, subject: "sub-gone" }, ctx), 409, /deleted member/);
    // The tombstone cannot be removed through the member it names either.
    refuses(() => unlinkIdentity(loaded, { memberId: gone.id, issuer: ISS, subject: "sub-gone" }, ctx), 409, /deleted/);
    // An identity naming no member at all is still refused on load.
    const raw = JSON.parse(readFileSync(path, "utf8"));
    raw.identities[0].memberId = "00000000-0000-4000-8000-000000000000";
    writeFileSync(path, JSON.stringify(raw));
    refuses(() => loadMemberDocument(path), 400, /unknown member/);
  });

  it("refuses linking an identity bound to another member", () => {
    const { document, adminId } = withAdmin();
    const other = createMember(document, { username: "other", status: "active", roles: ["reader"] }, ctx);
    linkIdentity(document, { memberId: adminId, issuer: ISS, subject: "sub-1" }, ctx);
    refuses(() => linkIdentity(document, { memberId: other.id, issuer: ISS, subject: "sub-1" }, ctx), 409, /another member/);
    assert.equal(findByIdentity(document, ISS, "sub-1")?.id, adminId);
    // Same subject at another issuer is a different identity.
    linkIdentity(document, { memberId: other.id, issuer: "https://other.example.test", subject: "sub-1" }, ctx);
  });

  it("refuses removing the last login method of a member without a password", () => {
    const { document, adminId } = withAdmin();
    linkIdentity(document, { memberId: adminId, issuer: ISS, subject: "a" }, ctx);
    linkIdentity(document, { memberId: adminId, issuer: ISS, subject: "b" }, ctx);
    unlinkIdentity(document, { memberId: adminId, issuer: ISS, subject: "a" }, ctx);
    refuses(() => unlinkIdentity(document, { memberId: adminId, issuer: ISS, subject: "b" }, ctx), 409, /last login method/);
    setPassword(document, adminId, HASH, { mustChange: false }, ctx);
    unlinkIdentity(document, { memberId: adminId, issuer: ISS, subject: "b" }, ctx);
    assert.equal(findByIdentity(document, ISS, "b"), null);
  });

  it("refuses an issuer the URL parser would rewrite, or with control or bidi characters", () => {
    const { document, adminId } = withAdmin();
    for (const bad of [` ${ISS}`, `${ISS} `, "https://idp.exa\tmple.test", `${ISS}\u202e`, `${ISS}/x\u0007`, `${ISS}/a b`, "HTTPS://IDP.example.test"]) {
      refuses(() => linkIdentity(document, { memberId: adminId, issuer: bad, subject: "a" }, ctx), 400, /issuer/);
    }
    linkIdentity(document, { memberId: adminId, issuer: ISS, subject: "a" }, ctx);
    linkIdentity(document, { memberId: adminId, issuer: `${ISS}/`, subject: "a" }, ctx);
    linkIdentity(document, { memberId: adminId, issuer: `${ISS}/realms/main`, subject: "a" }, ctx);
    assert.equal(document.identities.length, 3);
  });

  it("refuses a non-https issuer", () => {
    const { document, adminId } = withAdmin();
    refuses(() => linkIdentity(document, { memberId: adminId, issuer: "http://idp.example.test", subject: "a" }, ctx), 400, /https/);
  });
});
