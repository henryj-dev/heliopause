import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { activeKey, crumbsFor, isPublicPath, mustChangeRedirect, navGroups } from "./nav.ts";

describe("app nav", () => {
  it("groups the seven screens the classic console also names", () => {
    const groups = navGroups();
    assert.deepEqual(groups.map((g) => g.label), ["fleet", "evidence", "policy"]);
    assert.deepEqual(groups.flatMap((g) => g.items.map((i) => i.key)), [
      "fleet", "changes", "enrollment", "lookup", "traffic", "routing", "policy",
    ]);
  });

  it("shows account to a member and members to an admin only, and leaves them out otherwise", () => {
    const keys = (caller: Parameters<typeof navGroups>[0]) => navGroups(caller).flatMap((g) => g.items.map((i) => i.key));
    assert.deepEqual(keys({ via: "certificate", isAdmin: false }).slice(-2), ["routing", "policy"]);
    assert.deepEqual(keys({ via: "oidc", isAdmin: false }).slice(-2), ["routing", "policy"]);
    assert.deepEqual(keys({ via: "password", isAdmin: false }).slice(-2), ["policy", "account"]);
    assert.deepEqual(keys({ via: "password", isAdmin: true }).slice(-2), ["account", "members"]);
    assert.deepEqual(navGroups({ via: "password", isAdmin: true }).map((g) => g.label), ["fleet", "evidence", "policy", "account"]);
  });

  it("names the pages a signed-out browser uses, and nothing else", () => {
    for (const p of ["/app/login", "/app/invite", "/app/reset"]) {
      assert.equal(isPublicPath(p, "/app"), true, p);
    }
    for (const p of ["/app", "/app/fleet", "/app/account", "/app/members", "/app/login/x", "/app/invite/hpmem_x", "/app/invitex"]) {
      assert.equal(isPublicPath(p, "/app"), false, p);
    }
  });

  it("sends a password that must change to /account, from every other screen only", () => {
    assert.equal(mustChangeRedirect("mustChange", "fleet", "/app"), "/app/account");
    assert.equal(mustChangeRedirect("mustChange", "members", "/app"), "/app/account");
    assert.equal(mustChangeRedirect("mustChange", "account", "/app"), null);
    for (const kind of ["ok", "unauth", "error", "loading"]) assert.equal(mustChangeRedirect(kind, "fleet", "/app"), null, kind);
  });

  it("puts the member screens on their own key", () => {
    assert.equal(activeKey("/app/account", "/app"), "account");
    assert.equal(activeKey("/app/members", "/app"), "members");
    assert.deepEqual(crumbsFor("members", "/app/members", "/app"), ["members"]);
  });

  it("treats /app and /app/policy/files as named places, not queries", () => {
    assert.equal(activeKey("/app", "/app"), "fleet");
    assert.equal(activeKey("/app/", "/app"), "fleet");
    assert.equal(activeKey("/app/policy/files", "/app"), "policy");
    assert.deepEqual(crumbsFor("policy", "/app/policy/files", "/app"), ["policy", "files"]);
    assert.doesNotMatch(crumbsFor("policy", "/app/policy/files", "/app").join("/"), /[?&]s=/);
  });

  it("names a CSR status in the path so a colleague opens the same queue", () => {
    assert.equal(activeKey("/app/enrollment/pending", "/app"), "enrollment");
    assert.deepEqual(crumbsFor("enrollment", "/app/enrollment/pending", "/app"), ["enrollment", "pending"]);
    assert.deepEqual(crumbsFor("enrollment", "/app/enrollment", "/app"), ["enrollment"]);
    assert.doesNotMatch(crumbsFor("enrollment", "/app/enrollment/pending", "/app").join("/"), /[?&]status=/);
  });

  it("names a plan in the path so a colleague can open the same card", () => {
    const hash = "sha256:" + "9f31c0a4" + "0".repeat(52) + "7be2";
    assert.equal(activeKey(`/app/changes/${encodeURIComponent(hash)}`, "/app"), "changes");
    assert.deepEqual(crumbsFor("changes", `/app/changes/${encodeURIComponent(hash)}`, "/app"), [
      "changes",
      "sha256:9f31c0a4…7be2",
    ]);
    assert.deepEqual(crumbsFor("changes", "/app/changes", "/app"), ["changes"]);
  });
});
