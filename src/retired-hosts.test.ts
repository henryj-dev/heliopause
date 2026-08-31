import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseRetiredHostsDocument, retireHost, withoutRetiredHosts } from "./retired-hosts.ts";

describe("machine-owned retired host policy", () => {
  it("adds one exact canonical hostname, sorts it, and converges on replay", () => {
    const first = retireHost('{"schemaVersion":1,"retiredHosts":[{"hostname":"z.dev","hostLifecycleId":"l-z","externalOperationId":"o-z","retiredAt":"2026-08-31T00:00:00.000Z"}]}', {
      hostname: "a.dev", hostLifecycleId: "l-a", externalOperationId: "o-a", retiredAt: "2026-08-31T00:00:00.000Z",
    });
    assert.equal(first.changed, true);
    assert.deepEqual(parseRetiredHostsDocument(first.content).retiredHosts.map((entry) => entry.hostname), ["a.dev", "z.dev"]);
    const replay = retireHost(first.content, {
      hostname: "a.dev", hostLifecycleId: "l-a", externalOperationId: "o-a", retiredAt: "2026-09-01T00:00:00.000Z",
    });
    assert.equal(replay.changed, false);
    assert.equal(replay.content, first.content);
    assert.throws(() => retireHost(first.content, {
      hostname: "a.dev", hostLifecycleId: "different", externalOperationId: "o-a", retiredAt: "2026-08-31T00:00:00.000Z",
    }), /different lifecycle or operation/);
  });

  it("refuses patterns, non-canonical names, duplicates and unknown schema fields", () => {
    const entry = { hostLifecycleId: "l", externalOperationId: "o", retiredAt: "2026-08-31T00:00:00.000Z" };
    assert.throws(() => retireHost('{"schemaVersion":1,"retiredHosts":[]}', { hostname: "*.dev", ...entry }), /non-canonical/);
    assert.throws(() => parseRetiredHostsDocument('{"schemaVersion":1,"retiredHosts":[{"hostname":"A.dev","hostLifecycleId":"l","externalOperationId":"o","retiredAt":"2026-08-31T00:00:00Z"}]}'), /invalid/);
    assert.throws(() => parseRetiredHostsDocument('{"schemaVersion":1,"retiredHosts":[{"hostname":"a.dev","hostLifecycleId":"l","externalOperationId":"o","retiredAt":"2026-08-31T00:00:00.000Z"},{"hostname":"a.dev","hostLifecycleId":"l","externalOperationId":"o","retiredAt":"2026-08-31T00:00:00.000Z"}]}'), /duplicate/);
    assert.throws(() => parseRetiredHostsDocument('{"schemaVersion":1,"retiredHosts":[],"allow":"*"}'), /expected schemaVersion/);
    assert.throws(() => parseRetiredHostsDocument('{"schemaVersion":1,"retiredHosts":[{"hostname":"a.dev","hostLifecycleId":"../bad","externalOperationId":"o","retiredAt":"2026-08-31T00:00:00.000Z"}]}'), /invalid/);
  });

  it("filters exact ids and leaves similarly named hosts alone", () => {
    const hosts = [{ id: "web-01.dev" }, { id: "web-010.dev" }, { id: "other.dev" }];
    assert.deepEqual(
      withoutRetiredHosts(hosts, { schemaVersion: 1, retiredHosts: [{ hostname: "web-01.dev", hostLifecycleId: "l", externalOperationId: "o", retiredAt: "2026-08-31T00:00:00.000Z" }] }).map((host) => host.id),
      ["web-010.dev", "other.dev"],
    );
  });
});
