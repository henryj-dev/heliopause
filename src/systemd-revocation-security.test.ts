import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const read = (relative: string) => readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");

describe("systemd revocation privilege boundary", () => {
  it("provisions a fixed locked writer identity and a distinct submit-only group", () => {
    const sysusers = read("../packaging/systemd/heliopause-revocations.conf");
    assert.match(sysusers, /^g heliopause-revocations -$/m);
    assert.match(
      sysusers,
      /^u heliopause-revocation-writer - "heliopause monotonic revocation writer" \/var\/lib\/heliopause-revocations \/usr\/sbin\/nologin$/m,
    );

    const writer = read("../packaging/systemd/heliopause-revocation-writer.service");
    assert.match(writer, /^User=heliopause-revocation-writer$/m);
    assert.match(writer, /^Group=heliopause-revocation-writer$/m);
    assert.doesNotMatch(writer, /^DynamicUser=yes$/m);
    assert.match(writer, /^StateDirectory=heliopause-revocations$/m);
    assert.match(writer, /^StateDirectoryMode=0755$/m);
    assert.match(writer, /^CapabilityBoundingSet=$/m);
    assert.match(writer, /^AmbientCapabilities=$/m);
    assert.match(writer, /^RestrictAddressFamilies=AF_UNIX$/m);
    assert.match(writer, /^IPAddressDeny=any$/m);
  });

  it("gives relay only read access to the snapshot and submit access to the socket", () => {
    const socket = read("../packaging/systemd/heliopause-revocation-writer.socket");
    assert.match(socket, /^ListenStream=\/run\/heliopause-revocation-writer\.sock$/m);
    assert.match(socket, /^SocketMode=0660$/m);
    assert.match(socket, /^SocketGroup=heliopause-revocations$/m);

    const relay = read("../packaging/systemd/heliopause-relay.service");
    assert.match(relay, /^DynamicUser=yes$/m);
    assert.match(relay, /^SupplementaryGroups=heliopause-revocations$/m);
    assert.match(
      relay,
      /^Environment=HELIOPAUSE_REVOCATION_FILE=\/var\/lib\/heliopause-revocations\/revocations\.json$/m,
    );
    assert.match(
      relay,
      /^Environment=HELIOPAUSE_REVOCATION_WRITER_SOCKET=\/run\/heliopause-revocation-writer\.sock$/m,
    );
    assert.match(relay, /^ReadOnlyPaths=\/var\/lib\/heliopause-revocations$/m);
    assert.doesNotMatch(relay, /^Bind(?:ReadOnly)?Paths=.*heliopause-revocations/m);
    assert.match(relay, /^StateDirectory=heliopause$/m);

    const relaySource = read("./relay.ts");
    assert.doesNotMatch(relaySource, /writeRevocationSnapshot/);
    assert.match(relaySource, /installRevocationSnapshot/);
  });

  it("documents identity provisioning and initialization before either unit is enabled", () => {
    const docs = read("../packaging/systemd/README.md");
    const sysusers = docs.indexOf("systemd-sysusers /etc/sysusers.d/heliopause-revocations.conf");
    const initialize = docs.indexOf("init /var/lib/heliopause-revocations/revocations.json");
    const socket = docs.indexOf("systemctl enable --now heliopause-revocation-writer.socket");
    const relay = docs.indexOf("systemctl enable --now heliopause-relay");
    assert.ok(sysusers >= 0 && initialize > sysusers && socket > initialize && relay > socket);
  });
});
