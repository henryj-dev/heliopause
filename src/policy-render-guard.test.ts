// The renderer's self-check, exercised with a service account token that exists.
//
// This file exists because of a defect injection result. `policy-render-service.test.ts` starts the
// real process and proves it refuses on a credential-shaped environment variable — but deleting the
// service account token branch broke nothing, because that branch reads
// `/var/run/secrets/kubernetes.io/serviceaccount/token` and no machine running these tests has one.
// The most important check in the file was the one nothing covered.
//
// Splitting the decision out is what makes it reachable. The path comes in as an argument here; the
// entry point passes the real constant and the spawn test proves the entry point calls it. Neither
// test is sufficient alone: this one would pass on a binary that never runs the guard, and that one
// would pass on a guard that ignores the token.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ALLOWED_CREDENTIAL, SERVICE_ACCOUNT_TOKEN, armedReasons } from "./policy-render-guard.ts";

/** A pod spec that got it right: the settings the renderer needs and nothing else. */
const CLEAN = {
  PATH: "/usr/local/bin:/usr/bin",
  HELIOPAUSE_POLICY_SITE: "/policy/dev.ts",
  HELIOPAUSE_POLICY_ALLOW_PATHS: "policies.json,dev.ts",
  HELIOPAUSE_POLICY_RENDER_PORT: "9099",
};

describe("the renderer's guard", () => {
  it("lets a pod with nothing in it start", () => {
    // The known positive. Without it every assertion below passes just as well on a guard that
    // reports everything as armed, which would be a renderer that never starts.
    assert.deepEqual(armedReasons({ env: CLEAN, exists: () => false }), []);
  });

  it("names a service account token that should not be there", () => {
    // `automountServiceAccountToken: false` is one line in a manifest, and a manifest edited by
    // somebody copying the manager's pod spec loses it silently. With the token, code from the
    // policy repository talks to the Kubernetes API as this pod — inside the cluster whose firewall
    // this system governs.
    const dir = mkdtempSync(join(tmpdir(), "hp-sa-"));
    try {
      const token = join(dir, "token");
      writeFileSync(token, "ey.not.a.real.token");
      const armed = armedReasons({ env: CLEAN, serviceAccountTokenFile: token });
      assert.deepEqual(armed, [`service account token at ${token}`]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("defaults to the path kubelet actually projects", () => {
    // The argument exists for testability, and a default that drifted from the real path would make
    // this whole file a test of a path nothing uses.
    assert.equal(SERVICE_ACCOUNT_TOKEN, "/var/run/secrets/kubernetes.io/serviceaccount/token");
    let asked = "";
    armedReasons({ env: CLEAN, exists: (p) => { asked = p; return false; } });
    assert.equal(asked, SERVICE_ACCOUNT_TOKEN);
  });

  it("names any credential-shaped variable, including ones nobody has invented yet", () => {
    const armed = armedReasons({
      env: {
        ...CLEAN,
        HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE: "/signing/artifact-signing.key",
        HELIOPAUSE_OIDC_CLIENT_SECRET_FILE: "/pki/oidc",
        SOME_FUTURE_API_TOKEN: "x",
      },
      exists: () => false,
    });
    assert.deepEqual(armed, [
      "environment HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE",
      "environment HELIOPAUSE_OIDC_CLIENT_SECRET_FILE",
      "environment SOME_FUTURE_API_TOKEN",
    ]);
  });

  it("keeps the one credential that protects it", () => {
    // A guard that refused every variable with TOKEN in the name would make the renderer unable to
    // hold the bearer that authenticates its caller, and the fix an operator would reach for at
    // three in the morning is deleting the guard.
    assert.deepEqual(
      armedReasons({ env: { ...CLEAN, [ALLOWED_CREDENTIAL]: "s3cret" }, exists: () => false }),
      [],
    );
  });

  it("reports names and never values", () => {
    // This message goes to a container log, which is not as private as the secret it is complaining
    // about. A refusal that prints what it found has published it to anybody who can read the log.
    const armed = armedReasons({
      env: { ...CLEAN, DATABASE_PASSWORD: "hunter2-and-this-must-not-appear" },
      exists: () => false,
    });
    assert.deepEqual(armed, ["environment DATABASE_PASSWORD"]);
    assert.ok(!armed.join(" ").includes("hunter2"), "the guard printed a secret's value");
  });
});
