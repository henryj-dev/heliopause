import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { closeSync, ftruncateSync, mkdirSync, mkdtempSync, openSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { planHash, type PlanBundle } from "./bundle.ts";
import { SCHEMA_VERSION } from "./protocol.ts";
import {
  ArtifactSignatureError,
  AuthorizationTimestampIssuer,
  HOST_ARTIFACT_SIGNATURE_DOMAIN,
  HOST_ARTIFACT_ENVELOPE_VERSION,
  MAX_HOST_ARTIFACT_ENVELOPE_BYTES,
  artifactSigningKeyId,
  artifactSigningTrustSummary,
  artifactAuthorizationPayloadHash,
  decodeHostArtifactEnvelope,
  encodeHostArtifactEnvelope,
  signHostArtifactAuthorization,
  signAuthorizedArtifactBundle,
  validateAuthorizedArtifactBundle,
  AUTHORIZED_ARTIFACT_BUNDLE_FILE,
  MAX_AUTHORIZED_ARTIFACT_BUNDLE_BYTES,
  encodeAuthorizedArtifactBundle,
  loadAuthorizedArtifactBundle,
  verifyHostArtifactAuthorization,
  type HostArtifactEnvelope,
  privateKeyFileModeError,
  privateKeyFileOwnerError,
} from "./artifact-signature.ts";

const HOST = "canary-01.dev";
const TARGET = "dev";
const AUTHORIZED = new Date("2026-08-15T00:05:00.000Z");
const EXPIRES = new Date("2026-08-15T00:20:00.000Z");
const NOW = new Date("2026-08-15T00:06:00.000Z");
const RULESET = JSON.stringify({ nftables: [{ add: { table: { family: "inet", name: "heliopause" } } }] });
const WORKLOAD = JSON.stringify({ apiVersion: "v1", kind: "List", items: [] });

const rulesetHash = "sha256:" + createHash("sha256").update(RULESET).digest("hex");
const workloadHash = "sha256:" + createHash("sha256").update(WORKLOAD).digest("hex");

function bundle(): PlanBundle {
  return {
    manifest: {
      generation: "0123456789abcdef",
      issuedAt: "2026-08-15T00:00:00.000Z",
      // The constant, not a literal. This fixture pinned `3` and broke on the bump to 4 — which is a
      // test asserting the version number rather than the behaviour that depends on it.
      schemaVersion: SCHEMA_VERSION,
      hosts: {
        [HOST]: {
          stage: "canary",
          rulesetHash,
          confirmTimeoutSec: 30,
          mustContain: ["baseline:ssh"],
          expectAddrs: ["192.0.2.10"],
          expectFilters: [],
          workload: {
            policiesHash: workloadHash,
            cluster: "dev",
            mustExist: ["apps/hp-dev-p700"],
            confirmTimeoutSec: 180,
            policyCount: 1,
            ingressProtectedSelectors: [{ "k8s:app": "api" }],
            watchSelectors: { namespaces: ["apps"], labels: ["app=api"] },
          },
        },
      },
    },
    rulesets: { [HOST]: RULESET },
    workload: { [HOST]: WORKLOAD },
  };
}

const signing = generateKeyPairSync("ed25519");
const breakGlass = generateKeyPairSync("ed25519");
const wrong = generateKeyPairSync("ed25519");

function envelope(over: Partial<Parameters<typeof signHostArtifactAuthorization>[0]> = {}) {
  return signHostArtifactAuthorization({
    target: TARGET,
    bundle: bundle(),
    host: HOST,
    authorizedAt: AUTHORIZED,
    expiresAt: EXPIRES,
    authorizationMode: "two-person",
    ...over,
  }, signing.privateKey);
}

function verified(e: HostArtifactEnvelope | string = envelope(), over: Partial<Parameters<typeof verifyHostArtifactAuthorization>[1]> = {}) {
  return verifyHostArtifactAuthorization(e, {
    trustedKeys: { manager: [signing.publicKey], breakGlass: [breakGlass.publicKey] },
    expectedTarget: TARGET,
    expectedHost: HOST,
    now: NOW,
    ...over,
  });
}

describe("host artifact authorization envelope", () => {
  it("carries the exact plan receipt and derives it from legacy signed-host bundles", () => {
    const signed = signAuthorizedArtifactBundle({
      target: TARGET, bundle: bundle(), authorizedAt: AUTHORIZED, expiresAt: EXPIRES,
      authorizationMode: "two-person",
    }, signing.privateKey);
    assert.equal(signed.planHash, planHash(TARGET, bundle()));
    assert.throws(() => validateAuthorizedArtifactBundle({
      ...signed, planHash: `sha256:${"0".repeat(64)}`,
    }), /differs from its signed artifacts/);

    const legacy = structuredClone(signed) as unknown as Record<string, unknown>;
    delete legacy.planHash;
    assert.equal(validateAuthorizedArtifactBundle(legacy).planHash, signed.planHash,
      "a rolling upgrade failed to derive the receipt from the signed host payload");
  });

  it("binds the manifest header, exact host entry, ruleset, workload, approval and destination", () => {
    const e = envelope();
    const p = verified(encodeHostArtifactEnvelope(e));

    assert.equal(e.version, HOST_ARTIFACT_ENVELOPE_VERSION);
    assert.equal(p.target, TARGET);
    assert.equal(p.host, HOST);
    assert.equal(p.authorizationMode, "two-person");
    assert.equal(p.authorizedAt, AUTHORIZED.toISOString());
    assert.equal(p.expiresAt, EXPIRES.toISOString());
    assert.match(p.planHash, /^sha256:[0-9a-f]{64}$/);
    assert.match(p.bundleHash, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(p.entry, bundle().manifest.hosts[HOST]);
    assert.deepEqual(Object.keys(p.manifest).sort(), ["generation", "issuedAt", "schemaVersion"]);
    assert.equal("hosts" in p.manifest, false, "one compromised host must not receive fleet inventory");
    assert.equal(p.ruleset, RULESET);
    assert.equal(p.workload, WORKLOAD);
  });

  it("derives keyId from SHA-256 of DER SPKI bytes", () => {
    const spki = signing.publicKey.export({ type: "spki", format: "der" });
    const expected = "sha256:" + createHash("sha256").update(spki).digest("hex");
    assert.equal(artifactSigningKeyId(signing.publicKey), expected);
    assert.equal(envelope().keyId, expected);
  });

  it("issues distinct monotonic milliseconds even when the process clock is fixed", () => {
    const issuer = new AuthorizationTimestampIssuer();
    const fixed = new Date("2026-08-15T00:05:00.000Z");
    assert.equal(issuer.next(fixed).toISOString(), "2026-08-15T00:05:00.000Z");
    assert.equal(issuer.next(fixed).toISOString(), "2026-08-15T00:05:00.001Z");
    assert.equal(issuer.next(new Date("2026-08-14T00:00:00.000Z")).toISOString(), "2026-08-15T00:05:00.002Z");
  });

  it("provides the exact signed-payload digest for durable replay equality", () => {
    const e = envelope();
    assert.equal(
      artifactAuthorizationPayloadHash(e),
      "sha256:" + createHash("sha256").update(Buffer.from(e.payload, "base64url")).digest("hex"),
    );
  });

  it("signs the independently length-framed domain, keyId and exact payload bytes", () => {
    const e = envelope();
    const frame = (bytes: Buffer) => {
      const length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      return Buffer.concat([length, bytes]);
    };
    const payload = Buffer.from(e.payload, "base64url");
    const input = Buffer.concat([
      frame(Buffer.from(HOST_ARTIFACT_SIGNATURE_DOMAIN)),
      frame(Buffer.from(e.keyId)),
      frame(payload),
    ]);
    assert.equal(cryptoVerify(null, input, signing.publicKey, Buffer.from(e.signature, "base64url")), true);
    assert.equal(
      cryptoVerify(
        null,
        Buffer.concat([Buffer.from(HOST_ARTIFACT_SIGNATURE_DOMAIN), Buffer.from(e.keyId), payload]),
        signing.publicKey,
        Buffer.from(e.signature, "base64url"),
      ),
      false,
    );
  });

  it("rejects any relay tampering with signed payload bytes", () => {
    const e = envelope();
    const payload = JSON.parse(Buffer.from(e.payload, "base64url").toString("utf8")) as Record<string, unknown>;
    payload.ruleset = RULESET.replace("heliopause", "attacker");
    const tampered = { ...e, payload: Buffer.from(JSON.stringify(payload)).toString("base64url") };
    assert.throws(() => verified(tampered), /signature is invalid/);
  });

  it("rejects even a valid signature over a non-canonical payload encoding", () => {
    const e = envelope();
    const parsed = JSON.parse(Buffer.from(e.payload, "base64url").toString("utf8"));
    const noncanonical = Buffer.from(JSON.stringify(parsed, null, 2));
    const frame = (bytes: Buffer) => {
      const length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      return Buffer.concat([length, bytes]);
    };
    const input = Buffer.concat([
      frame(Buffer.from(HOST_ARTIFACT_SIGNATURE_DOMAIN)),
      frame(Buffer.from(e.keyId)),
      frame(noncanonical),
    ]);
    const malformed = {
      ...e,
      payload: noncanonical.toString("base64url"),
      signature: cryptoSign(null, input, signing.privateKey).toString("base64url"),
    };
    assert.throws(() => verified(malformed), /not in canonical JSON form/);
  });

  it("rejects a valid envelope when the pinned public key is wrong", () => {
    assert.throws(
      () => verified(envelope(), {
        trustedKeys: { manager: [wrong.publicKey], breakGlass: [breakGlass.publicKey] },
      }),
      /untrusted key/,
    );
  });

  it("rejects expiry at the exact signed instant", () => {
    assert.throws(
      () => verified(envelope(), { now: EXPIRES }),
      /expired/,
    );
  });

  it("rejects an authorization too far in the future", () => {
    const future = envelope({
      authorizedAt: new Date("2026-08-15T00:10:00.000Z"),
      expiresAt: new Date("2026-08-15T00:25:00.000Z"),
    });
    assert.throws(() => verified(future), /from the future/);
  });

  it("rejects a signature valid for another relay target", () => {
    assert.throws(
      () => verified(envelope(), { expectedTarget: "prod" }),
      /target .* does not match/,
    );
  });

  it("rejects a signature valid for another host", () => {
    assert.throws(
      () => verified(envelope(), { expectedHost: "general-01.dev" }),
      /host .* does not match/,
    );
  });

  it("rejects oversized input before base64 decoding", () => {
    const tooLarge = JSON.stringify({
      version: HOST_ARTIFACT_ENVELOPE_VERSION,
      algorithm: "Ed25519",
      keyId: envelope().keyId,
      payload: "A".repeat(MAX_HOST_ARTIFACT_ENVELOPE_BYTES),
      signature: "A".repeat(86),
    });
    assert.throws(() => decodeHostArtifactEnvelope(tooLarge), /exceeds its byte limit/);
  });

  it("rejects unknown envelope fields and non-canonical base64url", () => {
    assert.throws(() => decodeHostArtifactEnvelope({ ...envelope(), relayApproved: true }), /unsupported or missing fields/);
    assert.throws(() => decodeHostArtifactEnvelope({ ...envelope(), signature: envelope().signature + "=" }), /canonical base64url/);
  });

  it("rejects non-Ed25519 signing material", () => {
    const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    assert.throws(
      () => signHostArtifactAuthorization({
        target: TARGET,
        bundle: bundle(),
        host: HOST,
        authorizedAt: AUTHORIZED,
        expiresAt: EXPIRES,
        authorizationMode: "solo-otp",
      }, ec.privateKey),
      (error: unknown) => error instanceof ArtifactSignatureError && /dedicated Ed25519/.test(error.message),
    );
  });

  it("records the explicit emergency break-glass authorization mode", () => {
    const emergency = signHostArtifactAuthorization({
      target: TARGET,
      bundle: bundle(),
      host: HOST,
      authorizedAt: AUTHORIZED,
      expiresAt: EXPIRES,
      authorizationMode: "break-glass",
    }, breakGlass.privateKey);
    assert.equal(verified(emergency).authorizationMode, "break-glass");
  });

  it("does not let online manager and offline emergency keys impersonate each other's mode", () => {
    const falseEmergency = envelope({ authorizationMode: "break-glass" });
    assert.throws(() => verified(falseEmergency), /break-glass authorization was signed by a manager key/);

    const falseApproval = signHostArtifactAuthorization({
      target: TARGET,
      bundle: bundle(),
      host: HOST,
      authorizedAt: AUTHORIZED,
      expiresAt: EXPIRES,
      authorizationMode: "two-person",
    }, breakGlass.privateKey);
    assert.throws(() => verified(falseApproval), /two-person authorization was signed by a break-glass key/);
  });

  it("allows manager rollout windows up to seven days but caps break-glass at 24 hours", () => {
    const managerDay = envelope({ expiresAt: new Date("2026-08-16T00:05:00.000Z") });
    assert.equal(verified(managerDay).authorizationMode, "two-person");

    assert.throws(() => signHostArtifactAuthorization({
      target: TARGET,
      bundle: bundle(),
      host: HOST,
      authorizedAt: AUTHORIZED,
      expiresAt: new Date("2026-08-16T00:05:00.001Z"),
      authorizationMode: "break-glass",
    }, breakGlass.privateKey), /24-hour emergency limit/);

    assert.throws(() => envelope({ expiresAt: new Date("2026-08-15T00:19:59.999Z") }), /shorter than 15 minutes/);
  });

  it("reports labelled trust-ring key ids and a stable configuration digest", () => {
    const a = artifactSigningTrustSummary({
      manager: [signing.publicKey, wrong.publicKey],
      breakGlass: [breakGlass.publicKey],
    });
    const b = artifactSigningTrustSummary({
      manager: [wrong.publicKey, signing.publicKey],
      breakGlass: [breakGlass.publicKey],
    });
    assert.deepEqual(a, b, "key file order must not change trust telemetry");
    assert.deepEqual(a.managerKeyIds, [artifactSigningKeyId(signing.publicKey), artifactSigningKeyId(wrong.publicKey)].sort());
    assert.deepEqual(a.breakGlassKeyIds, [artifactSigningKeyId(breakGlass.publicKey)]);
    assert.match(a.digest, /^sha256:[0-9a-f]{64}$/);

    const moved = artifactSigningTrustSummary({
      manager: [signing.publicKey],
      breakGlass: [breakGlass.publicKey, wrong.publicKey],
    });
    assert.notEqual(moved.digest, a.digest, "moving a key between trust classes must change the digest");
  });

  it("refuses one key appearing in both trust classes", () => {
    assert.throws(
      () => artifactSigningTrustSummary({ manager: [signing.publicKey], breakGlass: [signing.publicKey] }),
      /both trust classes/,
    );
  });

  it("accepts protocol-compatible entries that omit optional expectFilters", () => {
    const withoutOptional = bundle();
    delete withoutOptional.manifest.hosts[HOST]!.expectFilters;
    const signed = signHostArtifactAuthorization({
      target: TARGET,
      bundle: withoutOptional,
      host: HOST,
      authorizedAt: AUTHORIZED,
      expiresAt: EXPIRES,
      authorizationMode: "two-person",
    }, signing.privateKey);
    assert.equal(verified(signed).entry.expectFilters, undefined);
  });
});

describe("private key file permissions", () => {
  // ## Why this is not `mode & 0o077`
  //
  // It was, and it took the manager down. Kubernetes projects a Secret to a non-root process through
  // `fsGroup`: kubelet takes group ownership and adds the group read bit itself, so `defaultMode:
  // 0400` arrives as `0440`. Measured 2026-08-15 on the first rollout of the signing path — mode
  // 0440 owned 10001:10001 with runAsUser = runAsGroup = fsGroup = 10001 — and the process refused a
  // file that nothing but itself could read.
  //
  // The rule now asks the question it meant to ask, and these cases are the boundary of it.
  const ours = 10001;

  it("accepts a key only the owner can read", () => {
    assert.equal(privateKeyFileModeError({ mode: 0o400, gid: ours }, ours), null);
    assert.equal(privateKeyFileModeError({ mode: 0o600, gid: ours }, ours), null);
  });

  it("accepts group read when the group is this process's own", () => {
    // The Kubernetes case. Owner and group are the same identity, so this is no wider than 0400.
    assert.equal(privateKeyFileModeError({ mode: 0o440, gid: ours }, ours), null);
  });

  it("refuses group read by a group this process is not in", () => {
    // The case the relaxation must not swallow: another account's group can read the signing key.
    assert.match(privateKeyFileModeError({ mode: 0o440, gid: 20 }, ours) ?? "", /group this process runs as/);
  });

  it("refuses group write even when the group is ours", () => {
    // Read is unavoidable under fsGroup; write never is. A group that can replace the key chooses
    // what the fleet's firewalls accept.
    assert.match(privateKeyFileModeError({ mode: 0o460, gid: ours }, ours) ?? "", /writable/);
    assert.match(privateKeyFileModeError({ mode: 0o470, gid: ours }, ours) ?? "", /writable/);
  });

  it("refuses anything reachable by other", () => {
    for (const mode of [0o404, 0o402, 0o401, 0o444]) {
      assert.match(privateKeyFileModeError({ mode, gid: ours }, ours) ?? "", /other/);
    }
  });

  it("refuses group read when the process has no gid to compare", () => {
    // `process.getgid` is absent on some platforms. Unknown is not "ours" — the check fails closed.
    assert.match(privateKeyFileModeError({ mode: 0o440, gid: ours }, undefined) ?? "", /group this process runs as/);
  });
});

describe("private key file ownership", () => {
  // `uid !== getuid()` is the workstation rule and it refuses the only shape a Secret has. kubelet
  // writes secret files owned by **root**, takes group ownership for `fsGroup`, and lets the workload
  // read them through the group bit — the same pairing that forced the mode check to accept group
  // read. Measured 2026-08-15: with the mode check fixed, the very next start refused the file for
  // being owned by uid 0.
  it("accepts a key this process owns", () => {
    assert.equal(privateKeyFileOwnerError({ uid: 10001 }, 10001), null);
  });

  it("accepts a root-owned key", () => {
    // Strictly safer than us owning it: root can already read anything here.
    assert.equal(privateKeyFileOwnerError({ uid: 0 }, 10001), null);
  });

  it("refuses a key owned by another unprivileged account", () => {
    // The case worth refusing — that account can rewrite the key and choose what every firewall in
    // the fleet accepts.
    assert.match(privateKeyFileOwnerError({ uid: 1234 }, 10001) ?? "", /owned by this account or by root/);
  });
});

// ── The routing half of a signed entry ──────────────────────────────────────
//
// `planPublish` has emitted `routes` and `routeGuard` since the routing half was written, and this
// validator refused unknown keys, so a host declaring a route produced a manifest entry that could
// not be signed — `payload.entry has unsupported or missing fields`, for the whole generation. It
// went unnoticed because no site module declares an `owner: "heliopause"` route yet, so the path
// existed and had never once run.
//
// The known positive below is therefore the load-bearing test in this section: it is the first time
// a routed entry has gone through the signer at all.

describe("signed routes", () => {
  const routed = (over: Record<string, unknown> = {}) => {
    const b = bundle();
    Object.assign(b.manifest.hosts[HOST]!, {
      routes: [{ dst: "10.17.128.0/18", via: "10.17.0.9" }],
      routeGuard: ["10.17.0.0/16"],
      ...over,
    });
    return b;
  };

  it("carries routes and their guard through signing and verification", () => {
    const p = verified(envelope({ bundle: routed() }));
    assert.deepEqual(p.entry.routes, [{ dst: "10.17.128.0/18", via: "10.17.0.9" }]);
    assert.deepEqual(p.entry.routeGuard, ["10.17.0.0/16"]);
  });

  it("still signs an entry that declares no routes", () => {
    // The other half of the positive: adding the fields must not make them mandatory. Every host in
    // the fleet is this case today.
    const p = verified(envelope());
    assert.equal(p.entry.routes, undefined);
    assert.equal(p.entry.routeGuard, undefined);
  });

  // The guard is the routing half of `mustContain`. A heartbeat proves the *relay* path survived and
  // says nothing about the operator's, so a route that moves the management range confirms cleanly
  // and locks everyone out — with the deadline never firing, because nothing it can see went wrong.
  it("refuses routes with no management guard", () => {
    assert.throws(
      () => envelope({ bundle: routed({ routeGuard: undefined }) }),
      /routeGuard/,
    );
  });

  // `managementGuard` returns `[]` for a baseline whose entries name no source — which is what this
  // site's baseline looks like. An empty guard reaches the applier as a value it would accept and
  // protects nothing, so it is refused where the generation is authorized.
  it("refuses an empty management guard, which protects nothing", () => {
    assert.throws(
      () => envelope({ bundle: routed({ routeGuard: [] }) }),
      /routeGuard is empty/,
    );
  });

  it("refuses a guard with no routes to guard", () => {
    assert.throws(
      () => envelope({ bundle: routed({ routes: undefined }) }),
      /routeGuard travels only with routes/,
    );
  });

  it("refuses a route spec with fields nobody sends", () => {
    // `routesFor` strips the owner and the note deliberately: the owner has already been used as the
    // filter, and the note is prose an operator wrote, which has no business in the input of a
    // process that runs `ip route`.
    assert.throws(
      () => envelope({ bundle: routed({ routes: [{ dst: "10.17.128.0/18", note: "why" }] }) }),
      /unsupported or missing fields/,
    );
  });

  it("refuses a route spec with no destination", () => {
    assert.throws(
      () => envelope({ bundle: routed({ routes: [{ via: "10.17.0.9" }] }) }),
      /unsupported or missing fields/,
    );
  });

  it("bounds how many routes one host may be given", () => {
    const many = Array.from({ length: 65 }, (_, i) => ({ dst: `10.17.${i}.0/24`, via: "10.17.0.9" }));
    assert.throws(() => envelope({ bundle: routed({ routes: many }) }), /1\.\.64/);
  });

  it("refuses a relay that adds a route to a signed entry", () => {
    // The property the whole envelope exists for, stated for this field. A courier that appends a
    // route must not be able to produce something an agent applies.
    const e = envelope({ bundle: routed() });
    const payload = JSON.parse(Buffer.from(e.payload, "base64url").toString("utf8")) as {
      entry: { routes: unknown[] };
    };
    payload.entry.routes.push({ dst: "0.0.0.0/0", via: "203.0.113.1" });
    const tampered = { ...e, payload: Buffer.from(JSON.stringify(payload), "utf8").toString("base64url") };
    assert.throws(() => verified(tampered), /signature is invalid/);
  });
});

// ── The relay's strict validation, and what it binds ──────────────────────────
//
// 🔴 **Eleven branches here had no test at all.** Measured by disabling each one and re-running the
// whole suite — every one survived: the three that bind an envelope to the outer manifest, the
// "one signed planHash" rule, the exact host-set comparison, and the five ruleset/workload hash
// bindings inside `validatePayload`.
//
// `validateAuthorizedArtifactBundle` is what the relay runs on `POST /publish` — network input,
// behind mTLS and a publisher CN, but network input. It deliberately verifies **no signature**; the
// agent does that. So what it is for is exactly these bindings, and they were the untested part.
//
// That also makes them reachable from a test without signing anything: hand the function a bundle
// whose payload has been rewritten, and it will parse and bind-check it.
describe("what the relay's bundle validation actually binds", () => {
  const signed = () => signAuthorizedArtifactBundle(
    { target: TARGET, bundle: bundle(), authorizedAt: AUTHORIZED, expiresAt: EXPIRES, authorizationMode: "two-person" },
    signing.privateKey,
  );

  /**
   * The module's canonical form, written a second time.
   *
   * It is `JSON.stringify` over key-sorted values, six lines, and re-implementing it here is
   * deliberate: if the two ever disagree the module's own canonicality check fires first and says
   * "signed payload is not canonical JSON" — a different, loud message — rather than letting a
   * test pass for the wrong reason.
   */
  const sortKeys = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(sortKeys)
      : v && typeof v === "object"
        ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sortKeys((v as Record<string, unknown>)[k])]))
        : v;

  /** Rewrite one host's signed payload. The signature is left stale on purpose — see above. */
  function withPayload(b: ReturnType<typeof signed>, host: string, mutate: (p: Record<string, unknown>) => void) {
    const clone = structuredClone(b) as unknown as { artifacts: Record<string, HostArtifactEnvelope> };
    const env = clone.artifacts[host]!;
    const payload = JSON.parse(Buffer.from(env.payload, "base64url").toString("utf8")) as Record<string, unknown>;
    mutate(payload);
    env.payload = Buffer.from(JSON.stringify(sortKeys(payload)), "utf8").toString("base64url");
    return clone;
  }

  it("accepts what it signed — the known positive", () => {
    assert.equal(validateAuthorizedArtifactBundle(signed()).manifest.generation, "0123456789abcdef");
  });

  // ── binding to the outer manifest ───────────────────────────────────────────

  it("refuses an envelope that names a different generation", () => {
    // The replay shape: last week's still-unexpired envelope re-served under this week's header.
    const b = withPayload(signed(), HOST, (p) => {
      (p.manifest as Record<string, unknown>).generation = "ffffffffffffffff";
    });
    assert.throws(() => validateAuthorizedArtifactBundle(b), /does not bind the outer manifest/);
  });

  it("refuses an envelope that names a different issuedAt", () => {
    const b = withPayload(signed(), HOST, (p) => {
      (p.manifest as Record<string, unknown>).issuedAt = "2026-01-01T00:00:00.000Z";
    });
    assert.throws(() => validateAuthorizedArtifactBundle(b), /does not bind the outer manifest/);
  });

  it("refuses an envelope filed under a host it was not signed for", () => {
    const b = withPayload(signed(), HOST, (p) => { p.host = "somebody-else.dev"; });
    assert.throws(() => validateAuthorizedArtifactBundle(b), /does not bind the outer manifest/);
  });

  // ── the host set, and one plan ──────────────────────────────────────────────

  it("refuses a bundle carrying an artifact its manifest does not name", () => {
    const b = structuredClone(signed()) as unknown as { artifacts: Record<string, unknown> };
    b.artifacts["stowaway.dev"] = b.artifacts[HOST];
    assert.throws(() => validateAuthorizedArtifactBundle(b), /hosts do not exactly match/);
  });

  it("refuses a bundle missing an artifact its manifest names", () => {
    const b = structuredClone(signed()) as unknown as { artifacts: Record<string, unknown> };
    delete b.artifacts[HOST];
    assert.throws(() => validateAuthorizedArtifactBundle(b), /hosts do not exactly match/);
  });

  // 🔴 A receipt that is merely *shaped* like a digest is not a receipt. This binding — planHash
  // over the target and the bundle's own hash — is what makes it one, and it fires before the
  // agreement rule below.
  it("refuses a planHash that does not bind its target and bundle", () => {
    const b = withPayload(signed(), HOST, (p) => { p.planHash = `sha256:${"a".repeat(64)}`; });
    assert.throws(() => validateAuthorizedArtifactBundle(b), /planHash does not bind its target and bundleHash/);
  });

  it("refuses artifacts that do not agree on one signed planHash", () => {
    // Two hosts and one manifest, signed twice for **different targets**. Each envelope is
    // internally consistent — its planHash correctly binds its own target — so every binding check
    // above passes. What is wrong is that one bundle now describes two plans, which is the shape of
    // a splice: an envelope lifted from another authorization and filed here.
    const two = structuredClone(bundle()) as PlanBundle;
    two.manifest.hosts["second.dev"] = structuredClone(two.manifest.hosts[HOST]!);
    // The bundle carries the bytes as well as the manifest entry, and `prepareAuthorization`
    // refuses a manifest naming a host the bundle has no ruleset for — which is itself a binding
    // worth having, and is why this fixture has to be complete rather than manifest-only.
    two.rulesets["second.dev"] = RULESET;
    two.workload!["second.dev"] = WORKLOAD;
    const common = { bundle: two, authorizedAt: AUTHORIZED, expiresAt: EXPIRES, authorizationMode: "two-person" as const };
    const forDev = signAuthorizedArtifactBundle({ ...common, target: TARGET }, signing.privateKey);
    const forProd = signAuthorizedArtifactBundle({ ...common, target: "prod" }, signing.privateKey);
    assert.notEqual(
      forDev.artifacts[HOST]!.payload,
      forProd.artifacts[HOST]!.payload,
      "the fixture must actually produce two different plans",
    );

    const spliced = structuredClone(forDev) as unknown as { artifacts: Record<string, unknown> };
    spliced.artifacts["second.dev"] = forProd.artifacts["second.dev"];
    assert.throws(() => validateAuthorizedArtifactBundle(spliced), /agree on one signed planHash/);
  });

  // ── the hashes that bind bytes to the manifest ──────────────────────────────

  it("refuses a ruleset whose bytes do not hash to the signed entry", () => {
    // The one that matters most: this is the byte string the agent applies. Without it the manifest
    // describes one ruleset and the fleet applies another.
    const b = withPayload(signed(), HOST, (p) => { p.ruleset = `${p.ruleset as string} `; });
    assert.throws(() => validateAuthorizedArtifactBundle(b), /ruleset does not match the signed manifest entry hash/);
  });

  it("refuses a workload whose bytes do not hash to the signed entry", () => {
    const b = withPayload(signed(), HOST, (p) => { p.workload = `${p.workload as string} `; });
    assert.throws(() => validateAuthorizedArtifactBundle(b), /workload does not match the signed manifest entry hash/);
  });

  it("refuses a payload that omits a workload its entry assigns", () => {
    const b = withPayload(signed(), HOST, (p) => { p.workload = null; });
    assert.throws(() => validateAuthorizedArtifactBundle(b), /omits the workload assigned/);
  });

  it("refuses a workload smuggled in without a manifest assignment", () => {
    // The other direction, and the more interesting one: cluster policy delivered to a host whose
    // entry never assigned any.
    const noWorkload = structuredClone(bundle()) as PlanBundle;
    delete (noWorkload.manifest.hosts[HOST] as unknown as Record<string, unknown>).workload;
    // …and the document too, or the signer refuses the inconsistency before this test reaches the
    // branch it is about.
    delete noWorkload.workload![HOST];
    const b = signAuthorizedArtifactBundle(
      { target: TARGET, bundle: noWorkload, authorizedAt: AUTHORIZED, expiresAt: EXPIRES, authorizationMode: "two-person" },
      signing.privateKey,
    );
    const smuggled = withPayload(b, HOST, (p) => { p.workload = WORKLOAD; });
    assert.throws(() => validateAuthorizedArtifactBundle(smuggled), /workload without a manifest assignment/);
  });

  it("refuses a workload that is neither text nor null", () => {
    const b = withPayload(signed(), HOST, (p) => { p.workload = 7; });
    assert.throws(() => validateAuthorizedArtifactBundle(b), /workload must be text or null/);
  });

  it("refuses a manifest issued after the authorization that signs it", () => {
    // Time only runs one way: an authorization cannot vouch for a plan that did not exist yet.
    const b = withPayload(signed(), HOST, (p) => {
      (p.manifest as Record<string, unknown>).issuedAt = "2026-08-15T00:10:00.000Z";
    });
    assert.throws(() => validateAuthorizedArtifactBundle(b), /issuedAt is later than artifact authorization/);
  });
});

// ── Reading the bundle off disk ───────────────────────────────────────────────
//
// 🔴 `loadAuthorizedArtifactBundle`'s refusals had no test, and the source comment above them
// records that **one of them had already been lost once**: it used to `lstat` the path, refuse a
// symlink, then read the path again — and the read follows links, so the thing refused and the
// thing read were never guaranteed to be the same object. It was rewritten to open once with
// `O_NOFOLLOW` and ask the descriptor. Nothing pinned the rewrite, so the next refactor could lose
// it the same way, and just as quietly.
//
// This is the relay's own copy of the file that says a generation was authorized.
describe("loading the authorized bundle from disk", () => {
  const encoded = () => encodeAuthorizedArtifactBundle(signAuthorizedArtifactBundle(
    { target: TARGET, bundle: bundle(), authorizedAt: AUTHORIZED, expiresAt: EXPIRES, authorizationMode: "two-person" },
    signing.privateKey,
  ));

  it("reads a regular file — the known positive", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-bundle-"));
    writeFileSync(join(dir, AUTHORIZED_ARTIFACT_BUNDLE_FILE), encoded());
    const loaded = await loadAuthorizedArtifactBundle(dir);
    assert.equal(loaded.manifest.generation, "0123456789abcdef");
  });

  it("refuses a symlink, even one pointing at a valid bundle", async () => {
    // The point of `O_NOFOLLOW`. The target here is a perfectly good bundle: what is refused is the
    // indirection, because a name that can be repointed is not the file that was checked.
    const dir = mkdtempSync(join(tmpdir(), "hp-bundle-link-"));
    const real = join(dir, "elsewhere.json");
    writeFileSync(real, encoded());
    symlinkSync(real, join(dir, AUTHORIZED_ARTIFACT_BUNDLE_FILE));
    await assert.rejects(
      loadAuthorizedArtifactBundle(dir),
      (e: Error) => e instanceof ArtifactSignatureError && /not a regular file/.test(e.message),
    );
  });

  it("refuses a directory in the bundle's place, by name and not by accident", async () => {
    // The matcher is the test. Reading a directory fails anyway (EISDIR), so a bare `rejects` here
    // passes just as well with the `isFile` check deleted — measured. What is pinned is that the
    // refusal is *this* module's, decided from the descriptor, before any read is attempted.
    const dir = mkdtempSync(join(tmpdir(), "hp-bundle-dir-"));
    mkdirSync(join(dir, AUTHORIZED_ARTIFACT_BUNDLE_FILE));
    await assert.rejects(
      loadAuthorizedArtifactBundle(dir),
      (e: Error) => e instanceof ArtifactSignatureError && /not a regular file/.test(e.message),
    );
  });

  it("refuses a file past the byte limit", async () => {
    // ⚠️ There are **two** limits here and only one is observable from this test. The `stat` check
    // refuses before reading; the post-read check refuses the bytes actually in hand. Deleting the
    // first still fails this test, because the second catches the same file with the same message —
    // measured. That is not a gap in the test: the source says the second exists precisely because
    // a file can grow between the stat and the read, so the first is a guard against *reading* a
    // huge file rather than against accepting one. The correctness claim is the second, and that is
    // what is pinned.
    const dir = mkdtempSync(join(tmpdir(), "hp-bundle-big-"));
    const path = join(dir, AUTHORIZED_ARTIFACT_BUNDLE_FILE);
    const fd = openSync(path, "w");
    try {
      ftruncateSync(fd, MAX_AUTHORIZED_ARTIFACT_BUNDLE_BYTES + 1);
    } finally {
      closeSync(fd);
    }
    await assert.rejects(
      loadAuthorizedArtifactBundle(dir),
      (e: Error) => e instanceof ArtifactSignatureError && /exceeds its byte limit/.test(e.message),
    );
  });

  it("reports a missing bundle as a missing file, not as a malformed one", async () => {
    // The relay distinguishes "no generation has been authorized yet" from "the authorization is
    // corrupt", and those want different operator responses.
    const dir = mkdtempSync(join(tmpdir(), "hp-bundle-none-"));
    await assert.rejects(loadAuthorizedArtifactBundle(dir), (e: NodeJS.ErrnoException) => e.code === "ENOENT");
  });
});
