// Sign the end-to-end harness's fixture artifacts, the way a real authorization is signed.
//
// ## Why this exists
//
// `e2e-roundtrip.sh` used to write `manifest.json` by hand and point the relay at it. That stopped
// working the day the signed-artifact path landed: the relay now loads `authorized-bundle.json` and
// serves per-host envelopes, and the agent refuses to start without a target and two trust
// directories. Twelve of eighteen cases failed at once and stayed failing for eight CI runs —
// **the harness that exists to catch a protocol change was itself left behind by one.**
//
// So the fixture is signed here with the same functions the manager and `heliopause-publish` use.
// Nothing about the protocol is restated: a change to the envelope format breaks this file, which
// is the point of not hand-writing the JSON.
//
// ## Break-glass, not manager
//
// The two trust classes are separate on purpose — an online manager key and an offline emergency
// key must not be able to make each other's audit claim. The harness signs `break-glass` and puts
// its public key in the break-glass directory only, so the classes stay honest here too. The
// manager directory is created and left empty, which is a state the agent must accept: a host that
// trusts only an emergency key is a real deployment, not a broken one.
import { createPrivateKey, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { signAuthorizedArtifactBundle, writeAuthorizedArtifactBundle } from "../src/artifact-signature.ts";

const [artifactDir, trustDir, target] = process.argv.slice(2);
if (!artifactDir || !trustDir || !target) {
  console.error("usage: e2e-authorize.mjs <artifact-dir> <trust-dir> <target>");
  process.exit(64);
}

const manifest = JSON.parse(readFileSync(join(artifactDir, "manifest.json"), "utf8"));

// Only hosts with a ruleset file get one. `h-e2e-02` is in the manifest and has none on purpose —
// the harness covers the missing-artifact path with it, and that path has to survive signing.
const rulesets = {};
for (const host of Object.keys(manifest.hosts)) {
  try {
    rulesets[host] = readFileSync(join(artifactDir, "hosts", `${host}.nft`), "utf8");
  } catch {
    // Absent by design; see above.
  }
}

// 0755/0644 and not a symlink: the agent refuses a key directory or file that is group- or
// world-writable, and refusing is correct — a trust root anybody can append to is not one.
mkdirSync(join(trustDir, "manager"), { recursive: true, mode: 0o755 });
mkdirSync(join(trustDir, "break-glass"), { recursive: true, mode: 0o755 });

// **One key per trust directory, reused across authorizations.** A harness publishes several
// generations in a run, and an agent reads its trust ring once at startup — so a fresh keypair per
// call makes every generation after the first `signed by untrusted key`. That is the agent behaving
// correctly against a harness that was rotating keys behind its back.
//
// The private half lives at the trust root, not in either public directory: the agent reads
// `manager/` and `break-glass/`, and a private key sitting in one of them would be offered to it as
// a trust anchor.
const privatePath = join(trustDir, "signing.key");
let privateKey;
if (existsSync(privatePath)) {
  privateKey = createPrivateKey(readFileSync(privatePath, "utf8"));
} else {
  const pair = generateKeyPairSync("ed25519");
  privateKey = pair.privateKey;
  writeFileSync(privatePath, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  writeFileSync(
    join(trustDir, "break-glass", "e2e.pem"),
    pair.publicKey.export({ format: "pem", type: "spki" }),
    { mode: 0o644 },
  );
}

const authorizedAt = new Date();
const signed = signAuthorizedArtifactBundle(
  {
    target,
    bundle: { manifest, rulesets, workload: {} },
    authorizedAt,
    // Well inside the 24h ceiling the protocol puts on a break-glass authorization. A harness that
    // signed something the protocol would refuse would be testing a shape nothing accepts.
    expiresAt: new Date(authorizedAt.getTime() + 60 * 60 * 1000),
    authorizationMode: "break-glass",
  },
  privateKey,
);
await writeAuthorizedArtifactBundle(artifactDir, signed);
console.log(`authorized ${Object.keys(signed.artifacts).length} host envelope(s) for target ${target}`);
