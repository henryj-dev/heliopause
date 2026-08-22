// ID token verification, against tokens this test actually signs.
//
// The known positive is the point. A suite that only feeds bad tokens to a verifier passes just as
// happily when the verifier rejects everything — including the tokens a real login produces. So each
// case here starts from a token that **does** verify and breaks exactly one thing.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, createSign, randomBytes, constants } from "node:crypto";
import {
  MAX_OIDC_DOCUMENT_BYTES,
  OidcError,
  Provider,
  pkce,
  safeEqual,
  verifyIdToken,
  authorizeUrl,
} from "./oidc.ts";

const ISSUER = "https://idp.example.invalid";
const CLIENT = "heliopause-manager";
const NONCE = "nonce-from-this-login";

const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const { publicKey: rsaPub, privateKey: rsaPriv } = generateKeyPairSync("rsa", { modulusLength: 2048 });

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");

/** Sign a token the way a real IdP would. `over` mutates the payload; `head` the header. */
function token(over: Record<string, unknown> = {}, head: Record<string, unknown> = {}, rsa = false) {
  const alg = rsa ? "PS256" : "ES256";
  const header = { alg, kid: rsa ? "rsa-1" : "ec-1", typ: "JWT", ...head };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ISSUER, aud: CLIENT, sub: "user-1", nonce: NONCE,
    exp: now + 300, iat: now, email: "a@example.invalid",
    preferred_username: "ops-alice", groups: ["fleet-operators"],
    ...over,
  };
  const input = `${b64(header)}.${b64(payload)}`;
  const s = createSign(alg.startsWith("PS") ? "sha256" : "sha256").update(input);
  const sig = rsa
    ? s.sign({ key: rsaPriv, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST })
    : s.sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${input}.${sig.toString("base64url")}`;
}

/** A Provider wired to an in-process IdP, so nothing here touches the network. */
function provider() {
  const jwks = {
    keys: [
      { ...publicKey.export({ format: "jwk" }), kid: "ec-1", use: "sig", alg: "ES256" },
      { ...rsaPub.export({ format: "jwk" }), kid: "rsa-1", use: "sig", alg: "PS256" },
    ],
  };
  const doc = {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oidc/authorize`,
    token_endpoint: `${ISSUER}/oidc/token`,
    jwks_uri: `${ISSUER}/oidc/jwks`,
    code_challenge_methods_supported: ["S256"],
  };
  const fake = (async (url: string | URL) => {
    const u = String(url);
    const body = u.endsWith("/oidc/jwks") ? jwks : doc;
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  return new Provider(ISSUER, fake, 0);
}

describe("id token verification", () => {
  it("accepts a token this test signed — the known positive", async () => {
    const id = await verifyIdToken(provider(), token(), CLIENT, NONCE);
    assert.equal(id.sub, "user-1");
    assert.equal(id.username, "ops-alice");
    assert.deepEqual(id.groups, ["fleet-operators"]);
  });

  it("accepts PS256 with real PSS padding", async () => {
    // The first draft passed `padding: 1` (PKCS#1 v1.5) for PS*. That is not a weaker check, it is a
    // different one, and it rejects every genuine PS256 token — a login that fails for everybody.
    const id = await verifyIdToken(provider(), token({}, {}, true), CLIENT, NONCE);
    assert.equal(id.sub, "user-1");
  });

  it("refuses a token signed by a different key", async () => {
    const other = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const header = b64({ alg: "ES256", kid: "ec-1" });
    const payload = b64({ iss: ISSUER, aud: CLIENT, sub: "x", nonce: NONCE, exp: Math.floor(Date.now() / 1000) + 300 });
    const sig = createSign("sha256").update(`${header}.${payload}`)
      .sign({ key: other.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    await assert.rejects(() => verifyIdToken(provider(), `${header}.${payload}.${sig}`, CLIENT, NONCE), /signature/);
  });

  it("refuses alg none, whatever the signature says", async () => {
    const header = b64({ alg: "none", kid: "ec-1" });
    const payload = b64({ iss: ISSUER, aud: CLIENT, sub: "x", nonce: NONCE, exp: Math.floor(Date.now() / 1000) + 300 });
    await assert.rejects(() => verifyIdToken(provider(), `${header}.${payload}.`, CLIENT, NONCE), /not accepted/);
  });

  it("refuses HS256 — the key confusion case", async () => {
    // Signing an RS/ES token's verification key as an HMAC secret is the classic JWT forgery. The
    // algorithm allowlist is checked before any key is fetched, so this never reaches a verifier.
    const header = b64({ alg: "HS256", kid: "ec-1" });
    const payload = b64({ iss: ISSUER, aud: CLIENT, sub: "x", nonce: NONCE, exp: Math.floor(Date.now() / 1000) + 300 });
    const mac = createHash("sha256").update(`${header}.${payload}`).digest("base64url");
    await assert.rejects(() => verifyIdToken(provider(), `${header}.${payload}.${mac}`, CLIENT, NONCE), /not accepted/);
  });

  it("refuses a token for another audience", async () => {
    await assert.rejects(() => verifyIdToken(provider(), token({ aud: "some-other-app" }), CLIENT, NONCE), /addressed/);
  });

  it("refuses a multi-audience token whose azp is another client", async () => {
    await assert.rejects(
      () => verifyIdToken(provider(), token({ aud: [CLIENT, "other"], azp: "other" }), CLIENT, NONCE), /azp/);
  });

  it("refuses a token from another issuer", async () => {
    await assert.rejects(() => verifyIdToken(provider(), token({ iss: "https://evil.example.invalid" }), CLIENT, NONCE), /issuer/);
  });

  it("refuses an expired token", async () => {
    await assert.rejects(
      () => verifyIdToken(provider(), token({ exp: Math.floor(Date.now() / 1000) - 3600 }), CLIENT, NONCE), /expired/);
  });

  it("refuses a token whose nonce is not this login's", async () => {
    // Without this a token minted for another session — legitimately — replays into this one.
    await assert.rejects(() => verifyIdToken(provider(), token({ nonce: "someone-elses" }), CLIENT, NONCE), /nonce/);
  });

  it("refuses a token with no nonce at all", async () => {
    await assert.rejects(() => verifyIdToken(provider(), token({ nonce: undefined }), CLIENT, NONCE), /nonce/);
  });

  it("reads groups whether the IdP sends a list or a string", async () => {
    const a = await verifyIdToken(provider(), token({ groups: ["x", "y"], roles: "admin ops" }), CLIENT, NONCE);
    assert.deepEqual(a.groups, ["x", "y", "admin", "ops"]);
    const b = await verifyIdToken(provider(), token({ groups: undefined, roles: undefined }), CLIENT, NONCE);
    assert.deepEqual(b.groups, [], "no group claim must be an empty list, never null");
  });
});

describe("PKCE and one-time values", () => {
  it("produces an S256 challenge that matches its verifier", () => {
    const { verifier, challenge } = pkce();
    assert.equal(createHash("sha256").update(verifier).digest("base64url"), challenge);
  });

  it("does not repeat", () => {
    const seen = new Set(Array.from({ length: 200 }, () => pkce().verifier));
    assert.equal(seen.size, 200);
  });

  it("compares equal-length secrets in constant time and unequal ones as false", () => {
    assert.equal(safeEqual("abc", "abc"), true);
    assert.equal(safeEqual("abc", "abd"), false);
    assert.equal(safeEqual("abc", "abcd"), false);
  });
});

describe("the authorization request", () => {
  it("asks for code with S256 and carries state and nonce", async () => {
    const d = await provider().load();
    const u = new URL(authorizeUrl(d, {
      clientId: CLIENT, redirectUri: "https://m.example.invalid/auth/callback",
      state: "st", nonce: "no", challenge: "ch", scopes: ["openid", "groups"],
    }));
    assert.equal(u.searchParams.get("response_type"), "code");
    assert.equal(u.searchParams.get("code_challenge_method"), "S256");
    assert.equal(u.searchParams.get("code_challenge"), "ch");
    assert.equal(u.searchParams.get("state"), "st");
    assert.equal(u.searchParams.get("nonce"), "no");
    assert.equal(u.searchParams.get("scope"), "openid groups");
  });
});

describe("discovery", () => {
  it("refuses an oversized discovery document from its declared length", async () => {
    const fake = (async () => new Response("{}", {
      status: 200,
      headers: { "content-length": String(MAX_OIDC_DOCUMENT_BYTES + 1) },
    })) as unknown as typeof fetch;
    await assert.rejects(() => new Provider(ISSUER, fake).load(), /response exceeds/);
  });

  it("enforces the byte limit while streaming a JWKS with no Content-Length", async () => {
    const encoder = new TextEncoder();
    const doc = {
      issuer: ISSUER,
      authorization_endpoint: "a",
      token_endpoint: "b",
      jwks_uri: `${ISSUER}/oidc/jwks`,
    };
    const fake = (async (url: string | URL) => {
      if (!String(url).endsWith("/oidc/jwks")) return new Response(JSON.stringify(doc), { status: 200 });
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode('{"keys":[],"padding":"'));
          controller.enqueue(encoder.encode("x".repeat(MAX_OIDC_DOCUMENT_BYTES)));
          controller.enqueue(encoder.encode('"}'));
          controller.close();
        },
      });
      return new Response(body, { status: 200 });
    }) as unknown as typeof fetch;
    await assert.rejects(() => new Provider(ISSUER, fake, 0).keyFor("unknown"), /response exceeds/);
  });

  it("refuses a document whose issuer is not the one configured", async () => {
    const fake = (async () =>
      new Response(JSON.stringify({ issuer: "https://elsewhere.invalid", authorization_endpoint: "a", token_endpoint: "b", jwks_uri: "c" }),
        { status: 200 })) as unknown as typeof fetch;
    await assert.rejects(() => new Provider(ISSUER, fake).load(), /does not match configured/);
  });

  it("refuses to fetch discovery over plaintext", async () => {
    await assert.rejects(() => new Provider("http://idp.example.invalid", fetch).load(), /plaintext/);
  });

  it("refuses an IdP that cannot do PKCE S256", async () => {
    const fake = (async () =>
      new Response(JSON.stringify({
        issuer: ISSUER, authorization_endpoint: "a", token_endpoint: "b", jwks_uri: "c",
        code_challenge_methods_supported: ["plain"],
      }), { status: 200 })) as unknown as typeof fetch;
    await assert.rejects(() => new Provider(ISSUER, fake).load(), /S256/);
  });

  it("rate limits key-set refreshes so an unknown kid cannot drive fetches", async () => {
    let fetches = 0;
    const fake = (async (url: string | URL) => {
      fetches++;
      const u = String(url);
      const body = u.endsWith("/oidc/jwks")
        ? { keys: [{ ...publicKey.export({ format: "jwk" }), kid: "ec-1", use: "sig" }] }
        : { issuer: ISSUER, authorization_endpoint: "a", token_endpoint: "b", jwks_uri: `${ISSUER}/oidc/jwks` };
      return new Response(JSON.stringify(body), { status: 200 });
    }) as unknown as typeof fetch;
    const p = new Provider(ISSUER, fake, 60_000);
    await assert.rejects(() => p.keyFor("unknown-1"), /has no key/);
    const after = fetches;
    await assert.rejects(() => p.keyFor("unknown-2"), /refreshed/);
    assert.equal(fetches, after, "a second unknown kid must not cause another fetch");
  });
});

describe("OidcError", () => {
  it("carries an HTTP status so the caller does not invent one", () => {
    assert.equal(new OidcError("x").status, 400);
    assert.equal(new OidcError("x", 401).status, 401);
  });
});
