// TOTP verification, delegated to the IdP.
//
// ## Why the manager does not hold the secret
//
// It could: storing a TOTP secret is thirty lines. It must not, because then this process — which
// already holds an operator certificate for three VPCs — would also hold the second factor that is
// supposed to be independent of it. A second factor kept next to the first is one factor with extra
// steps.
//
// So the secret stays in KeyStone, where it was enrolled, and this sends the six digits over for a
// verdict. What the manager holds is a service token scoped to that one call.
//
// ## What the IdP already does, so this does not
//
// - **Replay rejection.** KeyStone stores the last used TOTP step in `credentials.counter` and
//   refuses a code at or below it. A code is single-use without anything here.
// - **Brute force.** Ten attempts per user per five minutes, enforced there.
//
// Reimplementing either would be a second, weaker copy of a control that already exists.
//
// ## Why a result object rather than a thrown error
//
// Five failures reach an operator very differently — a mistyped code, an account with no TOTP
// enrolled, a rate limit, a broken service token, and an unreachable IdP. The first is the user's
// own doing and needs no diagnosis; the fourth is a deployment fault that no amount of retyping will
// fix. Collapsing them into one exception loses exactly the distinction the person needs.

import { BodyTooLargeError, readBoundedText } from "./bounded-body.ts";

export type OtpFailure =
  /** The six digits were wrong, or already used. The only failure the caller can retry. */
  | "wrong-code"
  /** This user has no TOTP credential. They must enrol before they can approve anything. */
  | "not-enrolled"
  /** Too many attempts for this user. Enforced by the IdP, not here. */
  | "rate-limited"
  /** The manager's own credential was refused. Nothing the operator types will help. */
  | "service-token"
  /** The IdP could not be reached, or answered something unexpected. */
  | "unavailable";

export type OtpResult = { ok: true } | { ok: false; reason: OtpFailure; detail: string };

export interface OtpOptions {
  /** The identity provider's base URL — `https://idp.example.com`. */
  baseUrl: string;
  /** The manager's service token for `/api/totp/verify`. */
  serviceToken: string;
  /** KeyStone's user id. For an OIDC principal this is the `sub` claim. */
  userId: string;
  /** The six digits, as typed. */
  code: string;
  timeoutMs?: number;
}

/**
 * The most this will read of the IdP's verdict.
 *
 * The verdict is `{"ok":true}`. This is four orders of magnitude of headroom, and it exists for the
 * same reason `MAX_OIDC_DOCUMENT_BYTES` does one file over: the manager holds the artifact signing
 * key and runs as a single pod, so a body it buffers without a limit is an outage of the control
 * plane. `oidc.ts` bounds every document it reads from this same IdP; this call did not.
 */
export const MAX_OTP_RESPONSE_BYTES = 64 * 1024;

/**
 * Ask the IdP whether these digits are this user's current TOTP.
 *
 * Never throws for a verification outcome — only a programming error escapes. A caller that has to
 * wrap this in try/catch to find out whether the code was wrong will eventually treat a network
 * failure as a wrong code, which fails open on the one path this exists to close.
 */
export async function verifyOtp(o: OtpOptions, fetchImpl: typeof fetch = fetch): Promise<OtpResult> {
  if (!o.baseUrl.startsWith("https://")) {
    return { ok: false, reason: "unavailable", detail: `refusing to send a one-time code over plaintext (${o.baseUrl})` };
  }
  // Checked before the request so an obviously malformed code costs the user's rate limit nothing.
  // The IdP strips whitespace itself; this only refuses what cannot be a TOTP at all.
  if (!/^[0-9]{6,8}$/.test(o.code.replace(/\s/g, ""))) {
    return { ok: false, reason: "wrong-code", detail: "a one-time code is six digits" };
  }

  let res: Response;
  try {
    res = await fetchImpl(`${o.baseUrl.replace(/\/$/, "")}/api/totp/verify`, {
      method: "POST",
      headers: { authorization: `Bearer ${o.serviceToken}`, "content-type": "application/json" },
      body: JSON.stringify({ userId: o.userId, code: o.code.replace(/\s/g, "") }),
      redirect: "error",
      signal: AbortSignal.timeout(o.timeoutMs ?? 8_000),
    });
  } catch (e) {
    return { ok: false, reason: "unavailable", detail: (e as Error).message };
  }

  // ## Bounded, like every other read from this IdP
  //
  // This was `await res.text()`, which buffers whatever arrives. `AbortSignal.timeout` above bounds
  // the *duration*, not the size — eight seconds of a fast link is still gigabytes — and a
  // `Content-Length` is a claim, which is why `readBoundedText` counts while it reads.
  //
  // Failing to read is `unavailable` rather than a thrown error, because the contract above is that
  // only a programming error escapes: a caller forced to try/catch to learn whether a code was wrong
  // will eventually read a network failure as a wrong code, which fails open on the one path this
  // function exists to close. A body too large is the deployment's problem, not the operator's
  // credential, and `statusFor` turns it into a 503 rather than a 401 they would retype a code for.
  let text: string;
  try {
    text = await readBoundedText(res, MAX_OTP_RESPONSE_BYTES, "the IdP's one-time-code verdict");
  } catch (e) {
    return {
      ok: false,
      reason: "unavailable",
      detail: e instanceof BodyTooLargeError ? e.message : `could not read the IdP's answer: ${(e as Error).message}`,
    };
  }
  if (res.status === 200) {
    // The IdP answers 200 only on success, but read the body anyway: a proxy that returns 200 with
    // an error page would otherwise be a way to approve a firewall change with no code at all.
    try {
      if ((JSON.parse(text) as { ok?: unknown }).ok === true) return { ok: true };
    } catch {
      /* fall through to the refusal below */
    }
    return { ok: false, reason: "unavailable", detail: "the IdP answered 200 without a verdict" };
  }

  if (res.status === 401) {
    // Two different 401s, and the operator has to look in two different places. A wrong code comes
    // back as `{"ok":false}` from the handler; a refused service token is thrown by the guard before
    // the handler runs, so it carries no such body.
    let wrongCode = false;
    try {
      wrongCode = (JSON.parse(text) as { ok?: unknown }).ok === false;
    } catch {
      wrongCode = false;
    }
    return wrongCode
      ? { ok: false, reason: "wrong-code", detail: "that code is not valid, or has already been used" }
      : { ok: false, reason: "service-token", detail: "the IdP refused this manager's service token" };
  }

  if (res.status === 404) {
    return { ok: false, reason: "not-enrolled", detail: "this account has no one-time code enrolled at the IdP" };
  }
  if (res.status === 429) {
    return { ok: false, reason: "rate-limited", detail: "too many attempts — the IdP is rate limiting this account" };
  }
  return { ok: false, reason: "unavailable", detail: `the IdP answered ${res.status}` };
}

/** The HTTP status the manager should answer with for each failure. */
export function statusFor(reason: OtpFailure): number {
  switch (reason) {
    case "wrong-code":
      return 401;
    case "not-enrolled":
      return 403;
    case "rate-limited":
      return 429;
    // A broken service token and an unreachable IdP are both this deployment's fault, not the
    // caller's. 503 says "try again later, and it is not your credential" — which is true, and which
    // stops an operator from retyping a code that was never the problem.
    case "service-token":
    case "unavailable":
      return 503;
  }
}
