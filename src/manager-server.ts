// The manager's HTTP surface (H26): reads the whole site, and is the ordinary way a generation gets
// published.
//
// ## Why this is separate from the relay
//
// The relay serves one VPC and cannot interpret what it serves — that is deliberate, and it is what
// keeps a compromised gateway from inventing a ruleset. The manager is the opposite: it sees the whole
// site and is the only thing that can hand a generation to every VPC. Putting both in one process
// would give the most exposed machine in each VPC the ability to publish to the others.
//
// ## The write half, and what makes it a permission model rather than three endpoints
//
// `POST /plan` → `POST /approve` → `POST /publish`, and the ordering is the whole point
// (docs/인터페이스-설계.md 결정 4). Two properties carry it:
//
//   · **The approval is a fact this server remembers, not a value a request claims.** No endpoint
//     accepts an "approved" flag, and none accepts a plan hash — the hash is computed here from the
//     bytes that arrived. A submitted hash would be the proposer's claim about content the approver
//     never saw.
//   · **Two allowlists.** `operatorCNs` may read the site; `writerCNs` may change it. Reading and
//     changing are different powers and the second is strictly larger, so a read-only credential must
//     not silently carry publish rights.
//
// Neither list is reachable through the API. An API that can grant itself permission is not a
// permission model (결정 6) — they are deployment configuration, along with certificate issuance.
//
// ## What this deliberately cannot do
//
// **Evaluate the policy.** It draws the policy screen, but it never runs the site module, and the
// distinction is the entire content of audit finding C1. This process holds the artifact signing
// key, the GitHub App key, the OIDC client secret and a client certificate for every relay; the site
// module is TypeScript, whose top level is code; so `await import(sitePath)` here made a commit to
// the policy repository into arbitrary code execution beside all of it, landed by a sync sidecar with
// no operator in the loop.
//
// What it does instead is read JSON from `heliopause-policy-render` — a separate Deployment holding
// a policy checkout and nothing else — and render that with its own code. See `policy-source.ts` for
// the contract and for the measurement that says the screen is byte-identical either way.
//
// The first remediation deleted the screen outright, which also deleted the console; `/policy/edit`
// and `/policy/propose` went with it despite never having had the flaw, since committing a file
// through the GitHub App and opening a pull request are data operations. They are back.
//
// **Be required.** Every path out of an incident bypasses this process (결정 5): relays keep serving
// the last generation without it, `heliopause-publish` writes straight to a gateway's artifact
// directory, and `heliopause-status` reads a relay directly. Verified by killing it and using all
// three.

import { createServer, request, type Server } from "node:https";
import { createSecureContext, type SecureContext } from "node:tls";
import type { IncomingMessage, ServerResponse } from "node:http";
import { readFile, readdir, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { peerCN, type FleetView } from "./relay.ts";
import { readBoundedNodeBody, readBoundedText } from "./bounded-body.ts";
import { buildId } from "./build-id.ts";

import { authorizeUrl, endSessionUrl, exchange, nonce as randomNonce, pkce, Provider } from "./oidc.ts";
import { authorize } from "./oidc-authz.ts";
import { statusFor, verifyOtp } from "./otp.ts";
import { RoleChangeLedger, verifyBackchannelLogout, verifyRoleChange } from "./set.ts";
import {
  checkCsrf, clearCookieHeader, clearLoginCookieHeader, cookieHeader, COOKIE, CSRF_HEADER,
  DEFAULT_LIMITS as DEFAULT_SESSION_LIMITS, LOGIN_COOKIE, loginBinder, loginBinderMatches,
  loginCookieHeader, readCookie, SessionStore, type Principal,
} from "./session.ts";

import { CONSOLE_ENTRY, consoleAppPath, policyAppPath } from "./app-shell.ts";

import { allSitePolicies, buildScreen, type Screen } from "./policy-screen.ts";
import { planPublish } from "./publish.ts";
import { editableFiles, parsePolicySource, screenSiteOf, type PolicySource } from "./policy-source.ts";
import { compareRoutes, readyToApply, type RouteDecl } from "./routes.ts";
import { lookupPolicies } from "./policy-lookup.ts";
import { pickLang } from "./i18n.ts";
import type { Lang } from "./i18n.ts";
import { formatOperatorEvent, formatOperatorLog } from "./operator-i18n.ts";
import { repeatedLiterals, whereUsed } from "./where-used.ts";
import { parseTrafficDump } from "./workload-traffic.ts";
import {
  branchName,
  commitToBranch,
  openPullRequest,
  proposalBody,
  ProposalError,
  type AppCredentials,
  compareGenerations,
  isGeneratedPolicyFile,
  isUsableBranchName,
  repoHead,
  sameCommit,
  type Fetcher,
  type ProposalTarget,
} from "./policy-proposal.ts";
import {
  startHostDeregistrationPolicyWorker,
  type PolicyWorkerPlan,
} from "./host-deregistration-policy-worker.ts";
import { siteView, type RelaySource, type RelayResult, type SiteView } from "./manager.ts";
import { bundleFromPlan, planHash, validateBundle, type PlanBundle } from "./bundle.ts";
import { diffRulesets } from "./ruleset-diff.ts";
import {
  AuthorizationTimestampIssuer,
  artifactSigningKeyId,
  signAuthorizedArtifactBundle,
} from "./artifact-signature.ts";
import {
  ApprovalError,
  approve,
  claimForPublish,
  DEFAULT_LIMITS,
  emptyApprovals,
  listPlans,
  propose,
  release,
  type ApprovalLimits,
  type Plan,
  type PlanSummary,
} from "./approval.ts";
import {
  APP_TOKEN_SCOPES, EnrollmentError, appTokenAllowsHostname, appTokenCreatedBy, beginHostDeregistration,
  bindLegacyHostLifecycle, completeHostDeregistrationPolicy, confirmHostInfrastructureDestroyed, createAppToken, createNodeToken,
  fetchNodeCertificate, looksLikeAppToken, looksLikeNodeToken, lookupAppToken,
  normalizeEnrollmentHostname, preflightNodeCsr, rejectNodeCsr, requireEnrollmentDocument,
  recordHostDeregistrationReplication, reconcileHostDeregistrationRelays,
  normalizeExternalOperationId, repairHostDeregistrationCertificateInventory,
  repairHostDeregistrationRevocationCapacity,
  revokeAppToken, revokeCertificate, revokeNodeToken, storeNodeCertificate,
  submitValidatedNodeCsr, touchExistingNodeCsr, validateNodeCsrAsync, withEnrollmentTransaction,
  type AppTokenRecord, type AppTokenScope, type EnrollmentDocument, type NodeCsrRecord,
} from "./enrollment-store.ts";
import { certificateIsRevoked } from "./certificate-revocation.ts";
import { MAX_REVOCATION_ROWS, serializeRevocationSnapshot } from "./revocation-snapshot.ts";
import { daysUntilExpiry } from "./cert-api.ts";
import type { CertBundle } from "./cert-api.ts";
import type { CertificateRevocation } from "./enrollment-store.ts";

/**
 * Body limit for `POST /plan`, well above the relay's.
 *
 * A plan carries every host's rendered ruleset. Measured on dev: 6 hosts, 71 KB. The bound is generous
 * because the failure it would cause is "the publish stopped working" on the day a VPC grew, and small
 * because a body this size is buffered in a process that also serves the console.
 */
const MAX_PLAN_BYTES = 8 * 1024 * 1024;

/**
 * Anonymous login starts held while the browser is at the IdP.
 *
 * The session store accepts at most 64 signed-in users. Twice that many incomplete logins is ample
 * for redirects in flight and, more importantly, makes `/auth/login` consume constant-bounded
 * memory even when an unauthenticated caller never returns from the IdP.
 */
export const MAX_PENDING_OIDC_LOGINS = 128;
const PENDING_OIDC_LOGIN_TTL_MS = 10 * 60_000;

/**
 * The data routes, which answer under `/api/` as well as at the top level.
 *
 * ## Why the prefix
 *
 * Screens and data grew into the same namespace and started colliding. `/policy` is a screen **and**
 * the stem of `/policy/lookup`, `/policy/edit`, `/policy/propose`, `/policy/plan`, `/policy/where-used`;
 * `/enrollment` is a screen and the stem of four more. `manager-ui.ts` records the cost in prose: the
 * `/changes` screen reads the `/plans` API and *could not be called `/plans`*, because that name was
 * taken by the data. So the screens have been picking names around the API, and a reader cannot tell
 * from a path which kind of thing is at the end of it.
 *
 * A screen route that is also a data route is not a style problem. `manager-ui.test.ts` has a check
 * for exactly that collision, written after one of them returned a 200 from the wrong handler.
 *
 * ## Why it is additive, and why removal is not in this commit
 *
 * Four binaries and two rendered pages call these paths, and **the fleet runs a deployed manager
 * image**. Renaming in one commit means an old CLI meets a new server, or the reverse, and the
 * failure is a 404 that reads like an outage. So: this step adds `/api/` while every old path keeps
 * answering, the callers in this repository move to it, and the top-level paths come out **only
 * after every deployed caller is on the new image.** Three steps, and the third is somebody's later
 * decision with a deploy in front of it — writing it here as a comment is the whole point, because
 * an additive step with no recorded second half is how a permanent alias gets made by accident.
 *
 * ## What is deliberately absent
 *
 * `/healthz` is the kubelet's, `/auth/login` and `/auth/callback` are browser navigations to and from
 * the identity provider, and **`/infra/node-csrs` is an external contract**: `agent/heliopause-enroll.py`
 * posts there from every fleet host, reached through `node-enroll.tinyuniver.se`, a name that is in
 * stardust's SNI allowlist. Moving that one is not a rename, it is a handoff to another organisation.
 * Screens are absent for the obvious reason and the test below keeps them out.
 */
export const API_ROUTES: ReadonlySet<string> = new Set([
  "/site",
  "/authz",
  "/plans",
  "/plan",
  "/approve",
  "/publish",
  "/routes",
  "/workload-traffic",
  "/policy/lookup",
  "/policy/where-used",
  "/policy/screen",
  "/policy/edit",
  "/policy/propose",
  "/policy/plan",
  "/enrollment/requests",
  "/enrollment/tokens",
  "/enrollment/app-tokens",
  "/enrollment/audit",
  "/enrollment/revocations",
  "/enrollment/host-deregistrations",
]);

/**
 * The same thing for the routes matched by shape rather than by equality.
 *
 * Kept as a second list because the first one is a `Set` and a `Set` cannot answer for
 * `/plans/<hash>/changes`. **The exact list alone was the first version of this change and it was
 * wrong** — the console fetches four of these, and moving its callers while the alias only covered
 * equality would have moved them onto 404s. The honesty check in `manager-server.test.ts` reads both
 * dispatch shapes now, which is how this was found.
 *
 * `/infra/node-csrs/<name>/certificate` is deliberately absent for the reason its sibling is: a
 * fleet agent fetches its own certificate from there, through a name in stardust's SNI allowlist.
 */
export const API_ROUTE_PATTERNS: readonly RegExp[] = [
  /^\/plans\/[^/]+\/changes$/,
  /^\/plans\/[^/]+\/ruleset$/,
  /^\/plans\/[^/]+\/ruleset-diff$/,
  /^\/enrollment\/tokens\/[^/]+\/revoke$/,
  /^\/enrollment\/app-tokens\/[^/]+\/revoke$/,
  /^\/enrollment\/requests\/[^/]+\/reject$/,
  /^\/enrollment\/requests\/[^/]+\/certificate$/,
  /^\/enrollment\/host-lifecycle-bindings\/[^/]+\/[^/]+$/,
  /^\/enrollment\/host-deregistrations\/[^/]+\/[^/]+(?:\/infrastructure-destroyed)?$/,
  /^\/enrollment\/host-deregistrations\/[^/]+\/[^/]+\/policy-completed$/,
  /^\/enrollment\/host-deregistrations\/[^/]+\/[^/]+\/repairs\/(?:certificate-inventory|revocation-capacity)$/,
];

export type PendingOidcLogin = {
  verifier: string;
  nonce: string;
  at: number;
  returnTo?: string;
  /**
   * SHA-256 of the value handed to this browser as the `__Host-heliopause-login` cookie.
   *
   * What ties a callback to the browser that started the login. Without it `state` alone admits a
   * callback anyone can replay into anyone else's browser — see the note in `session.ts`.
   *
   * Optional only so a record written by an older process is refused rather than crashing on a
   * missing field; `loginBinderMatches` treats `undefined` as no match.
   */
  binder?: string;
};

/**
 * Where to send the browser after a login, or `null` if the request did not name a safe place.
 *
 * **Kept server-side, in the pending record keyed by `state`.** The obvious alternative — carry the
 * path through the IdP and read it back off the callback URL — makes the redirect target something
 * the caller supplies at the moment it is used, which is the shape of an open redirect. Here the
 * value is stored under a state this server minted and is unreachable to anyone who did not start
 * the login.
 *
 * Same-origin paths only, and that is three separate refusals rather than one: anything with a
 * scheme, anything starting `//` (protocol-relative, a host in disguise), and anything not starting
 * `/`. A backslash is refused too — some browsers normalise `/\evil.com` to `//evil.com`.
 */
export function safeReturnTo(raw: string | null): string | null {
  if (!raw || !raw.startsWith("/")) return null;
  if (raw.startsWith("//") || raw.startsWith("/\\")) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw)) return null;
  // The login routes themselves would loop, and a POST-only route reached by redirect becomes a GET.
  if (raw.startsWith("/auth/")) return null;
  return raw;
}

/** Expire and evict from the oldest end of insertion-ordered `Map`, reserving one insert slot. */
export function trimPendingOidcLogins(pending: Map<string, PendingOidcLogin>, nowMs: number): void {
  const cutoff = nowMs - PENDING_OIDC_LOGIN_TTL_MS;
  while (pending.size > 0) {
    const oldest = pending.entries().next().value as [string, PendingOidcLogin] | undefined;
    if (!oldest || oldest[1].at >= cutoff) break;
    pending.delete(oldest[0]);
  }
  while (pending.size >= MAX_PENDING_OIDC_LOGINS) {
    const oldestState = pending.keys().next().value as string | undefined;
    if (oldestState === undefined) break;
    pending.delete(oldestState);
  }
}

/** Delete a state on lookup and refuse it when its own timestamp is past the TTL. */
export function consumePendingOidcLogin(
  pending: Map<string, PendingOidcLogin>,
  state: string,
  nowMs: number,
): PendingOidcLogin | undefined {
  const found = pending.get(state);
  if (found) pending.delete(state);
  return found && found.at >= nowMs - PENDING_OIDC_LOGIN_TTL_MS ? found : undefined;
}

export interface ManagerOptions {
  port: number;
  hostname?: string;
  /** The relays this manager aggregates — one per VPC. */
  relays: readonly RelaySource[];
  /**
   * Where the rendered policy comes from — a URL, never a path.
   *
   * A path would mean a checkout in this process, and a checkout is one `import()` away from being
   * executed by whoever writes the next line here. The type is the guard rail: there is no filename
   * in this interface for a future caller to reach for.
   *
   * Unset leaves `/policy` answering 404 and the console read-only, which is what a deployment
   * without a policy repository should look like.
   */
  policySource?: {
    /** `http://heliopause-policy-render:9099` — cluster-internal, reached only through the CNP. */
    url: string;
    /** Optional bearer, as defence in depth behind the network policy. */
    token?: string;
    /** Injectable for tests. Defaults to global `fetch`. */
    fetch?: typeof fetch;
  };
  /**
   * The credential that turns an edit into a branch and a branch into a pull request.
   *
   * Separate from `policySource` because they are different powers held for different reasons: one
   * reads a rendered policy, the other can write to the repository. A console with the first and not
   * the second is a viewer, and that is a sensible thing to deploy.
   */
  policyWrite?: {
    creds: AppCredentials;
    target: ProposalTarget;
    /**
     * What the console may commit.
     *
     * An allowlist rather than sanitising. `../` is the traversal everyone remembers; the one that
     * matters here is a plausible path — a workflow file — that turns a policy editor into a way to
     * run code in CI. The same list is applied in the renderer when the text is read out, so the two
     * halves cannot drift into offering an editor over a file the commit would refuse.
     */
    allowPaths: readonly string[];
    fetch?: Fetcher;
  };
  /** Reviewed-Git host retirement orchestration. It never approves, merges or publishes. */
  policyWorker?: {
    /** Machine-owned JSON file in the policy repository, also exposed by the renderer allowlist. */
    retiredHostsPath: string;
    intervalMs?: number;
  };
  /**
   * Where to read Cilium's policy-map counters from, if a reader is deployed.
   *
   * A URL and never a command. The `exec` that produces this needs `pods/exec` in `kube-system`,
   * which is effectively control of the node's dataplane — the process that applies the firewall must
   * not hold it, or it holds a way round the firewall too. So the permission lives in a pod that
   * holds nothing else and serves the dump verbatim, and this process only reads.
   *
   * Same shape and same reasoning as `policySource`. Unset leaves `/traffic` answering 404.
   */
  trafficReader?: { url: string; fetch?: Fetcher };
  /** Optional standalone enrollment database. Unset leaves all enrollment routes disabled. */
  enrollment?: { storeFile: string; trustedCaFiles?: ReadonlyMap<string, string> };
  /** Enrollment store or standalone JSON denylist, reloaded on every authenticated request. */
  revocationFile?: string;
  /** Dedicated online Ed25519 key. It signs approved artifacts and is never shared with a relay. */
  artifactSigning?: {
    privateKey: KeyObject;
    /** Default 24h; bounded to 15 minutes..7 days by the signed-artifact protocol. */
    authorizationTtlSec?: number;
  };
  tls: {
    /** This server's own certificate — what operators verify when they connect *to* the manager. */
    certFile: string;
    keyFile: string;
    /** Anchor for verifying callers of this server. */
    caFile: string;
    /**
     * A second, publicly-trusted certificate, served only to clients that ask for `serverName`.
     *
     * ## Why two certificates rather than one
     *
     * The internal certificate is issued by `heliopause-ca` and its SANs are IP addresses and
     * in-cluster names. Every operator CLI verifies the manager against that CA — `api-client.ts`
     * passes `ca: creds.ca` explicitly — so replacing it with a public certificate breaks
     * `heliopause-status`, `--propose` and `heliopause-approve` in one step. Measured before writing
     * this: the public certificate's only SAN is the DNS name, so even the IP paths would stop
     * matching.
     *
     * The reverse is also true and is why the public one exists at all: a browser will not trust
     * `heliopause-ca`, and the console is meant to be opened by a person.
     *
     * So neither certificate can be the only one. SNI is what makes that a configuration rather than
     * a compromise — the name gets the public certificate, everything else keeps the internal one,
     * and **the client CA for mTLS is the same in both cases.** Certificate logins and OIDC logins
     * sit behind the same server for the same reason.
     *
     * Omitted means "one certificate, as before". A deployment with no public name is unaffected.
     */
    public?: {
      /** Exact SNI names this certificate answers for. Compared case-insensitively, never a suffix match. */
      serverNames: readonly string[];
      /**
       * Where the certificate comes from, called at startup and on `refreshSec`.
       *
       * A function rather than a pair of paths because the certificate is not on disk: it is issued
       * by cert-manager into another namespace and read over the mesh from stardust's cert-api. See
       * `cert-api.ts` for why that is better than mounting a second, duplicate `Certificate`.
       *
       * **May throw, and throwing is survivable.** On the first call the manager starts without a
       * public certificate; on later calls it keeps the one it has. The operator CLI verifies against
       * the internal CA and never touches this, so the cost of failure is the browser path alone —
       * which is the right thing to lose in a process that decides firewall rules.
       */
      load: () => Promise<CertBundle>;
      /** Seconds between refreshes. Renewal happens 15 days out, so this does not need to be often. */
      refreshSec?: number;
      /**
       * First delay before retrying **while this process holds no public certificate at all.**
       * Doubles on each failure up to `refreshSec`, and stops the moment one is loaded.
       *
       * ## Why this is not just `refreshSec`
       *
       * The two answer different questions. `refreshSec` asks "has the certificate rotated", and an
       * hour is right for that — renewal happens 15 days out. This asks "is the console reachable at
       * its own name", and an hour is the wrong answer for that by a factor of hundreds.
       *
       * Measured 2026-08-18: the manager restarted while `dispatch.tinyuniver.se` was briefly slow,
       * the startup load timed out, and both public names — the console and `node-enroll`, which
       * every fleet host posts its CSR to — served the internal certificate and failed hostname
       * verification for the next hour. The cert API answered in 138ms the whole time. Nothing was
       * broken except that the one attempt had already been spent.
       *
       * Fractional values are accepted so a test can drive the whole ladder without waiting; the
       * clamp below keeps a zero or a negative from turning this into a spin.
       */
      retrySec?: number;
    };
  };
  /**
   * CNs allowed to read. Unset means nobody, which is the right default.
   *
   * A site view names every host, its generation and its drift state across every VPC — strictly
   * more than any single relay exposes. Defaulting this open would make the manager the easiest way
   * to enumerate the fleet.
   */
  operatorCNs?: readonly string[];
  /**
   * CNs allowed to propose, approve and publish. A subset of `operatorCNs` in practice, and checked
   * independently — a writer who is not also a reader gets 403 at the earlier check, which is correct:
   * changing a fleet you cannot inspect is not a workflow worth supporting.
   *
   * Empty means the write endpoints exist and refuse everyone. That is the right default for the same
   * reason `operatorCNs` is: the safe failure is "nobody can publish through the API", because the
   * filesystem path on each gateway still works.
   *
   * **Two entries are needed for the mechanism to function at all.** With one, every plan is proposed
   * and approved by the same CN and `POST /approve` refuses it forever. That is a real configuration —
   * this site has one operator today — and it means publishing goes through the direct path until a
   * second operator exists. Reported at startup rather than discovered at 3am.
   */
  writerCNs?: readonly string[];

  /**
   * A one-time code, required on every request that approves or publishes.
   *
   * Top level rather than under `oidc`, because it applies to **both** ways of arriving: a browser
   * session and a client certificate. Putting it under `oidc` would have made the CLI a way around
   * it, and a second factor with a documented bypass is not a second factor.
   *
   * ## What it costs the certificate path
   *
   * A certificate carries no IdP identity, so `users` maps a certificate name to a KeyStone user id.
   * A writer with no entry cannot approve — refused with a message naming the missing mapping. That
   * is the same safe direction the rest of this file takes: the failure is "nobody can publish
   * through the API", and every gateway's filesystem path still works.
   *
   * Unset means no code is required, which is what this was before.
   */
  otp?: {
    /** KeyStone's base URL. */
    issuerUrl: string;
    /** Service token for `POST /api/totp/verify`. */
    serviceToken: string;
    /**
     * Certificate name → KeyStone user id.
     *
     * Not needed for an OIDC principal: its `sub` **is** the KeyStone user id
     * (`token/+server.ts:98`, `sub: user.id`). Confirmed with the KeyStone team, who have agreed to
     * say so at that line — until they do, this coupling is one a reader of either repository can
     * miss.
     */
    users: ReadonlyMap<string, string>;
    fetchImpl?: typeof fetch;
  };

  /**
   * Browser login through an OIDC provider, as an alternative to a client certificate.
   *
   * Unset means the console is certificate-only, which is what it was. Setting it adds `/auth/*` and
   * a second way to arrive at a principal — **not** a second permission model: the decision still
   * produces a name in the same space `operatorCNs` uses, and `oidc-authz.ts` explains why a writer
   * must have an alias into that space before anything may be published.
   *
   * This exists because the certificate path was measured to be unusable in a browser on this
   * operator's machine: an identity imported correctly, with `clientAuth`, issued by the CA the
   * server advertises, still was not offered. `curl` with the same files kept working, so the console
   * — the one part meant for a person — was the only thing that broke.
   */
  oidc?: {
    issuer: string;
    clientId: string;
    /** Omit for a public client. Present means `client_secret_basic`. */
    clientSecret?: string;
    /** Must match the value registered with the IdP exactly. */
    redirectUri: string;
    operatorGroups: readonly string[];
    writerGroups: readonly string[];
    /** OIDC identity → certificate-space name. See `oidc-authz.ts`. */
    aliases: ReadonlyMap<string, string>;
    /** Session lifetime. Group claims are captured at login, so this is also how stale they get. */
    sessionTtlSec?: number;
    /**
     * Roles that grant solo approval — approving a plan one proposed oneself.
     *
     * **This switches off the two-person rule for the identities named here**, which is the rule
     * `approval.ts` exists for. It is enabled because this site has one operator and the alternative
     * is that nothing can be published through the API at all.
     *
     * The compensating control is the one-time code: `requireOtp` is not optional when this is set,
     * and a solo approval is recorded on the plan so the audit trail can tell the two apart. What
     * remains true, and is worth stating plainly: a compromise of one admin account with its second
     * factor is a firewall change with nobody else involved.
     */
    soloApprovalRoles?: readonly string[];
    /**
     * The `events` key the identity provider puts a role change under.
     *
     * Required, and deliberately not defaulted. RFC 8417 leaves the key to the issuer, so it is a
     * fact about the deployment's IdP rather than about this code. A default would name one
     * provider — it used to, in `set.ts`, which put a live domain in tracked source and made every
     * other provider fail *silently*: the token verifies, the key does not match, and the change is
     * discarded as "carries no role-change event".
     */
    roleChangeEvent: string;
    /**
     * How the IdP is reached. Defaults to the global `fetch`.
     *
     * A seam, not a feature. `/auth/login` cannot build a redirect without the discovery document,
     * so with no way to substitute this every test of the login routes needs a live IdP — and a
     * suite that needs one is a suite that stops running. Same reason `tls.public.load` is a
     * function.
     */
    fetchImpl?: typeof fetch;
  };
  /** Per-relay timeout. Short on purpose — see `pollRelays`. */
  timeoutMs?: number;
  /**
   * Timeout for pushing a generation to a relay. Longer than `timeoutMs`.
   *
   * A status poll runs behind an interactive page and a slow relay is better reported than waited for.
   * A publish is the opposite: it writes every host's ruleset on the far side, and giving up early
   * abandons a push that may have landed — leaving the manager's record and the relay's disagreeing.
   */
  publishTimeoutMs?: number;
  /** Approval window and pending-plan bound. Defaults in `approval.ts`. */
  limits?: ApprovalLimits;
  /** Overridable for tests. */
  now?: () => Date;
  log?: (m: string) => void;
  /** Deployment-wide journal language; never derived from an individual request. */
  logLang?: Lang;
  /**
   * Runs before this process's own handler. Return true if the response is finished.
   *
   * The workspace manager package uses this to serve the SvelteKit console at `/app` without
   * importing Hono into `src/` — `npm install heliopause` must not grow a frontend runtime.
   * Unset is the published-package path and leaves every request with the existing handler.
   */
  intercept?: (req: IncomingMessage, res: ServerResponse) => boolean | Promise<boolean>;
}

/**
 * Ask every relay for its fleet view, in parallel, and never let one failure lose the others.
 *
 * `Promise.all` would be wrong here: one unreachable relay would reject the whole batch, and the
 * site view would go from "prod is down, here is dev and util" to nothing at all. That is precisely
 * backwards — the relays are separate so an outage is contained.
 *
 * The timeout is short because this runs behind an interactive request. A relay that has not
 * answered in a few seconds is unreachable *for the purpose of drawing this page*, and saying so is
 * more useful than making the operator wait on a TCP timeout.
 */
export async function pollRelays(
  relays: readonly RelaySource[],
  timeoutMs = 5_000,
): Promise<RelayResult[]> {
  return Promise.all(
    relays.map(async (r): Promise<RelayResult> => {
      try {
        // Per-VPC credentials, loaded per request rather than cached. A certificate rotation should
        // take effect on the next poll, not on the next manager restart — and this runs at human
        // pace, so three file reads cost nothing worth optimising.
        const tls = await loadRelayCreds(r);
        const view = await getFleetView(r.url, tls, timeoutMs);
        return { name: r.name, url: r.url, ok: true, view };
      } catch (e) {
        return { name: r.name, url: r.url, ok: false, error: (e as Error).message };
      }
    }),
  );
}

/**
 * The operator certificate and anchor for one VPC.
 *
 * Each VPC has its own CA, so "the manager's certificate" is not one thing — it is one per VPC, and
 * presenting the wrong one gets `self-signed certificate in certificate chain` from a relay that is
 * working perfectly well.
 */
async function loadRelayCreds(r: RelaySource): Promise<{ cert: Buffer; key: Buffer; ca: Buffer }> {
  // Named explicitly when given. A directory holding both a human's certificate and the manager's is
  // normal on a workstation, and the manager must never present the human's.
  const wanted = r.operatorName ? `operator-${r.operatorName}.pem` : null;
  const found = (await readdir(r.pkiDir)).filter(
    (f) => f.startsWith("operator-") && f.endsWith(".pem"),
  );
  if (wanted) {
    if (!found.includes(wanted)) {
      throw new Error(
        `no ${wanted} in ${r.pkiDir} — issue it with: ` +
          `heliopause-pki issue ${r.pkiDir} ${r.operatorName} --role=operator`,
      );
    }
  } else {
    if (found.length === 0) {
      throw new Error(
        `no operator certificate in ${r.pkiDir} — issue one with: heliopause-pki issue ${r.pkiDir} <name> --role=operator`,
      );
    }
    if (found.length > 1) {
      // Refused rather than guessed. Picking one would mean the manager silently authenticates as
      // whichever name sorts first, and that is not something to discover from an audit log.
      throw new Error(
        `several operator certificates in ${r.pkiDir} (${found.join(", ")}) — name one with operatorName`,
      );
    }
  }
  const base = join(r.pkiDir, (wanted ?? found[0]!).replace(/\.pem$/, ""));
  const [cert, key, ca] = await Promise.all([
    readFile(`${base}.pem`),
    readFile(`${base}.key`),
    readFile(join(r.pkiDir, "ca.pem")),
  ]);
  return { cert, key, ca };
}

/**
 * How much rendered policy this process will accept.
 *
 * The renderer is the untrusted side of that connection — it is the process that runs the policy
 * author's code — so its answer is bounded like any other request body. The live site serialises to
 * roughly 200 kB; a megabyte is room to grow and still far below anything that would matter here.
 */
const MAX_POLICY_SOURCE_BYTES = 4 * 1024 * 1024;

/**
 * How much of a relay's answer this will hold.
 *
 * `GET /status` is the large one — a `FleetView` carries every host's state, its intrusion events
 * and its route table. Measured on dev: 6 hosts, a few kilobytes. The manifest allows 4,096 hosts,
 * so the ceiling is set well above any fleet this deployment will have and well below anything that
 * would matter to a manager pod.
 */
const MAX_RELAY_RESPONSE_BYTES = 8 * 1024 * 1024;

/**
 * How much of the traffic reader's dump this will hold.
 *
 * A Cilium policy-map dump for one node. The reader is a pod holding `pods/exec` in `kube-system`
 * and nothing else — which is to say it holds a permission this process deliberately does not, so
 * its answer is bounded like every other body that crosses into here.
 */
const MAX_TRAFFIC_DUMP_BYTES = 8 * 1024 * 1024;

/**
 * How often one source address may reach the two certificate-less enrollment routes.
 *
 * ## What is being limited, and why it is not "requests"
 *
 * Both routes read and parse the whole enrollment store **synchronously**, and one of them takes the
 * `O_EXCL` lock, which is waited on with `Atomics.wait` — also synchronously. So each admitted
 * request is a slice of this process's event loop during which nothing else is served, including
 * the console and `/site`. That cost grows with the store, which only ever gets bigger.
 *
 * A real agent enrols once and then polls for its certificate every few seconds until it is signed.
 * Thirty in a minute is far above that and far below anything that would matter.
 *
 * ## What this is not
 *
 * Not a defence against a distributed source, and not a substitute for the shape check in front of
 * it. It is the bound on how much one caller can spend, which is the part that was missing.
 */
const ENROLLMENT_RATE_WINDOW_MS = 60_000;
const ENROLLMENT_RATE_MAX = 30;
/** Distinct source addresses tracked. Beyond this the oldest window is dropped, never the newest. */
const ENROLLMENT_RATE_SOURCES = 1_024;

/**
 * How long an HTTP request will wait for the enrollment lock.
 *
 * ## Why the manager's answer is not the CLI's
 *
 * `withEnrollmentTransaction` defaults to ten seconds, which is right for `heliopause-enrollment`:
 * a person at a terminal can wait, and giving up early would fail an operator's write because a
 * request happened to be mid-flight.
 *
 * It is wrong here, and the reason is what the wait costs rather than how long it is. The
 * transaction is **fully synchronous** — `openSync`, a synchronous read, the mutation, a synchronous
 * write and two `fsync`s — and the spin between attempts is `Atomics.wait`, which blocks the thread.
 * So a waiting request does not wait *beside* the rest of the manager; it stops it. Ten seconds of
 * that is ten seconds in which the console, `/site` and every heartbeat poll are frozen.
 *
 * ## What can actually make it wait
 *
 * Not another request. Node is single-threaded and this path never yields, so two transactions in
 * this process cannot interleave — the lock is always free when a route takes it. The only
 * contenders are *other processes*: an operator running `heliopause-enrollment` on the same host,
 * and — the case that matters — a **stale `.lock` left by a crash**, which by design is never
 * reclaimed automatically.
 *
 * With a stale lock, every enrollment write froze the manager for ten seconds and then answered 503.
 * At 100ms it answers 503 just as correctly and the freeze is unnoticeable. The operator's own
 * command still waits the full ten seconds, which is where waiting belongs.
 */
const ENROLLMENT_HTTP_LOCK_WAIT_MS = 100;

/** Fixed-window counter per source. Exported for its test; the state is the caller's. */
export function rateLimited(
  seen: Map<string, { windowStartedAt: number; count: number }>,
  key: string,
  nowMs: number,
  limit = ENROLLMENT_RATE_MAX,
  windowMs = ENROLLMENT_RATE_WINDOW_MS,
  maxKeys = ENROLLMENT_RATE_SOURCES,
): boolean {
  const found = seen.get(key);
  if (!found || nowMs - found.windowStartedAt >= windowMs) {
    // Re-inserted rather than mutated, so `Map` insertion order tracks recency and the eviction
    // below drops the least recently *started* window instead of an arbitrary one.
    seen.delete(key);
    seen.set(key, { windowStartedAt: nowMs, count: 1 });
    while (seen.size > maxKeys) {
      const oldest = seen.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      seen.delete(oldest);
    }
    return false;
  }
  found.count += 1;
  return found.count > limit;
}

/**
 * Fetch the policy as data and render it here.
 *
 * The replacement for the `await import(sitePath)` that was C1. Nothing in this function evaluates
 * anything from the policy repository: it reads JSON over HTTP, validates its shape, and hands it to
 * the same `buildScreen` the workstation uses. `repo` is passed through because this process has no
 * checkout — without it the coverage table would say "not measured" and the history table would be
 * empty, both of which are false sentences about facts that exist a pod away.
 */
async function fetchPolicySource(
  src: NonNullable<ManagerOptions["policySource"]>,
  timeoutMs: number,
): Promise<PolicySource> {
  const call = src.fetch ?? fetch;
  const res = await call(`${src.url.replace(/\/$/, "")}/source`, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: src.token ? { authorization: `Bearer ${src.token}` } : {},
  });
  // Counted while reading, not measured afterwards. This process is the one holding the signing
  // key and the renderer is the untrusted side of the connection, so "buffer it all and then check"
  // is a limit enforced by the OOM killer rather than by this line. `text.length` was also the
  // wrong unit — UTF-16 code units, not bytes.
  const text = await readBoundedText(res, MAX_POLICY_SOURCE_BYTES, "the renderer");
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`the renderer returned ${res.status} and not JSON`);
  }
  if (!res.ok) {
    // The renderer's own sentence, which names the field or the throw in the policy module. A bare
    // status here would send the reader to the network layer for a syntax error in a rule.
    throw new Error(String((body as { error?: string }).error ?? `the renderer returned ${res.status}`));
  }
  return parsePolicySource(body);
}

/** Assemble the page: policy from the renderer, fleet from the relays this manager already polls. */
async function renderPolicyScreen(
  src: NonNullable<ManagerOptions["policySource"]>,
  relays: ManagerOptions["relays"],
  timeoutMs: number,
): Promise<{ screen: Screen; source: PolicySource }> {
  const source = await fetchPolicySource(src, timeoutMs);
  // The same assembly `/site` answers with, so the hosts table here and the console's own table
  // cannot disagree about the fleet — two differently-aged answers on one screen is the kind of
  // instrument that makes a reader trust the wrong one.
  let fleet = null as Parameters<typeof buildScreen>[0]["fleet"];
  try {
    fleet = siteView(await pollRelays(relays, timeoutMs)) as typeof fleet;
  } catch {
    // A relay that will not answer costs the fleet columns, not the page.
  }
  const screen = buildScreen({
    site: screenSiteOf(source),
    // A label, and never a path: this process has no policy on its filesystem, so a filename here
    // would name a file that does not exist in the process printing it.
    sitePath: source.label,
    label: source.label,
    repo: source.repo,
    fleet,
  });
  return { screen, source };
}

/** GET /status on one relay, with an operator certificate. */
function getFleetView(
  relayUrl: string,
  tls: { cert: Buffer; key: Buffer; ca: Buffer },
  timeoutMs: number,
): Promise<FleetView> {
  return relayCall<FleetView>(relayUrl, "/status", "GET", null, tls, timeoutMs);
}

/**
 * One request to one relay, with that VPC's credentials.
 *
 * Shared by the read and write paths deliberately. The certificate selection is the part that is easy
 * to get wrong — each VPC has its own CA, and presenting the wrong certificate produces a TLS error
 * that reads like the relay being broken (V39) — so there is one place that does it.
 */
function relayCall<T>(
  relayUrl: string,
  path: string,
  method: "GET" | "POST",
  body: string | Buffer | null,
  tls: { cert: Buffer; key: Buffer; ca: Buffer },
  timeoutMs: number,
): Promise<T> {
  const url = new URL(path, relayUrl);
  return new Promise((settleOk, settleErr) => {
    // ## `timeout` is inactivity; this is the wall clock
    //
    // `request({ timeout })` is `socket.setTimeout` — every byte resets it, so a relay answering one
    // byte at a time never trips it. This runs **in the manager**, a single pod, and it is the fan-out
    // behind `/site` as well as the push behind `/publish`. A hung call there is an HTTP request that
    // never answers, holding the plan lock with it.
    //
    // The `/publish` call site already reasoned about the timeout *value* — "a timeout here would
    // abandon a push that may well have landed" — and that is exactly as true of the idle timeout it
    // was reasoning about. What changes here is that the wait is now bounded at all; an indefinite
    // hang leaves the plan unpublishable and the operator with no answer, which is strictly worse
    // than an error the existing `catch` already knows how to release.
    //
    // Cleared on every exit rather than `unref`'d: an unref'd timer still fires, and firing after a
    // successful call would destroy a socket the agent may have handed to the next one.
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const clear = () => { if (deadline !== undefined) clearTimeout(deadline); deadline = undefined; };
    const resolve = (v: T) => { clear(); settleOk(v); };
    const reject = (e: unknown) => { clear(); settleErr(e); };

    const req = request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method,
        cert: tls.cert,
        key: tls.key,
        ca: tls.ca,
        timeout: timeoutMs,
        ...(body !== null
          ? {
              headers: {
                "content-type": "application/json",
                "content-length": Buffer.byteLength(body),
              },
            }
          : {}),
      },
      (res) => {
        // ## Decoded once, on the whole body — not per chunk
        //
        // This was `let payload = ""; res.on("data", (c) => (payload += c))`, which calls
        // `Buffer.prototype.toString()` on each chunk **independently**. A multi-byte character
        // split across a TCP boundary therefore becomes two U+FFFD replacement characters, and the
        // damaged JSON still parses — so the failure is a wrong value on the screen rather than an
        // error anywhere. Measured: a Korean string split at four different offsets came back
        // corrupted at every one, and `JSON.parse` accepted all four.
        //
        // `/status` is where it bites. A `FleetView` carries the agent's own `detail` (nft's error
        // text), `intrusions[].raw` (a line from `nft monitor`), `workloadDetail`, and the
        // `maintenance` reason a person wrote in the policy — the four fields most likely to be
        // non-ASCII, on the endpoint whose whole job is saying what is wrong.
        //
        // `api-client.ts` already collected chunks and concatenated once. This is now the same.
        readBoundedNodeBody(res, MAX_RELAY_RESPONSE_BYTES, `relay ${url.host}`).then(
          (buffer) => {
            const payload = buffer.toString("utf8");
            if (res.statusCode !== 200) {
              // The relay's own message, not a generic one — it distinguishes "not an operator" from
              // "no manifest loaded", and those need different fixes.
              return reject(new Error(`relay answered ${res.statusCode}: ${payload.slice(0, 300)}`));
            }
            try {
              resolve(JSON.parse(payload) as T);
            } catch (e) {
              reject(new Error(`relay sent unparseable JSON: ${(e as Error).message}`));
            }
          },
          reject,
        );
      },
    );
    // Inactivity, kept beside the deadline: a relay that has gone silent should not have to wait out
    // the whole deadline, and a relay that is answering too slowly to finish is a different thing.
    req.on("timeout", () => req.destroy(new Error(`no answer within ${timeoutMs}ms`)));
    deadline = setTimeout(() => {
      req.destroy(new Error(`relay ${url.host} did not finish answering within ${timeoutMs}ms`));
    }, timeoutMs);
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

/**
 * Where the IdP sends the browser after an RP-initiated logout.
 *
 * Derived from the redirect URI rather than configured separately, the same reasoning the
 * back-channel logout URI is derived: they are the same origin by construction, and a second
 * variable is a second thing to get wrong. `/` because that is where a signed-out operator belongs —
 * the login page.
 */
export function postLogoutRedirectUri(redirectUri: string): string {
  return new URL("/", redirectUri).toString();
}

/** Exact bounded representation shared by manager, relay socket, and the persisted denylist. */
export function revocationReplicationBody(revocations: readonly CertificateRevocation[]): Buffer {
  return serializeRevocationSnapshot({ schemaVersion: 1, revocations: [...revocations] });
}

/**
 * Start the manager. Returns the server so a caller can close it.
 *
 * Holds no state of its own: every answer is assembled from the relays at request time. That means a
 * restart costs nothing and there is no cache to go stale — the freshness question is answered by
 * each relay's own `relayAgeSec` and by the heartbeat ages inside it.
 */
export async function startManager(opts: ManagerOptions): Promise<{ server: Server }> {
  const writeLog = opts.log ?? ((m: string) => console.error(`[manager] ${m}`));
  const logEvent = (key: Parameters<typeof formatOperatorLog>[1], params: Record<string, string | number> = {}) =>
    writeLog(`[manager] ${formatOperatorLog(opts.logLang ?? "en", key, params)}`);
  const log = (en: string, ko: string) => writeLog(`[manager] ${formatOperatorEvent(opts.logLang ?? "en", { en, ko })}`);
  if ((opts.oidc?.soloApprovalRoles?.length ?? 0) > 0 && !opts.otp) {
    throw new Error("oidc.soloApprovalRoles requires otp — solo approval may not run without a second factor");
  }
  if (opts.enrollment) {
    // Initialization is an explicit operator action. Treating a missing store as first boot here
    // cannot be distinguished from deletion of a populated revocation ledger after a crash.
    requireEnrollmentDocument(opts.enrollment.storeFile);
  }
  if (opts.policyWorker) {
    if (!opts.enrollment || !opts.policySource || !opts.policyWrite) {
      throw new Error("policyWorker requires enrollment, policySource and policyWrite");
    }
    if (!opts.policyWrite.allowPaths.includes(opts.policyWorker.retiredHostsPath)) {
      throw new Error("policyWorker retiredHostsPath must be in policyWrite.allowPaths");
    }
    if (opts.relays.length === 0) throw new Error("policyWorker requires at least one configured relay");
    if (opts.policyWorker.intervalMs !== undefined
      && (!Number.isSafeInteger(opts.policyWorker.intervalMs) || opts.policyWorker.intervalMs < 1_000)) {
      throw new Error("policyWorker intervalMs must be an integer of at least 1000");
    }
  }
  let revocationSourceFormat: "snapshot" | "enrollment" = opts.revocationFile ? "snapshot" : "enrollment";
  if (opts.revocationFile && opts.enrollment) {
    try {
      revocationSourceFormat = await realpath(opts.revocationFile) === await realpath(opts.enrollment.storeFile)
        ? "enrollment"
        : "snapshot";
    } catch {
      // A missing source will fail closed when read. Resolve-only equality still handles the common
      // first-boot configuration where both environment variables name the same not-yet-created path.
      if (resolve(opts.revocationFile) === resolve(opts.enrollment.storeFile)) revocationSourceFormat = "enrollment";
    }
  }
  /**
   * What the policy repository's base branch is on, cached briefly.
   *
   * ## A second opinion, not a lookup
   *
   * The renderer reports the sha of the checkout it evaluated. On 2026-08-16 that value was frozen at
   * pod start for eleven hours and the screen printed it with no less confidence than usual — an
   * approver read pre-narrowing rules on the page where they approved the narrowing. The cache bug is
   * fixed; the shape that produced it is that the screen believed something about the repository and
   * nothing ever asked the repository. **A stale renderer cannot report its own staleness**, the same
   * way a stopped clock cannot report the time.
   *
   * Cached for a minute: the answer changes when somebody commits, not when somebody looks, and every
   * poll would otherwise spend an installation rate limit shared with the thing that actually needs
   * it — proposing.
   *
   * Failure is returned as failure. Answering `null` on error and letting the caller read that as
   * "matches" would rebuild the defect one layer up — a check that could not run must never look like
   * a check that passed.
   */
  let repoHeadCache: { at: number; sha: string } | null = null;
  const REPO_HEAD_TTL_MS = 60_000;
  async function currentRepoHead(): Promise<{ sha: string } | { error: string }> {
    if (!opts.policyWrite) return { error: "this console has no repository credential" };
    const at = now().getTime();
    if (repoHeadCache && at - repoHeadCache.at < REPO_HEAD_TTL_MS) return { sha: repoHeadCache.sha };
    try {
      const sha = await repoHead(
        opts.policyWrite.creds,
        opts.policyWrite.target,
        opts.policyWrite.fetch ?? (fetch as unknown as Fetcher),
        Math.floor(at / 1000),
      );
      repoHeadCache = { at, sha };
      return { sha };
    } catch (e) {
      return { error: (e as Error).message };
    }
  }

  /** Turn the two shas into the three states the screen draws. */
  async function freshnessOf(rendered: string | null): Promise<
    { state: "fresh" } | { state: "stale"; rendered: string | null; repository: string } | { state: "unknown"; why: string }
  > {
    const head = await currentRepoHead();
    if ("error" in head) return { state: "unknown", why: head.error };
    // A checkout with no git reports `null`, and that is not "fresh" — it is a page that cannot say
    // what it is showing, which is the state this banner was built to stop being invisible.
    if (!sameCommit(rendered, head.sha)) {
      return { state: "stale", rendered, repository: head.sha };
    }
    return { state: "fresh" };
  }

  const operators = new Set(opts.operatorCNs ?? []);
  const writers = new Set(opts.writerCNs ?? []);
  const authorizationTtlSec = opts.artifactSigning?.authorizationTtlSec ?? 24 * 60 * 60;
  if (!Number.isSafeInteger(authorizationTtlSec) || authorizationTtlSec < 15 * 60 || authorizationTtlSec > 7 * 24 * 60 * 60) {
    throw new Error("artifact signing authorizationTtlSec must be an integer between 900 and 604800");
  }
  if (opts.artifactSigning) artifactSigningKeyId(createPublicKey(opts.artifactSigning.privateKey));
  if (opts.tls.public && opts.tls.public.serverNames.length === 0) {
    throw new Error("public serverNames must contain at least one exact DNS name");
  }
  const replicateRevocations = async () => {
    if (!opts.enrollment) return [];
    const document = requireEnrollmentDocument(opts.enrollment.storeFile);
    const body = revocationReplicationBody(document.revocations);
    const snapshotFingerprints = document.revocations.map((row) => row.fingerprint256);
    const results = await Promise.all(opts.relays.map(async (relay) => {
      try {
        const tls = await loadRelayCreds(relay);
        const answer = await relayCall<{ count: number }>(relay.url, "/revocations", "POST", body, tls, opts.timeoutMs ?? 5_000);
        if (answer.count !== document.revocations.length) {
          throw new Error(`relay installed ${answer.count} revocations; expected ${document.revocations.length}`);
        }
        return { name: relay.name, ok: true as const, count: answer.count, snapshotFingerprints };
      } catch (e) {
        log(`revocation sync to ${relay.name} FAILED: ${(e as Error).message}`, `${relay.name}(으)로의 폐기 동기화 실패: ${(e as Error).message}`);
        return { name: relay.name, ok: false as const, error: (e as Error).message, snapshotFingerprints };
      }
    }));
    if (document.hostDeregistrations.length > 0) {
      enrollmentWrite(opts.enrollment.storeFile, (current) =>
        recordHostDeregistrationReplication(current, results, opts.relays.map((relay) => relay.name)));
    }
    return results;
  };

  // Only built when OIDC is configured, so a certificate-only deployment carries no session table and
  // no outbound dependency on an IdP.
  const oidc = opts.oidc
    ? {
        conf: opts.oidc,
        provider: new Provider(opts.oidc.issuer, opts.oidc.fetchImpl ?? fetch),
        sessions: new SessionStore({
          ttlSec: opts.oidc.sessionTtlSec ?? DEFAULT_SESSION_LIMITS.ttlSec,
          max: DEFAULT_SESSION_LIMITS.max,
        }),
        /**
         * In-flight logins, keyed by `state`.
         *
         * Server-side because the alternative is putting the PKCE verifier and the nonce in a cookie,
         * where they are readable by anything that can read cookies and survive longer than the ten
         * seconds they are needed for. Entries are deleted on use — a `state` is single-use, which is
         * what stops a captured callback URL being replayed.
         */
        pending: new Map<string, PendingOidcLogin>(),
        // Applied role-change tokens, so a captured one cannot be replayed to restore a role.
        ledger: new RoleChangeLedger(),
      }
    : null;
  const timeoutMs = opts.timeoutMs ?? 5_000;
  const publishTimeoutMs = opts.publishTimeoutMs ?? 30_000;
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const now = opts.now ?? (() => new Date());
  const authorizationTimestamps = new AuthorizationTimestampIssuer();

  /**
   * Per-source counters for the two enrollment routes a caller reaches without a certificate.
   *
   * In memory and per process, like the sessions and the pending plans. A restart forgives everyone,
   * which is the right trade for a bound whose job is to stop one caller monopolising the event loop
   * rather than to be an access-control decision.
   */
  /**
   * Every enrollment transaction this server takes, with the HTTP wait rather than the CLI one.
   *
   * A wrapper rather than an argument at each of the eight call sites, because eight is exactly the
   * number at which one gets missed — and the one that gets missed is the one that freezes the
   * process. See `ENROLLMENT_HTTP_LOCK_WAIT_MS`.
   */
  const enrollmentWrite = <T>(storeFile: string, mutate: (document: EnrollmentDocument) => T): T =>
    withEnrollmentTransaction(storeFile, mutate, { waitMs: ENROLLMENT_HTTP_LOCK_WAIT_MS });

  const enrollmentHits = new Map<string, { windowStartedAt: number; count: number }>();
  const enrollmentFloodRefused = (req: IncomingMessage, res: ServerResponse): boolean => {
    const source = req.socket.remoteAddress ?? "unknown";
    if (!rateLimited(enrollmentHits, source, now().getTime())) return false;
    log(
      `enrollment request refused for ${source}: more than ${ENROLLMENT_RATE_MAX} in ${ENROLLMENT_RATE_WINDOW_MS / 1000}s`,
      `${source}의 등록 요청 거부: ${ENROLLMENT_RATE_WINDOW_MS / 1000}초에 ${ENROLLMENT_RATE_MAX}건 초과`,
    );
    send(res, 429, { error: "too many enrollment requests from this address" });
    return true;
  };

  // ## Why pending plans live in memory and that is acceptable
  //
  // A restart loses them. That is a worse property than it sounds for approvals in general and an
  // acceptable one here, because of what is lost: an unpublished plan. Nothing that was published is
  // in this map — the relays hold that, and git holds the policy — so a restart costs a re-propose and
  // a re-approve, never a firewall state.
  //
  // The alternative is persistence, which for this manager means a volume in the cluster whose
  // firewall it governs. That is a dependency in the wrong direction: the way *out* of an incident
  // would need storage that the incident may have taken with it. The design is explicit that the
  // manager is expendable (결정 5.1) and this keeps it so.
  //
  // What it does mean: `POST /publish` for a plan this process never saw answers 409 with "re-propose
  // it", not 404 — an operator whose approval evaporated needs to know which of the two happened.
  const approvals = emptyApprovals();
  /** Plan hash → the bundle to push. Beside the plan, not inside it — see `POST /plan`. */
  const bundles = new Map<string, PlanBundle>();
  /** Plan hash → relay name. Stored at proposal so publishing cannot redirect the push. */
  const planTargets = new Map<string, string>();
  /**
   * The last bundle this process published to each target, so a later plan can be diffed against it.
   *
   * ## Why one per target and not a history
   *
   * The question an approver has is "what changes", which needs one base: what the fleet is running.
   * A history would invite comparing against something else, and nothing needs that.
   *
   * ## What it cannot answer, and says so
   *
   * Memory-only, like the plans. A restart empties it, and a generation published through the direct
   * path (`heliopause-publish` writing a gateway's artifact directory, which 결정 5 keeps as the way
   * out when this process is broken) never passes through here at all. In both cases the diff route
   * reports that it has no base rather than comparing against the wrong one — a diff against a base
   * the fleet is not running is worse than no diff, because it reads as authoritative.
   */
  const lastPublished = new Map<string, { generation: string; bundle: PlanBundle }>();

  /**
   * Recreate a worker proposal after a restart without recreating approval.
   *
   * The worker identity is intentionally not a configured writer: it reaches this function, never
   * the HTTP approve/publish handlers. A human writer sees the ordinary plan and must still approve
   * and publish it with the existing OTP/two-person gate.
   */
  async function proposePolicyRetirement(
    targetName: string,
    previous?: { generation: string; proposedAt: string },
  ): Promise<PolicyWorkerPlan> {
    if (!opts.policySource) throw new Error("policy worker has no renderer");
    const target = opts.relays.find((relay) => relay.name === targetName);
    if (!target) throw new Error(`policy worker target ${targetName} is not configured`);
    const source = await fetchPolicySource(opts.policySource, timeoutMs);
    if (source.head.sha === null || source.head.dirty) {
      throw new Error("policy worker cannot propose from an unnamed or dirty renderer checkout");
    }
    const site = screenSiteOf(source);
    const issuedAt = previous && sameCommit(previous.generation, source.head.sha)
      ? previous.proposedAt
      : now().toISOString();
    const plan = planPublish({
      cfg: site.cfg,
      generation: source.head.sha,
      issuedAt,
      hosts: site.hosts,
      ...(site.workload ? { workload: site.workload } : {}),
      ...(site.resolveService ? { resolveService: site.resolveService } : {}),
    } as Parameters<typeof planPublish>[0]);
    const bundle = bundleFromPlan(plan);
    const hash = planHash(targetName, bundle);
    propose(
      approvals,
      { hash, generation: bundle.manifest.generation, summary: summarise(bundle), by: "policy-worker", now: now() },
      limits,
    );
    bundles.set(hash, bundle);
    planTargets.set(hash, targetName);
    for (const key of bundles.keys()) {
      if (!approvals.plans.has(key)) {
        bundles.delete(key);
        planTargets.delete(key);
      }
    }
    return { relay: targetName, hash, generation: bundle.manifest.generation, proposedAt: issuedAt };
  }

  if (writers.size === 1) {
    // Said at startup, because the alternative is discovering it from a 403 while trying to change a
    // firewall. The mechanism is not broken — it is doing exactly what it was asked to do.
    log(
      `only one writer CN (${[...writers][0]}) — every plan would be proposed and approved by the ` +
        `same identity, which POST /approve refuses. Publishing goes through the direct path ` +
        `(heliopause-publish to the artifact directory) until a second operator exists.`,
      `작성자 CN이 하나뿐임 (${[...writers][0]}) — 모든 계획은 같은 신원이 제안·승인하게 되어 POST /approve가 거부함. 두 번째 운영자가 생길 때까지 직접 경로(아티팩트 디렉터리의 heliopause-publish)로 발행함.`,
    );
  }
  if (writers.size === 0) log("no writer CNs — the write endpoints will refuse everyone", "작성자 CN이 없음 — 쓰기 엔드포인트가 모두를 거부함");

  /**
   * Certificate name → every other writer name that is the same human.
   *
   * Built from `otp.users`, which is the only table in this process that says who a certificate
   * *is*. Two writer names mapping to one identity-provider account are one person, and `approval.ts`
   * compared names — so that person could propose under one and approve under the other, and the
   * plan would record a two-person approval.
   *
   * Measured on dev, 2026-08-24, before this existed:
   *
   *     HELIOPAUSE_WRITER_CNS = ops-henry,ops-henry-review
   *     HELIOPAUSE_OTP_USERS  = ops-henry=5b1ed54b-…, ops-henry-review=5b1ed54b-…
   *
   * Only writers are collapsed. A reader sharing an account with a writer changes nothing, and
   * including them would make the map answer a question nobody asks.
   */
  const sameHumanAs = new Map<string, string[]>();
  if (opts.otp) {
    const byAccount = new Map<string, string[]>();
    for (const [cn, userId] of opts.otp.users) {
      if (!writers.has(cn)) continue;
      byAccount.set(userId, [...(byAccount.get(userId) ?? []), cn]);
    }
    for (const [userId, names] of byAccount) {
      if (names.length < 2) continue;
      for (const cn of names) sameHumanAs.set(cn, names.filter((other) => other !== cn));
      // Said at startup for the same reason the one-writer case is: the alternative is finding out
      // from a 403 in the middle of a change. And unlike that one, this is a rule that **was not
      // being enforced** until now — an operator who has been approving this way will meet the
      // refusal, and needs to know why before they do.
      log(
        `writer CNs ${names.join(", ")} all map to identity-provider account ${userId} — they are ` +
          `one person, so POST /approve now refuses an approval between them. It used to accept it ` +
          `and record a two-person approval. Use a genuinely second operator, or an OIDC login with ` +
          `a solo-approval role, which records the approval as solo.`,
        `작성자 CN ${names.join(", ")} 이(가) 모두 IdP 계정 ${userId} 에 매핑됨 — 한 사람이므로 ` +
          `POST /approve 가 이제 이들 사이의 승인을 거부함. 예전에는 받아들이고 2인 승인으로 기록했음. ` +
          `실제 두 번째 운영자를 쓰거나, 단독 승인 역할의 OIDC 로그인을 쓸 것(그쪽은 단독으로 기록됨).`,
      );
    }
  }

  const [cert, key, ca] = await Promise.all([
    readFile(opts.tls.certFile),
    readFile(opts.tls.keyFile),
    readFile(opts.tls.caFile),
  ]);

  // `rejectUnauthorized: false`, and the relay next door uses `true`. The difference is deliberate
  // and it is safe only because of where the identity check lives.
  //
  // ## Why it had to change
  //
  // `/healthz` is documented below as unauthenticated, and under `rejectUnauthorized: true` it was
  // not reachable by anything that could not already read the whole fleet — the handshake is refused
  // before any route runs. So the endpoint existed and no caller could use it, and the Kubernetes
  // probe fell back to `tcpSocket`, which only proves a port is open.
  //
  // That is precisely what hid V46: the manager served a certificate with `extendedKeyUsage`
  // `clientAuth` for five hours, every correct TLS client was refused, and the pod reported `Ready`
  // the whole time because the probe never completed a handshake either.
  //
  // ## Why this does not open the door
  //
  // Authorisation does not live in the TLS layer here. `peerCN` returns null unless
  // `socket.authorized` is true, so a peer with a self-signed or untrusted certificate is
  // indistinguishable from one with none: both get null, and `/site` answers 401. What changes is
  // only that such a peer now completes a handshake and can reach the one route that tells it
  // nothing.
  //
  // **This is load-bearing on `peerCN` checking `socket.authorized`.** If that check is ever removed,
  // this flag turns a CN into an unverified claim, and anyone may self-sign `CN=ops-alice`.
  // The public certificate, when one is configured. Read here rather than inside the callback: a
  // disk read per handshake would be a way to make the server slow by connecting to it, and a file
  // that has gone missing should fail at startup where somebody is watching.
  // Held in a mutable box so a renewal can be installed without restarting the process. cert-manager
  // rotates this certificate every ~75 days; a manager that only read it at startup would serve an
  // expired one for as long as it stayed up, and this process is meant to stay up.
  const pub: { names: Set<string>; ctx: SecureContext | null; fingerprint: string | null } | null = opts.tls.public
    ? { names: new Set(opts.tls.public.serverNames.map((name) => name.toLowerCase())), ctx: null, fingerprint: null }
    : null;
  let refreshTimer: ReturnType<typeof setInterval> | null = null;
  /** The pending short retry, when this process is still without a public certificate. */
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  /**
   * Set when the server closes. The retry reschedules itself from inside a promise, so clearing the
   * handle is not enough on its own: a `load()` already in flight resolves afterwards and would
   * arm a fresh timer against a server that is gone.
   */
  let retryStopped = false;

  if (pub && opts.tls.public) {
    const conf = opts.tls.public;
    // Returns whether this process now holds a public certificate. The caller needs that answer to
    // decide whether to keep trying, and it used to return `void` — the failure was logged and then
    // nobody, including this function's own caller, could act on it.
    const refresh = async (): Promise<boolean> => {
      try {
        const b = await conf.load();
        if (b.fingerprint === pub.fingerprint) return true;
        // Read **before** the install below overwrites it. See the log line that uses it.
        const had = pub.fingerprint !== null;
        // `ca` is not optional here, and leaving it out is not a cosmetic omission. `requestCert`
        // is a server-level option but the **client** CA store is per-context, so a context built
        // without it verifies an operator's certificate against an empty store: the client is
        // offered an empty `certificate_authorities` list, sends nothing, and the manager sees a
        // connection with no client certificate. mTLS is off for that name and the log says the
        // caller did not present one.
        //
        // Measured in production 2026-08-06, same server and same certificate, SNI the only
        // difference: by IP `200 {"you":"ops-alice"}`, by name `401 no client certificate`. It fails
        // closed, so it denied rather than admitted — and it looked exactly like a broken client,
        // which is where the time went.
        pub.ctx = createSecureContext({ cert: b.cert, key: b.key, ca });
        pub.fingerprint = b.fingerprint;
        // ## Two lists, said separately, because they are two different facts
        //
        // This printed one list — the SNI allowlist — introduced as "the public certificate for
        // …". On 2026-08-11 a name was removed from the allowlist and this line changed
        // immediately, while the certificate in memory kept that name in its SAN for another hour
        // (`HELIOPAUSE_PUBLIC_REFRESH_SEC`). **Both teams read the line as the certificate's SAN**
        // and each recorded the removal as verified. It was caught by someone noticing the
        // fingerprint had not moved, not by any check.
        //
        // The lists are equal almost always, which is what makes the conflation survive: it is only
        // wrong in the window where something changed, i.e. exactly when someone is reading the log
        // to find out whether the change landed.
        //
        // So: what we answer for, what we are actually holding, and which certificate that is.
        const serving = b.sans.length ? b.sans.join(",") : "none stated";
        // The verb comes from what was held a moment ago, not from whether this is the first call.
        // Those were the same thing until a failed start could be retried; now a retry that succeeds
        // is the *first* certificate this process has had, and calling it a rotation would tell a
        // reader that one was replaced.
        log(
          `${had ? "rotated" : "loaded"} the public certificate ${b.fingerprint.slice(0, 17)} — ` +
            `answering SNI for ${[...pub.names].join(",")}; certificate SAN ${serving}`,
          `공개 인증서 ${b.fingerprint.slice(0, 17)}을(를) ${had ? "교체" : "불러옴"} — ${[...pub.names].join(",")}의 SNI에 응답; 인증서 SAN ${serving}`,
        );
        // A mismatch is not an error — a certificate may legitimately carry names this manager does
        // not answer for — but the reverse is a hole: a name in the allowlist with no SAN behind it
        // gets a certificate that fails hostname verification, which reads to the caller as a
        // broken client rather than a misconfigured server.
        const unbacked = [...pub.names].filter((n) => !b.sans.includes(n));
        if (unbacked.length && b.sans.length) {
          log(`  ⚠ no SAN for ${unbacked.join(",")} — callers using those names will fail hostname verification`, `  ⚠ ${unbacked.join(",")}에 SAN 없음 — 해당 이름을 쓰는 호출자의 호스트명 검증이 실패함`);
        }
        // How long the thing just loaded is good for. cert-manager renews 15 days out, so a number
        // under that means renewal has stopped and this process is serving a certificate on its way
        // to expiry — the failure that is invisible until the day browsers refuse the console.
        //
        // `daysUntilExpiry` existed and nothing called it: the fact was computable and nobody was
        // told. Said on every refresh rather than only when it is low, because a log that speaks
        // only in emergencies gives a reader no baseline to notice the change from.
        const days = daysUntilExpiry(b.cert);
        log(
          days <= 15
            ? `  ⚠ the public certificate expires in ${days} day(s) — renewal appears to have stopped`
            : `  expires in ${days} day(s)`,
          days <= 15
            ? `  ⚠ 공개 인증서가 ${days}일 뒤 만료됨 — 갱신이 중단된 것으로 보임`
            : `  ${days}일 뒤 만료됨`,
        );
        return true;
      } catch (e) {
        // Loud, and not fatal. Said at every failure rather than once, because the interesting case
        // is the one that starts failing weeks before anyone looks — a token revoked, or a renewal
        // that stopped. Silence here would spend the whole `renewBefore` window unnoticed.
        log(
          `public certificate for ${[...pub.names].join(",")} unavailable: ${(e as Error).message}` +
            (pub.ctx ? " — keeping the one already loaded" : " — serving the internal certificate only"),
          `${[...pub.names].join(",")}의 공개 인증서를 사용할 수 없음: ${(e as Error).message}` +
            (pub.ctx ? " — 이미 불러온 인증서를 유지함" : " — 내부 인증서만 제공함"),
        );
        return false;
      }
    };
    const everyMs = Math.max(60, conf.refreshSec ?? 3600) * 1000;

    // ## Retrying while there is no certificate at all
    //
    // The two failures this function can have are not the same size, and the schedule used to treat
    // them as one. Losing a *refresh* while holding a valid certificate costs nothing for an hour —
    // renewal happens 15 days out. Losing the *first* load costs both public names for an hour:
    // `heliopause.tinyuniver.se` serves a certificate whose SAN does not contain it, so a browser
    // refuses the console, and `node-enroll.tinyuniver.se` does the same to every fleet host trying
    // to post a CSR.
    //
    // Measured 2026-08-18. The manager rolled out while `dispatch.tinyuniver.se` was briefly slow,
    // the one startup attempt timed out, and the pod then sat `Running 1/1` with `/healthz` green
    // and both public names broken. The cert API answered in 138ms throughout — the outage was
    // entirely the schedule, and nothing but a single log line said so.
    //
    // So this ladder runs **only while `pub.ctx` is null**. It is not a general retry: once a
    // certificate is held the hourly cadence is the right one, and adding urgency there would turn a
    // renewal that fails for a week into a request every five seconds for a week.
    const retryBaseMs = Math.min(Math.max((conf.retrySec ?? 5) * 1000, 10), everyMs);
    let retryMs = retryBaseMs;
    const retryUntilLoaded = () => {
      if (retryStopped) return;
      const t = setTimeout(() => {
        void refresh().then((ok) => {
          if (ok) return;
          // Doubling, capped at the ordinary interval. Uncapped it would overtake `refreshSec` and
          // become slower than doing nothing; without doubling, a cert API that is down for an hour
          // gets seven hundred requests from a process whose whole point is to be expendable.
          retryMs = Math.min(retryMs * 2, everyMs);
          retryUntilLoaded();
        });
      }, retryMs);
      // Same reason as the interval below: a pending retry must not be what keeps this process alive.
      t.unref();
      retryTimer = t;
    };
    if (!(await refresh())) retryUntilLoaded();

    refreshTimer = setInterval(() => void refresh(), everyMs);
    // Do not hold the event loop open for a refresh. The server's own handle is what keeps this
    // process alive; a timer that outlives it would stop `close()` from ending the process.
    refreshTimer.unref();
  }

  const server = createServer(
    {
      cert,
      key,
      ca,
      requestCert: true,
      rejectUnauthorized: false,
      // Exact match, lower-cased. A suffix match would hand the public certificate to
      // `notconsole.example.com` when the name is `console.example.com`, and an SNI name is
      // attacker-chosen text.
      //
      // Returning `undefined` means "use the server's default context" — the internal certificate —
      // which is what an IP connection gets, because an IP is not a legal SNI name and clients send
      // no `server_name` for one.
      ...(pub
        ? {
            SNICallback: (servername: string, cb: (e: Error | null, c?: SecureContext) => void) =>
              // `pub.ctx ?? undefined` matters: before the first successful fetch, and after a
              // failure that left nothing loaded, the name falls back to the internal certificate
              // rather than the handshake failing. A browser then sees a certificate warning, which
              // is a worse experience and a much better outcome than an unreachable console.
              cb(null, pub.names.has(servername.toLowerCase()) ? (pub.ctx ?? undefined) : undefined),
          }
        : {}),
    },
    (req: IncomingMessage, res: ServerResponse) => {
      void (async () => {
        if (opts.intercept && await opts.intercept(req, res)) return;
        await handle(req, res);
      })().catch((e) => {
        logEvent("server.unhandled", { error: (e as Error).message });
        if (!res.headersSent) res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal error" }));
      });
    },
  );

  async function handle(req: IncomingMessage, res: ServerResponse) {
    const cn = peerCN(req);
    const url = new URL(req.url ?? "/", "https://manager.invalid");

    // The data routes also answer under `/api/`. Step one of three; see `API_ROUTES`.
    //
    // Before the certificate check on purpose: this rewrites the path and nothing else, so every
    // route keeps the authentication it had. Putting it after would make `/api/x` a way around the
    // check on `/x`, which is the worst thing this change could do and is one line away.
    if (url.pathname.startsWith("/api/")) {
      const bare = url.pathname.slice("/api".length);
      if (API_ROUTES.has(bare) || API_ROUTE_PATTERNS.some((p) => p.test(bare))) url.pathname = bare;
    }

    // Unauthenticated and deliberately empty, like the relay's. It proves the listener is up without
    // telling an unauthenticated caller anything about the fleet.
    if (req.method === "GET" && url.pathname === "/healthz") return send(res, 200, { ok: true });
    if (certificateIsRevoked(
      opts.revocationFile ?? opts.enrollment?.storeFile,
      req,
      revocationSourceFormat,
    )) {
      log(`refused ${url.pathname}: client certificate fingerprint is revoked`, `${url.pathname} 거부: 클라이언트 인증서 지문이 폐기됨`);
      return send(res, 401, { error: "client certificate has been revoked" });
    }

    // Bootstrap agents have no certificate yet; their one credential is a host-scoped bearer token.
    // These two routes therefore run before operator authentication and expose only that token's CSR.
    if (opts.enrollment && req.method === "POST" && url.pathname === "/infra/node-csrs") {
      try {
        const token = String(req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
        // ## Shape first, because everything after this reads a file synchronously
        //
        // This route runs before operator authentication — a bootstrapping agent has no certificate
        // yet — and the manager listens with `rejectUnauthorized: false`, so anyone who completes a
        // handshake reaches it. `requireEnrollmentDocument` then reads and parses the whole
        // enrollment store on the event loop, before the token has been checked at all.
        //
        // A shape test is not authentication and is not meant to be: `lookupNodeToken` still hashes
        // and compares, inside the transaction, exactly as before. What this removes is the file read
        // for a caller who has not presented something shaped like a token.
        //
        // 🔴 **It used to test the prefix alone, and the prefix is public.** `NODE_TOKEN_PREFIX` is
        // `"stnode_"`, seven characters in tracked source — so "a caller holding a well-formed but
        // wrong token" was every caller, and the mitigation this comment described was worth nothing.
        // `looksLikeNodeToken` checks the full emitted shape (prefix + 64 hex), which is what
        // `createNodeToken` produces and costs the same.
        //
        // The rate limit below is the other half: a caller who *is* guessing in the right space still
        // must not be able to spend this process's event loop on synchronous reads.
        if (!looksLikeNodeToken(token)) return send(res, 401, { error: "unauthorized node token" });
        if (enrollmentFloodRefused(req, res)) return;
        const body = JSON.parse(await readBody(req, 24 * 1024)) as { csrPem?: unknown };
        if (typeof body.csrPem !== "string") return send(res, 400, { error: "csrPem required" });
        const csrPem = body.csrPem;
        // Reject an expired token, an exact replay, or a host already at its unresolved-CSR cap
        // before starting OpenSSL. Expensive parsing runs in a bounded worker; the transaction then
        // repeats token/cap checks so a concurrent revoke or submission cannot cross the boundary.
        const preflight = preflightNodeCsr(requireEnrollmentDocument(opts.enrollment.storeFile), { csrPem, token });
        let result;
        if (preflight.existing) {
          result = enrollmentWrite(opts.enrollment.storeFile, (document) =>
            touchExistingNodeCsr(document, { csrPem, token }));
        } else {
          const csr = await validateNodeCsrAsync(csrPem, preflight.hostname);
          result = enrollmentWrite(opts.enrollment.storeFile, (document) =>
            submitValidatedNodeCsr(document, {
              csr, token, sourceIp: req.socket.remoteAddress ?? null,
            }));
        }
        return send(res, result.created ? 201 : 200, { ok: true, created: result.created, request: {
          id: result.row.id, hostname: result.row.hostname, status: result.row.status,
          csrSha256: result.row.csrSha256, createdAt: result.row.createdAt,
        } });
      } catch (e) { return sendEnrollmentError(res, e); }
    }
    const certificateFetch = /^\/infra\/node-csrs\/([^/]+)\/certificate$/.exec(url.pathname);
    if (opts.enrollment && req.method === "GET" && certificateFetch) {
      try {
        const token = String(req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
        // Same reasoning as `POST /infra/node-csrs` above, and one degree worse: the transaction
        // below takes the `O_EXCL` enrollment lock before checking anything, and that lock is waited
        // on with `Atomics.wait` — synchronously, on this thread.
        if (!looksLikeNodeToken(token)) return send(res, 401, { error: "unauthorized node token" });
        if (enrollmentFloodRefused(req, res)) return;
        const certificate = enrollmentWrite(opts.enrollment.storeFile, (document) =>
          fetchNodeCertificate(document, decodeURIComponent(certificateFetch[1]!), token, req.socket.remoteAddress ?? null));
        return send(res, 200, { ok: true, certificate });
      } catch (e) { return sendEnrollmentError(res, e); }
    }

    // ── The third principal: a program holding a scoped bearer token ──────────
    //
    // Split off **before** the certificate and session resolution below, and not folded into it.
    // Three reasons, and the middle one is the whole feature:
    //
    //   · an app token is not a person, so it must never reach `requireOtp` — that function resolves
    //     a KeyStone *user* and checks that user's one-time code, and there is nobody here to check;
    //   · it is not a browser, so it must not pick up a cookie session, a login redirect, or the
    //     CSRF header check, all of which are written against a session that does not exist;
    //   · a caller presenting a certificate *and* an app token is resolved as one of them rather
    //     than as whichever turns out to be more permissive further down.
    //
    // Shape first for the same reason as the two routes above: `looksLikeAppToken` is not
    // authentication, it is what keeps a caller who typed something else out of a synchronous read
    // of the whole enrollment store. The store read comes after it and after the rate limit.
    if (opts.enrollment) {
      const bearer = String(req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
      if (looksLikeAppToken(bearer)) return await handleAppToken(bearer, url, req, res, opts.enrollment.storeFile);
    }

    // ── The login routes, before any authorisation ────────────────────────────
    //
    // Deliberately reachable without a principal: their whole job is to produce one. Each is
    // individually harmless to an anonymous caller — `/auth/login` hands out a redirect to the IdP,
    // `/auth/callback` fails without a `state` this server issued, and `/auth/logout` ends a session
    // the caller must already hold.
    if (oidc && url.pathname.startsWith("/auth/")) {
      return await handleAuth(oidc, url, req, res);
    }

    // The distinction below is `Accept`, not the path: a `fetch` from the already-loaded page must be
    // treated as machinery, or a poll after the session expires fills the page with login HTML.
    const wantsHtml = String(req.headers["accept"] ?? "").includes("text/html");

    // ## A certificate is not a browser login
    //
    // Certificates still authenticate the CLI — `heliopause-publish --propose`, `-status`,
    // `-approve` and `-enrollment` have no other credential, and they are also the way in when the
    // IdP is down. What they no longer do is sign anybody in to a *page*: an HTML request is
    // resolved from the session alone, and a browser that happens to hold a client certificate is
    // sent to the IdP like any other.
    //
    // The reason is what a certificate cannot say. Authorisation here reads group claims — that is
    // why `maySoloApprove` requires `via === "oidc"` — and a certificate carries a CN and nothing
    // else, so an operator arriving that way is a name with no role.
    //
    // **Guarded on `oidc` being configured.** With no IdP there is no other way to reach the console,
    // and disabling the one that works would lock the operator out of their own firewall.
    const certIsAcceptable = !(oidc && wantsHtml);
    const session = oidc ? oidc.sessions.get(readCookie(req.headers["cookie"], COOKIE)) : null;

    // ## The session wins, and the `Accept` rule above is not enough on its own
    //
    // Refusing the certificate for HTML fixes the *page* and leaves everything the page calls. The
    // console's `fetch` sets no `Accept`, so the browser sends `*/*`, which does not contain
    // `text/html` — a signed-in operator whose browser also holds a client certificate would render
    // the console from their session and then have every `/site`, `/plans`, `/approve` and
    // `/policy/plan` behind it resolved as the certificate instead. Measured after shipping the
    // `Accept` rule alone: `curl --cert … /site` with a default `Accept` answered 200.
    //
    // Three things follow from that, and none of them are visible on the screen: the solo-approve
    // control disappears because `maySoloApprove` needs `via === "oidc"`; `canWrite` comes from
    // `writerCNs` rather than from the group decision the session already made; and **the CSRF check
    // is skipped entirely**, because it too is gated on `via === "oidc"`.
    //
    // So the order is session first. A CLI never carries a cookie, which is what makes this safe to
    // state so bluntly: presenting both is a browser, and a browser that has signed in has already
    // said who it is with claims a certificate cannot carry.
    const principal: Principal | null = session?.principal
      ?? (cn && certIsAcceptable
        ? { name: cn, sub: cn, groups: [], via: "certificate", canWrite: writers.has(cn) }
        : null);

    if (!principal) {
      // Every page, not just the console root. `/policy` used to answer 401 JSON to a browser that
      // followed a link to it, which reads as a broken site rather than as "sign in first".
      //
      // `next` carries them back afterwards; `safeReturnTo` is what keeps that from being an open
      // redirect. GET only — a 302 turns a POST into a GET, so a form would arrive stripped of its
      // body and look like it had been submitted.
      if (oidc && wantsHtml && req.method === "GET") {
        const next = `${url.pathname}${url.search}`;
        const to = safeReturnTo(next) ? `/auth/login?next=${encodeURIComponent(next)}` : "/auth/login";
        res.writeHead(302, { location: to, "cache-control": "no-store" });
        return void res.end();
      }
      return send(res, 401, {
        error: oidc
          ? "no client certificate and no session — sign in at /auth/login"
          : "client certificate carries no subject CN",
      });
    }

    // Two allowlists, one decision point. A certificate is checked against `operatorCNs`; a session
    // was already checked against the group claims when it was created, and carrying that decision
    // rather than re-deriving it is what keeps one identity from being evaluated two ways.
    const isOperator = principal.via === "certificate" ? operators.has(principal.name) : true;
    if (!isOperator) {
      log(`refused ${url.pathname} for ${principal.name}: not an operator`, `${principal.name}의 ${url.pathname} 거부: 운영자가 아님`);
      return send(res, 403, { error: "this certificate is not authorised to read the site view" });
    }

    // ## CSRF for cookie sessions
    //
    // The check below covers the certificate path. A cookie needs more, because the browser attaches
    // it to cross-site requests in ways it does not attach a certificate, and because this site chose
    // full write parity for sessions. `session.ts` explains the three layers; this is where the third
    // one — a token in a header no cross-origin form can set — is enforced.
    if (req.method === "POST" && session && principal.via === "oidc") {
      const refusal = checkCsrf(
        session,
        {
          origin: typeof req.headers["origin"] === "string" ? req.headers["origin"] : undefined,
          referer: typeof req.headers["referer"] === "string" ? req.headers["referer"] : undefined,
          csrf: typeof req.headers[CSRF_HEADER] === "string" ? (req.headers[CSRF_HEADER] as string) : undefined,
        },
        `https://${req.headers["host"] ?? ""}`,
      );
      if (refusal) {
        log(`refused ${url.pathname} for ${principal.name}: csrf (${refusal})`, `${principal.name}의 ${url.pathname} 거부: CSRF (${refusal})`);
        return send(res, 403, {
          error:
            refusal === "origin"
              ? "cross-site requests cannot change the fleet"
              : "missing or invalid CSRF token — reload the console",
        });
      }
    }

    // Kept so the existing certificate-path code below reads unchanged. Every use of `cn` from here
    // on means "the authenticated principal's name", which is what it always meant.
    const who = principal.name;
    // One boolean, one place. Certificates read the live allowlist; sessions carry the decision
    // taken at login — see `Principal.canWrite` for why that is stated rather than hidden.
    const mayWrite = principal.canWrite;
    // Solo approval is a role, and only ever an OIDC one: a certificate carries no role claim, so a
    // CLI caller can never approve their own plan. That asymmetry is deliberate rather than an
    // oversight — the browser path is the one with a one-time code prompt in front of a person, and
    // the rule this switches off is worth keeping wherever it can be kept.
    const soloRoles = new Set(opts.oidc?.soloApprovalRoles ?? []);
    const maySoloApprove =
      principal.via === "oidc" && principal.groups.some((g) => soloRoles.has(g));

    if (opts.enrollment && req.method === "GET" && url.pathname === "/enrollment/requests") {
      try {
        const filter = csrQueryFilter(url);
        const requests = requireEnrollmentDocument(opts.enrollment.storeFile).requests
          .filter((row) => matchesCsrFilter(row, filter));
        return send(res, 200, { requests });
      } catch (e) { return sendEnrollmentError(res, e); }
    }
    if (opts.enrollment && req.method === "GET" && url.pathname === "/enrollment/tokens") {
      const tokens = requireEnrollmentDocument(opts.enrollment.storeFile).tokens.map(({ tokenHash: _secret, ...row }) => row);
      return send(res, 200, { tokens });
    }
    // The hash is stripped for the same reason the node token list strips its own: the store holds
    // only a digest, and a digest is still an offline guessing target for a value this file also
    // says is 32 random bytes.
    if (opts.enrollment && req.method === "GET" && url.pathname === "/enrollment/app-tokens") {
      const tokens = requireEnrollmentDocument(opts.enrollment.storeFile).appTokens.map(({ tokenHash: _secret, ...row }) => row);
      return send(res, 200, { tokens });
    }
    if (opts.enrollment && req.method === "GET" && url.pathname === "/enrollment/audit") {
      return send(res, 200, { events: requireEnrollmentDocument(opts.enrollment.storeFile).audit });
    }
    if (opts.enrollment && req.method === "GET" && url.pathname === "/enrollment/revocations") {
      // ## The remaining capacity travels with the list
      //
      // `MAX_REVOCATION_ROWS` is a hard ceiling, and `revocation-snapshot.ts` calls reaching it
      // "the one failure a denylist cannot have" — past it, a new revocation is refused. Compaction
      // exists (`planRevocationCompaction`, and `heliopause-revocations` drives it) but it is an
      // operator action taken with the writer stopped.
      //
      // Nothing reported how close the list was. `/status`, `/site` and `/authz` all said nothing,
      // so the first sign would have been a refused revocation during whatever incident prompted it.
      // A number here is the cheapest version of the warning.
      const revocations = requireEnrollmentDocument(opts.enrollment.storeFile).revocations;
      return send(res, 200, {
        revocations,
        capacity: {
          used: revocations.length,
          max: MAX_REVOCATION_ROWS,
          remaining: Math.max(0, MAX_REVOCATION_ROWS - revocations.length),
        },
      });
    }

    // ## Cross-site requests, refused before any write route runs
    //
    // mTLS authenticates the *client*, and a browser attaches its client certificate automatically to
    // every request to this origin — including one a different site caused. So an operator with the
    // console's certificate in their keychain carries the ability to approve a plan into every page
    // they visit, and an HTML form posting `text/plain` needs no preflight to reach here.
    //
    // Measured 2026-08-03 before the console gained any write control: a request carrying
    // `Origin: https://evil.example`, `content-type: text/plain` and `Sec-Fetch-Site: cross-site`
    // reached `/approve`'s approval logic and was refused only because the plan hash did not exist. A
    // real hash would have been approved.
    //
    // ## Why the check is "not same-origin" rather than an allowlist
    //
    // There is no legitimate cross-origin caller. The CLI sends no `Origin` at all (it is not a
    // browser), the console is same-origin by construction, and anything else asking to change a
    // firewall from another site is the attack. So a present-and-different `Origin` is refused, and an
    // absent one is allowed — which is exactly the CLI's shape.
    //
    // `Sec-Fetch-Site` is checked too, because it is set by the browser and cannot be spoofed by page
    // script, while `Origin` can be absent on some navigations. Either one saying "cross-site" is
    // enough to refuse; neither being present means no browser is involved.
    //
    // Read routes are deliberately not covered. A cross-site `GET` cannot read the response without
    // CORS headers this server never sends, and refusing them would break nothing an attacker needs
    // while adding a way for the console to fail confusingly.
    if (req.method === "POST" || req.method === "PUT") {
      const origin = req.headers["origin"];
      const site = req.headers["sec-fetch-site"];
      if (crossSiteRequest(req)) {
        log(`refused ${url.pathname} for ${who}: cross-site request (origin=${origin ?? "-"}, sec-fetch-site=${site ?? "-"})`, `${who}의 ${url.pathname} 거부: 교차 사이트 요청 (origin=${origin ?? "-"}, sec-fetch-site=${site ?? "-"})`);
        return send(res, 403, {
          error:
            "cross-site requests cannot change the fleet — your certificate is valid, but this " +
            "request was caused by another site",
        });
      }
    }

    const lifecycleBind = /^\/enrollment\/host-lifecycle-bindings\/([^/]+)\/([^/]+)$/.exec(url.pathname);
    if (opts.enrollment && req.method === "PUT" && lifecycleBind) {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      try {
        const rawBody: unknown = JSON.parse(await readBody(req));
        if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) throw new EnrollmentError("request body must be an object");
        const body = rawBody as Record<string, unknown>;
        if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
        if (Object.keys(body).some((key) => !["inventoryEvidence", "otp"].includes(key))) {
          throw new EnrollmentError("request contains unsupported fields");
        }
        const rawEvidence = body.inventoryEvidence;
        if (!rawEvidence || typeof rawEvidence !== "object" || Array.isArray(rawEvidence)) {
          throw new EnrollmentError("inventoryEvidence must be an object");
        }
        const evidence = rawEvidence as Record<string, unknown>;
        const evidenceFields = ["stardustCreateOperationId", "provider", "providerInstanceId", "nodeTokenIds", "csrRequestIds", "certificateFingerprints"];
        if (Object.keys(evidence).some((key) => !evidenceFields.includes(key))
          || typeof evidence.stardustCreateOperationId !== "string" || evidence.provider !== "vultr"
          || typeof evidence.providerInstanceId !== "string" || !Array.isArray(evidence.nodeTokenIds)
          || !Array.isArray(evidence.csrRequestIds) || !Array.isArray(evidence.certificateFingerprints)
          || [...evidence.nodeTokenIds, ...evidence.csrRequestIds, ...evidence.certificateFingerprints]
            .some((value) => typeof value !== "string")) {
          throw new EnrollmentError("inventoryEvidence is malformed");
        }
        const result = enrollmentWrite(opts.enrollment.storeFile, (document) => bindLegacyHostLifecycle(document, {
          hostname: decodeURIComponent(lifecycleBind[1]!), hostLifecycleId: decodeURIComponent(lifecycleBind[2]!),
          evidence: {
            stardustCreateOperationId: evidence.stardustCreateOperationId as string,
            provider: "vultr", providerInstanceId: evidence.providerInstanceId as string,
            nodeTokenIds: evidence.nodeTokenIds as string[], csrRequestIds: evidence.csrRequestIds as string[],
            certificateFingerprints: evidence.certificateFingerprints as string[],
          }, actor: who,
        }));
        return send(res, 200, { binding: result });
      } catch (e) { return sendEnrollmentError(res, e); }
    }

    const deregistrationRepair = /^\/enrollment\/host-deregistrations\/([^/]+)\/([^/]+)\/repairs\/(certificate-inventory|revocation-capacity)$/.exec(url.pathname);
    if (opts.enrollment && req.method === "PUT" && deregistrationRepair) {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      try {
        const rawBody: unknown = JSON.parse(await readBody(req, 128 * 1024));
        if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) throw new EnrollmentError("request body must be an object");
        const body = rawBody as Record<string, unknown>;
        if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
        const hostname = decodeURIComponent(deregistrationRepair[1]!);
        const externalOperationId = decodeURIComponent(deregistrationRepair[2]!);
        let repaired;
        if (deregistrationRepair[3] === "certificate-inventory") {
          if (Object.keys(body).some((key) => !["hostLifecycleId", "certificates", "otp"].includes(key))
            || typeof body.hostLifecycleId !== "string" || !Array.isArray(body.certificates)) {
            throw new EnrollmentError("certificate inventory repair body is malformed");
          }
          const certificates = body.certificates.map((entry) => {
            if (!entry || typeof entry !== "object" || Array.isArray(entry)
              || Object.keys(entry).some((key) => !["requestId", "certificatePem"].includes(key))) {
              throw new EnrollmentError("certificates entries must contain only requestId and certificatePem");
            }
            const candidate = entry as Record<string, unknown>;
            if (typeof candidate.requestId !== "string" || typeof candidate.certificatePem !== "string") {
              throw new EnrollmentError("certificates entries require string requestId and certificatePem");
            }
            return { requestId: candidate.requestId, certificatePem: candidate.certificatePem };
          });
          repaired = enrollmentWrite(opts.enrollment.storeFile, (document) =>
            repairHostDeregistrationCertificateInventory(document, {
              hostname, externalOperationId, hostLifecycleId: body.hostLifecycleId as string,
              certificates, actor: who,
            }));
        } else {
          if (Object.keys(body).some((key) => !["hostLifecycleId", "relayConfirmations", "otp"].includes(key))
            || typeof body.hostLifecycleId !== "string" || !Array.isArray(body.relayConfirmations)) {
            throw new EnrollmentError("revocation capacity repair body is malformed");
          }
          const relayConfirmations = body.relayConfirmations.map((entry) => {
            if (!entry || typeof entry !== "object" || Array.isArray(entry)
              || Object.keys(entry).some((key) => !["name", "compactedAt", "retainedFingerprintSha256"].includes(key))) {
              throw new EnrollmentError("relayConfirmations entries contain unsupported fields");
            }
            const candidate = entry as Record<string, unknown>;
            if (typeof candidate.name !== "string" || typeof candidate.compactedAt !== "string"
              || typeof candidate.retainedFingerprintSha256 !== "string") {
              throw new EnrollmentError("relayConfirmations entries require string name, compactedAt, and retainedFingerprintSha256");
            }
            return { name: candidate.name, compactedAt: candidate.compactedAt,
              retainedFingerprintSha256: candidate.retainedFingerprintSha256 };
          });
          repaired = enrollmentWrite(opts.enrollment.storeFile, (document) =>
            repairHostDeregistrationRevocationCapacity(document, {
              hostname, externalOperationId, hostLifecycleId: body.hostLifecycleId as string,
              relayConfirmations, relayNames: opts.relays.map((relay) => relay.name), actor: who,
            }));
        }
        const replication = repaired.credentials.state === "replicating" ? await replicateRevocations() : [];
        const operation = requireEnrollmentDocument(opts.enrollment.storeFile).hostDeregistrations.find((candidate) =>
          candidate.hostname === repaired.hostname && candidate.externalOperationId === repaired.externalOperationId)!;
        return send(res, 200, { operation, replication });
      } catch (e) { return sendEnrollmentError(res, e); }
    }

    const policyComplete = /^\/enrollment\/host-deregistrations\/([^/]+)\/([^/]+)\/policy-completed$/.exec(url.pathname);
    if (opts.enrollment && req.method === "PUT" && policyComplete) {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      try {
        const rawBody: unknown = JSON.parse(await readBody(req));
        if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
          throw new EnrollmentError("request body must be an object");
        }
        const body = rawBody as Record<string, unknown>;
        if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
        const allowed = ["hostLifecycleId", "pullRequestUrl", "commitSha", "publishedGeneration", "relayConfirmations", "otp"];
        if (Object.keys(body).some((key) => !allowed.includes(key))) throw new EnrollmentError("request contains unsupported fields");
        if (typeof body.hostLifecycleId !== "string" || typeof body.pullRequestUrl !== "string"
          || typeof body.commitSha !== "string" || typeof body.publishedGeneration !== "string"
          || !Array.isArray(body.relayConfirmations)) {
          throw new EnrollmentError("policy completion evidence is malformed");
        }
        const relayConfirmations = body.relayConfirmations.map((entry) => {
          if (!entry || typeof entry !== "object" || Array.isArray(entry)
            || Object.keys(entry).some((key) => !["name", "absentAt"].includes(key))) {
            throw new EnrollmentError("relayConfirmations entries must contain only name and absentAt");
          }
          const candidate = entry as Record<string, unknown>;
          if (typeof candidate.name !== "string" || typeof candidate.absentAt !== "string") {
            throw new EnrollmentError("relayConfirmations entries require string name and absentAt");
          }
          return { name: candidate.name, absentAt: candidate.absentAt };
        });
        const row = enrollmentWrite(opts.enrollment.storeFile, (document) => completeHostDeregistrationPolicy(document, {
          hostname: decodeURIComponent(policyComplete[1]!), externalOperationId: decodeURIComponent(policyComplete[2]!),
          hostLifecycleId: body.hostLifecycleId as string, pullRequestUrl: body.pullRequestUrl as string,
          commitSha: body.commitSha as string, publishedGeneration: body.publishedGeneration as string,
          relayConfirmations, relayNames: opts.relays.map((relay) => relay.name), actor: who,
        }));
        return send(res, 200, { operation: row });
      } catch (e) { return sendEnrollmentError(res, e); }
    }

    if (opts.enrollment && req.method === "POST" && url.pathname === "/enrollment/tokens") {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      try {
        const body = JSON.parse(await readBody(req)) as {
          hostname?: unknown; hostLifecycleId?: unknown; label?: unknown; revokeExisting?: unknown; ttlSec?: unknown; otp?: unknown;
        };
        if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
        if (typeof body.hostLifecycleId !== "string") throw new EnrollmentError("hostLifecycleId must be a string");
        const hostLifecycleId = body.hostLifecycleId;
        const result = enrollmentWrite(opts.enrollment.storeFile, (document) => createNodeToken(document, {
          hostname: String(body.hostname ?? ""),
          hostLifecycleId,
          label: typeof body.label === "string" ? body.label : undefined,
          createdBy: who,
          ...(body.revokeExisting === undefined
            ? {}
            : typeof body.revokeExisting === "boolean"
              ? { revokeExisting: body.revokeExisting }
              : (() => { throw new EnrollmentError("revokeExisting must be a boolean"); })()),
          ...(body.ttlSec === undefined
            ? {}
            : { ttlSec: typeof body.ttlSec === "number" ? body.ttlSec : Number.NaN }),
        }));
        const { tokenHash: _secret, ...row } = result.row;
        return send(res, 201, { ok: true, id: row.id, token: result.token, row });
      } catch (e) { return sendEnrollmentError(res, e); }
    }
    // ## Issuing the credential a program will hold, with a person and a one-time code in front of it
    //
    // The route an app token *uses* has no second factor — that is the point of it. The route that
    // creates one keeps every check the operator path has, because this is where the grant is
    // decided: which scopes, and which hostnames. `createAppToken` is the only place that validates
    // either, so nothing here interprets a scope string or a pattern on its own.
    if (opts.enrollment && req.method === "POST" && url.pathname === "/enrollment/app-tokens") {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      try {
        const body = JSON.parse(await readBody(req)) as {
          label?: unknown; scopes?: unknown; hostnamePattern?: unknown; ttlSec?: unknown; otp?: unknown;
        };
        if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
        // Checked, not coerced — A1 again. `scopes` is the field where that matters most: a single
        // string would coerce into an array of characters, and every one of them is an unknown scope.
        if (typeof body.label !== "string") throw new EnrollmentError("label must be a string");
        if (typeof body.hostnamePattern !== "string") throw new EnrollmentError("hostnamePattern must be a string");
        if (!Array.isArray(body.scopes) || !body.scopes.every((s: unknown) => typeof s === "string")) {
          throw new EnrollmentError(`scopes must be an array of strings from: ${APP_TOKEN_SCOPES.join(", ")}`);
        }
        const scopes: string[] = body.scopes;
        const ttlSec = typeof body.ttlSec === "number" ? body.ttlSec : undefined;
        if (body.ttlSec !== undefined && ttlSec === undefined) throw new EnrollmentError("ttlSec must be a number");
        const label = body.label;
        const hostnamePattern = body.hostnamePattern;
        const result = enrollmentWrite(opts.enrollment.storeFile, (document) => createAppToken(document, {
          label, scopes, hostnamePattern, createdBy: who, ...(ttlSec === undefined ? {} : { ttlSec }),
        }));
        const { tokenHash: _secret, ...row } = result.row;
        log(
          `created app token ${row.id} (${row.label}) for ${row.hostnamePattern}: ${row.scopes.join(",")}`,
          `앱 토큰 ${row.id} (${row.label}) 생성 — 대상 ${row.hostnamePattern}, 스코프 ${row.scopes.join(",")}`,
        );
        return send(res, 201, { ok: true, id: row.id, token: result.token, row });
      } catch (e) { return sendEnrollmentError(res, e); }
    }
    const appTokenRevoke = /^\/enrollment\/app-tokens\/([^/]+)\/revoke$/.exec(url.pathname);
    if (opts.enrollment && req.method === "POST" && appTokenRevoke) {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      try {
        const body = JSON.parse(await readBody(req)) as { otp?: unknown };
        if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
        const revoked = enrollmentWrite(opts.enrollment.storeFile, (document) =>
          revokeAppToken(document, decodeURIComponent(appTokenRevoke[1]!), who));
        const { tokenHash: _secret, ...row } = revoked;
        log(`revoked app token ${row.id} (${row.label})`, `앱 토큰 ${row.id} (${row.label}) 폐기`);
        return send(res, 200, { ok: true, row });
      } catch (e) { return sendEnrollmentError(res, e); }
    }
    const tokenRevoke = /^\/enrollment\/tokens\/([^/]+)\/revoke$/.exec(url.pathname);
    if (opts.enrollment && req.method === "POST" && tokenRevoke) {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      try { const body = JSON.parse(await readBody(req)) as { otp?: unknown }; if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
        const row = enrollmentWrite(opts.enrollment.storeFile, (document) =>
          revokeNodeToken(document, decodeURIComponent(tokenRevoke[1]!), who));
        return send(res, 200, { ok: true, id: row.id }); }
      catch (e) { return sendEnrollmentError(res, e); }
    }
    const csrReject = /^\/enrollment\/requests\/([^/]+)\/reject$/.exec(url.pathname);
    if (opts.enrollment && req.method === "POST" && csrReject) {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      try { const body = JSON.parse(await readBody(req)) as { reason?: unknown; otp?: unknown }; if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
        const row = enrollmentWrite(opts.enrollment.storeFile, (document) =>
          rejectNodeCsr(document, decodeURIComponent(csrReject[1]!), who, String(body.reason ?? "")));
        return send(res, 200, { ok: true, request: row }); }
      catch (e) { return sendEnrollmentError(res, e); }
    }
    const certUpload = /^\/enrollment\/requests\/([^/]+)\/certificate$/.exec(url.pathname);
    if (opts.enrollment && req.method === "POST" && certUpload) {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      try {
        const body = JSON.parse(await readBody(req, 24 * 1024)) as { certificatePem?: unknown; caName?: unknown; otp?: unknown };
        if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
        if (typeof body.certificatePem !== "string" || typeof body.caName !== "string") throw new EnrollmentError("certificatePem and caName required");
        const certificatePem = body.certificatePem;
        const caName = body.caName;
        const caPath = opts.enrollment.trustedCaFiles?.get(caName);
        if (!caPath) throw new EnrollmentError(`CA ${JSON.stringify(caName)} is not configured as trusted`, 503);
        // File I/O is outside the enrollment lock. The transaction itself remains synchronous and
        // covers only load → validate/mutate → save, so a slow mount cannot block unrelated writes.
        const caPem = await readFile(caPath, "utf8");
        const row = enrollmentWrite(opts.enrollment.storeFile, (document) =>
          storeNodeCertificate(document, {
            requestId: decodeURIComponent(certUpload[1]!), certificatePem,
            caPem, caName, actor: who,
          }));
        return send(res, 200, { ok: true, request: row });
      } catch (e) { return sendEnrollmentError(res, e); }
    }
    if (opts.enrollment && req.method === "POST" && url.pathname === "/enrollment/revocations") {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      try { const body = JSON.parse(await readBody(req, 24 * 1024)) as { certificatePem?: unknown; reason?: unknown; otp?: unknown };
        if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
        if (typeof body.certificatePem !== "string") throw new EnrollmentError("certificatePem required");
        const certificatePem = body.certificatePem;
        const row = enrollmentWrite(opts.enrollment.storeFile, (document) =>
          revokeCertificate(document, { certificatePem, reason: String(body.reason ?? ""), actor: who }));
        const replication = await replicateRevocations();
        return send(res, 201, { ok: true, revocation: row, replication }); }
      catch (e) { return sendEnrollmentError(res, e); }
    }

    // `/ui` was an alias for `/` from the first read-only console and nothing in this repository ever
    // linked to it — no page, no document, no script, no redirect, and no comment saying why it
    // existed. It is gone now that the console has real routes, because an address that renders a
    // screen without naming it is the thing this menu is meant to end.
    //
    // A redirect rather than a 404: it costs the same and a bookmark somebody made a month ago still
    // lands somewhere useful. `301` because this is permanent — the alias is not coming back.
    if (req.method === "GET" && url.pathname === "/ui") {
      res.writeHead(301, { location: CONSOLE_ENTRY, "cache-control": "no-store" });
      return void res.end();
    }

    // `/` names the screen it shows instead of being a second address for it. Adding an overview
    // later then moves no URL: it becomes what `/` redirects to, and `/fleet` is the fleet under
    // `/app`. Serving the fleet at both would recreate `/ui`.
    if (req.method === "GET" && url.pathname === "/") {
      res.writeHead(302, { location: CONSOLE_ENTRY, "cache-control": "no-store" });
      return void res.end();
    }

    // Classic HTML screens. `/app` is the console; these paths keep bookmarks. Exact match only —
    // `/enrollment/tokens` is data, not this screen.
    if (req.method === "GET") {
      const to = consoleAppPath(url.pathname);
      if (to) {
        res.writeHead(302, { location: to, "cache-control": "no-store" });
        return void res.end();
      }
    }

    // ── Routing: declared against observed ─────────────────────────────────────
    //
    // A packet reaches a filter only if routing sent it there, and until 2026-08-16 this console saw
    // only the filter. The observation that arrived then reported two `proto static` routes on
    // gw-01.dev carrying every packet bound for the cluster — written down nowhere but that kernel.
    //
    // Observation alone could not close it: `proto static` names who probably knows, not whether
    // anyone intended it. This joins the two, and it is a **separate route from `/site` on purpose**.
    // The fleet view polls every few seconds; reading the policy repository on that path would put a
    // second network call in front of the one screen that has to stay responsive when things break.
    //
    // Nothing here writes a route. See `PublishHost.routes` for why that half is not a side effect of
    // this one.
    if (req.method === "GET" && url.pathname === "/routes") {
      if (!opts.policySource) {
        return send(res, 404, { error: "this deployment does not carry a policy repository" });
      }
      let source: PolicySource;
      try {
        source = await fetchPolicySource(opts.policySource, timeoutMs);
      } catch (e) {
        return send(res, 503, { error: `the policy could not be read: ${(e as Error).message}` });
      }
      const declaredBy = new Map<string, readonly RouteDecl[] | undefined>();
      for (const h of (screenSiteOf(source) as unknown as { hosts?: readonly { id: string; routes?: readonly RouteDecl[] }[] }).hosts ?? []) {
        declaredBy.set(h.id, h.routes);
      }
      const results = await pollRelays(opts.relays, timeoutMs);
      const view: SiteView = siteView(results);
      return send(res, 200, {
        generation: source.head.sha,
        dirty: source.head.dirty,
        hosts: view.hosts.map((h) => ({
          vpc: h.vpc,
          host: h.host,
          // **Passed straight through, and the first version did not.** It turned "in the model with
          // no routes key" into "declared, and the declaration is empty", so k3s-01 and the three
          // mailers came back `missing 0 · undeclared 0 · unstated 0` — the best-looking result this
          // screen can print — over four hosts nobody had described. Measured against the live fleet
          // twenty minutes after shipping it, and it also put this route in disagreement with
          // `policy/dev-routes.test.ts`, which asserts `rows === null` for exactly those hosts.
          //
          // Green because nothing was checked is the failure this project has a name for. A host whose
          // routing has not been written down must say so, and `routes: []` remains available and means
          // something different: somebody looked and there was nothing to declare.
          ...compareRoutes(declaredBy.get(h.host), h.routes),
          appliable: readyToApply(declaredBy.get(h.host)),
        })),
      });
    }

    // ── Policy lookup ──────────────────────────────────────────────────────────
    //
    // "Which rule decides this flow?" — the question a firewall console is expected to answer and
    // this one could not. It reads the same declarations the policy screen draws, so the two cannot
    // disagree about which rules exist, and it returns the undecidable set separately rather than
    // folding it into "no match": an address cannot rule a workload rule in or out, and pretending
    // otherwise hides exactly the rule the reader came for.
    if (req.method === "GET" && url.pathname === "/policy/lookup") {
      if (!opts.policySource) {
        return send(res, 404, { error: "this deployment does not carry a policy repository" });
      }
      const portRaw = url.searchParams.get("port");
      const port = portRaw === null || portRaw === "" ? null : Number(portRaw);
      if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) {
        return send(res, 400, { error: "port must be an integer between 1 and 65535" });
      }
      const protoRaw = url.searchParams.get("proto") ?? "any";
      if (!["tcp", "udp", "icmp", "any"].includes(protoRaw)) {
        return send(res, 400, { error: "proto must be tcp, udp, icmp or any" });
      }
      let source: PolicySource;
      try {
        source = await fetchPolicySource(opts.policySource, timeoutMs);
      } catch (e) {
        return send(res, 503, { error: `the policy could not be read: ${(e as Error).message}` });
      }
      const site = screenSiteOf(source);
      const cfg = (site as { cfg?: { internalSupernet?: string } }).cfg ?? {};
      // Only the CIDR members. An address object may also name a host or another object, and those
      // resolve through machinery this process does not have — the lookup reports them as undecided
      // rather than silently treating a partly-resolved object as fully resolved.
      const objects = new Map<string, readonly string[]>();
      for (const o of site.objects ?? []) {
        if (o.kind !== "address") continue;
        objects.set(o.name, o.members.filter((m) => m.kind === "cidr").map((m) => m.value));
      }
      const accept = req.headers["accept-language"];
      const lang = pickLang({
        override: url.searchParams.get("lang"),
        acceptLanguage: Array.isArray(accept) ? accept.join(",") : accept ?? null,
      });
      const result = lookupPolicies(
        allSitePolicies(site as Parameters<typeof allSitePolicies>[0]) as Parameters<typeof lookupPolicies>[0],
        {
          src: (url.searchParams.get("src") ?? "").trim(),
          dst: (url.searchParams.get("dst") ?? "").trim(),
          srcWorkload: (url.searchParams.get("srcWorkload") ?? "").trim(),
          dstWorkload: (url.searchParams.get("dstWorkload") ?? "").trim(),
          port,
          proto: protoRaw as Parameters<typeof lookupPolicies>[1]["proto"],
        },
        { internalSupernet: cfg.internalSupernet ?? "10.0.0.0/8", objects },
        lang,
      );
      // The generation travels with the answer. A lookup result read an hour later, against a policy
      // that has since moved, is the same failure as a screen that does not say how old it is.
      return send(res, 200, { ...result, generation: source.head.sha, dirty: source.head.dirty });
    }

    // ── What has passed the workload allows ────────────────────────────────────
    //
    // `/workload-traffic` and not `/traffic`, because `/traffic` is the *screen*. Naming both the
    // same served the console shell with a 200 and the API never ran — the identical collision this
    // file already avoided once by calling the plans screen `/changes`, walked into from the other
    // direction. Screens are named for what the operator does; APIs for the resource.
    //
    // Fetched from a reader pod rather than read here. The `exec` this needs is `pods/exec` in
    // `kube-system`, which is control of the node's dataplane — and this process holds the signing
    // key. The reader holds that permission and nothing else, exactly as the policy renderer holds
    // the policy checkout and nothing else.
    //
    // The parse happens here rather than there on purpose: a reader with no logic has no logic to get
    // wrong, and `workload-traffic.ts` is tested against a real dump without a cluster.
    if (req.method === "GET" && url.pathname === "/workload-traffic") {
      if (!opts.trafficReader) {
        return send(res, 404, { error: "this deployment has no traffic reader" });
      }
      const call = opts.trafficReader.fetch ?? (fetch as unknown as Fetcher);
      try {
        const answer = await call(`${opts.trafficReader.url.replace(/\/$/, "")}/traffic.txt`, {
          method: "GET",
          headers: { accept: "text/plain" },
        });
        if (!answer.ok) throw new Error(`the reader answered ${answer.status}`);
        const text = await readBoundedText(answer, MAX_TRAFFIC_DUMP_BYTES, "the traffic reader");
        // An empty body is the reader saying it has not managed a dump, and it must not read as a
        // cluster with no policy entries. Zero entries and no reading are opposite findings.
        if (!text.trim()) {
          return send(res, 200, { unavailable: "the reader has not produced a dump yet" });
        }
        return send(res, 200, parseTrafficDump(text));
      } catch (e) {
        // Said, never swallowed. A screen shown nothing concludes there is nothing.
        return send(res, 200, { unavailable: `the traffic reader could not be read: ${(e as Error).message}` });
      }
    }

    // ── Where is this written ──────────────────────────────────────────────────
    //
    // The companion to the lookup and a different question from it. The lookup asks what would decide
    // a flow; this asks where a value appears in the text, which is what somebody about to change an
    // address needs. Seventy-two policies here write twenty-four literal CIDRs and name one address
    // object, so today that question is a grep a person has to know to run.
    //
    // `repeated` comes back with it: the literals written in more than one rule, which is the case
    // for naming them, made from the policy rather than from taste.
    if (req.method === "GET" && url.pathname === "/policy/where-used") {
      if (!opts.policySource) {
        return send(res, 404, { error: "this deployment does not carry a policy repository" });
      }
      let source: PolicySource;
      try {
        source = await fetchPolicySource(opts.policySource, timeoutMs);
      } catch (e) {
        return send(res, 503, { error: `the policy could not be read: ${(e as Error).message}` });
      }
      const site = screenSiteOf(source);
      const policies = allSitePolicies(site as Parameters<typeof allSitePolicies>[0]) as Parameters<typeof whereUsed>[0];
      const q = (url.searchParams.get("q") ?? "").trim();
      return send(res, 200, {
        query: q,
        usages: whereUsed(policies, q),
        repeated: repeatedLiterals(policies),
        considered: policies.length,
        generation: source.head.sha,
      });
    }

    // ── The policy screen, as JSON ─────────────────────────────────────────────
    //
    // `/app/policy` reads this instead of scraping markup. Named `/policy/screen` rather than
    // `/policy` because `/policy` is the bookmark that now redirects, and `/api/policy` must
    // not become a second address for the screen.
    if (req.method === "GET" && url.pathname === "/policy/screen") {
      if (!opts.policySource) {
        return send(res, 404, { error: "this deployment does not carry a policy repository" });
      }
      let screen: Screen;
      let source: PolicySource;
      try {
        ({ screen, source } = await renderPolicyScreen(opts.policySource, opts.relays, timeoutMs));
      } catch (e) {
        log(`policy screen failed: ${(e as Error).message}`, `정책 화면 실패: ${(e as Error).message}`);
        return send(res, 503, { error: `the policy could not be read: ${(e as Error).message}` });
      }
      let edit: { path: string; content: string; more: { path: string; content: string }[] } | undefined;
      if (opts.policyWrite && mayWrite) {
        const { primary, more } = editableFiles(opts.policyWrite.allowPaths, source.files);
        if (primary) edit = { path: primary.path, content: primary.content, more };
      }
      return send(res, 200, {
        rows: screen.rows,
        extra: screen.extra,
        site: screen.meta.site,
        generation: screen.meta.generation ?? source.head.sha,
        hosts: screen.meta.hosts,
        freshness: await freshnessOf(source.head.sha),
        renderer: { build: source.build ?? null, mine: buildId() },
        canWrite: Boolean(edit),
        ...(edit ? { edit } : {}),
      });
    }

    // ── The policy console ─────────────────────────────────────────────────────
    //
    // The HTML page used to live here. `/app/policy` is now the console; this path keeps the
    // bookmarks (`?s=files`) and the classic sidenav link. The data routes under `/policy/…`
    // are not this path — `/policy/edit` and `/policy/screen` stay where they are.
    if (req.method === "GET" && url.pathname === "/policy") {
      if (!opts.policySource) {
        return send(res, 404, { error: "this deployment does not carry a policy repository" });
      }
      res.writeHead(302, {
        location: policyAppPath(url.searchParams.get("s")),
        "cache-control": "no-store",
      });
      return void res.end();
    }

    if (req.method === "POST" && (url.pathname === "/policy/edit" || url.pathname === "/policy/propose")) {
      if (!opts.policyWrite) return send(res, 404, { error: "this console has no write credential" });
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      const { creds, target, allowPaths } = opts.policyWrite;
      const call = opts.policyWrite.fetch ?? (fetch as unknown as Fetcher);
      const nowSec = Math.floor(now().getTime() / 1000);
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(await readBody(req)) as Record<string, unknown>;
      } catch {
        return send(res, 400, { error: "expected a JSON body" });
      }

      try {
        if (url.pathname === "/policy/edit") {
          const path = String(body.path ?? "");
          if (!allowPaths.includes(path)) {
            return send(res, 400, { error: `this console may only edit: ${allowPaths.join(", ")}` });
          }
          const content = String(body.content ?? "");
          if (!content) return send(res, 400, { error: "refusing to commit an empty file" });
          // Checked, not just defaulted. `branchName` slugs the operator's name and explains why a
          // `/` in it would be a problem — and a caller who supplies `branch` skipped that argument
          // entirely. See `isUsableBranchName`.
          const branch = String(body.branch ?? "") || branchName(who, now().toISOString());
          if (!isUsableBranchName(branch)) {
            return send(res, 400, {
              error: "branch must be slash-separated segments of letters, digits, dot, dash or underscore",
            });
          }
          const out = await commitToBranch(creds, call, nowSec, {
            target,
            path,
            content,
            branch,
            message: String(body.message ?? `policy: edit ${path} from the console`),
          });
          log(`policy edit by ${who}: ${path} → ${out.branch} ${out.commit.slice(0, 8)}`, `${who}의 정책 편집: ${path} → ${out.branch} ${out.commit.slice(0, 8)}`);
          return send(res, 200, { ok: true, ...out });
        }

        const branch = String(body.branch ?? "");
        if (!branch) return send(res, 400, { error: "propose needs the branch to open a pull request from" });
        if (!isUsableBranchName(branch)) {
          return send(res, 400, {
            error: "branch must be slash-separated segments of letters, digits, dot, dash or underscore",
          });
        }
        // The body names the rendered plan rather than describing the diff. GitHub shows the diff;
        // what a reviewer cannot see there is whether the change renders into anything.
        //
        // Best effort, and deliberately so — the renderer is still holding the *merged* policy at
        // this moment, not the branch, so these counts describe what is deployed rather than what is
        // proposed. Losing them costs two numbers in a pull request body; refusing the proposal
        // because a viewer is down would make the console unable to open a review at the moment
        // somebody is trying to fix the thing that broke it.
        let screen: Screen | null = null;
        if (opts.policySource) {
          try {
            ({ screen } = await renderPolicyScreen(opts.policySource, opts.relays, timeoutMs));
          } catch (e) {
            log(`proposal body has no render counts: ${(e as Error).message}`, `제안 본문에 렌더 수가 없음: ${(e as Error).message}`);
          }
        }
        const pr = await openPullRequest(creds, call, nowSec, {
          target,
          branch,
          title: String(body.title ?? `policy: ${branch}`),
          body: proposalBody({
            who,
            site: opts.policySource?.url ?? "unknown",
            ...(typeof body.planHash === "string" ? { planHash: body.planHash } : {}),
            policies: screen?.rows.length ?? 0,
            rendersNowhere: screen?.rows.filter((r) => r.risks.includes("renders-nowhere")).length ?? 0,
          }),
        });
        log(`policy proposal by ${who}: ${branch} → PR #${pr.number}`, `${who}의 정책 제안: ${branch} → PR #${pr.number}`);
        return send(res, 200, { ok: true, ...pr });
      } catch (e) {
        // GitHub's sentence, not just a status. "Reference already exists" and "No commits between"
        // send an operator to completely different places, and a bare 502 sends them to neither.
        const msg = e instanceof ProposalError ? e.message : (e as Error).message;
        log(`policy write failed for ${who}: ${msg}`, `${who}의 정책 쓰기 실패: ${msg}`);
        return send(res, 502, { error: msg });
      }
    }

    if (req.method === "GET" && url.pathname === "/site") {
      const results = await pollRelays(opts.relays, timeoutMs);
      const view: SiteView = siteView(results);
      // Logged only when something is wrong. A line per poll would bury the one that matters under a
      // repeating message that says nothing happened.
      for (const r of results) if (!r.ok) log(`${r.name} unreachable: ${r.error}`, `${r.name}에 연결할 수 없음: ${r.error}`);
      return send(res, 200, view);
    }

    // Who may change the fleet, and by which door.
    //
    // Behind the same certificate as `/site`: a caller who can already enumerate every host and open
    // port on the fleet learns nothing dangerous from the list of names allowed to publish.
    //
    // ## Why this exists
    //
    // Every value here has silently changed somebody's authority at least once. The two-person rule
    // compares `plan.proposedBy` with the approver as **strings**, so an OIDC identity with no alias
    // to a certificate name is refused a write and told only that it "may read the site". A
    // certificate CN missing from the OTP map cannot approve anything — one omission made approval
    // impossible on 2026-08-06, and nothing on any screen said so.
    //
    // **Names, roles and mappings, and the caller's own CSRF token.** No credential belonging to this
    // deployment — no service token, no signing key, no client secret — is reachable from here, and
    // `manager-server.test.ts` asserts it on the raw body.
    //
    // ## Why the CSRF token is not an exception to that
    //
    // It is not a secret this process holds; it is a value minted for one session and useful only to
    // a caller that already presents that session's cookie. `/plans` has returned it on exactly this
    // reasoning since sessions were added. It is absent for a certificate caller, who has no session
    // and needs no token.
    //
    // It is here because the policy screen's editor asked for it here and got `undefined`. That page
    // reads `(await r.json()).csrf` off this route, and with nothing to read it sent every write with
    // no header at all, which `checkCsrf` refuses. **Every write on `/policy` was dead for a cookie
    // session from the day the editor shipped**: the rule table's save, each additional file's save,
    // and the proposal. Nothing failed loudly, because a certificate caller skips the CSRF check
    // entirely and that is the path the tests took.
    //
    // The page's own half of it is fixed alongside — it used to cache the miss as `''` and never ask
    // again, which is what kept a missing field looking like a normal one. See `token()`.
    //
    // Adding the field here rather than repointing the page at `/plans` keeps the policy screen off
    // the approval route: an editor that breaks when a plan listing grows a gate is a coupling nobody
    // reading either file would predict.
    if (req.method === "GET" && url.pathname === "/authz") {
      return send(res, 200, {
        // Who is asking. `/plans` already sent these so the changes screen could offer the
        // right buttons; the Svelte chrome reads them here so identity does not depend on
        // there being a plan listing.
        you: who,
        canWrite: mayWrite,
        // A count, not the plans. The sidenav badge has to exist on every screen, and
        // hanging the chrome on `/plans` is the coupling `/authz` was added to avoid.
        pendingPlans: listPlans(approvals, now(), limits).filter((p) => !p.publishedAt).length,
        // A count, or nothing. 0 is "read the store, none waiting". Omitting on
        // a broken store is what stops the sidenav claiming there are no CSRs.
        pendingCsrs: pendingCsrCount(opts.enrollment?.storeFile),
        // Same rule as `/plans`: only for a session, and only ever to the caller holding it.
        ...(session && principal.via === "oidc" ? { csrf: session.csrf } : {}),
        certificate: {
          operators: [...operators],
          writers: [...writers],
          // The same person under two names is what makes the two-person rule usable on a site with
          // one operator, and it is exactly what would defeat it if the second name were a stranger.
          note: "approval compares proposer and approver as strings — one human under two names satisfies it",
        },
        oidc: opts.oidc
          ? {
              issuer: opts.oidc.issuer,
              operatorRoles: [...opts.oidc.operatorGroups],
              writerRoles: [...opts.oidc.writerGroups],
              soloApprovalRoles: [...(opts.oidc.soloApprovalRoles ?? [])],
              // Keys are identities at the identity provider; values are certificate names. Without
              // an entry, a writer role reads the fleet and cannot change it.
              aliases: Object.fromEntries(opts.oidc.aliases),
              roleChangeEvent: opts.oidc.roleChangeEvent,
            }
          : null,
        otp: opts.otp
          ? { issuer: opts.otp.issuerUrl, mappedCertificates: [...opts.otp.users.keys()] }
          : null,
      });
    }

    /**
     * The rules a pending plan would install on one host, as bytes.
     *
     * ## Why this route exists
     *
     * The approver saw a host name, a stage, a rule *count* and a digest. Nothing else. So approval
     * was a comparison of hashes — which is a real check against tampering in transit and no check at
     * all on what the rules say. `nft.ts` documents its text renderer as "the human-facing form —
     * what the GUI shows and what an operator reads in review"; no screen called it, and the
     * two-person rule rests on the second person reading something the first could not choose.
     *
     * ## Why the stored bytes rather than a fresh render
     *
     * These are the exact bytes `rulesetHash` covers and the agent applies. Re-rendering for display
     * would show a second artifact of the same policy, and the one property worth having here is that
     * **what is read is what lands**. The digest is recomputed from what is about to be served and
     * checked against the manifest, so a bundle that disagreed with its own manifest is refused
     * rather than displayed.
     *
     * Read tier, deliberately: anyone who may read `/site` already learns every host and open port,
     * and refusing them the rules they can already see the effects of would be theatre.
     */
    // The segment is decoded before it is matched: a plan hash contains `:`, which a browser's
    // `encodeURIComponent` sends as `%3A`. Matching the raw pathname worked from curl and 404'd from
    // the console, which is the kind of difference that gets found in a browser rather than a test.
    // ## What is different about this plan
    //
    // The ruleset route above shows an approver *what* a host will run. It cannot show them what
    // **changed**, and that is the question the second person is there to answer: sixteen rules where
    // fifteen were before, and finding the one that moved by eye is a job for a machine. Without it
    // the approver either takes the proposer's word or re-derives the change by hand, and the
    // two-person rule is worth exactly what the second person can see.
    //
    // Compared at the policy level rather than the ruleset level. A ruleset diff would need the bytes
    // each host is currently running, and the relay serves those only to the host that owns them —
    // `/artifact` is keyed on the client CN. The policy diff is cheaper and closer to the decision:
    // rules are authored as text by a person, and this is that text.
    const changesRoute = /^\/plans\/([^/]+)\/changes$/.exec(url.pathname);
    if (req.method === "GET" && changesRoute) {
      let hash: string;
      try {
        hash = decodeURIComponent(changesRoute[1]!);
      } catch {
        return send(res, 400, { error: "malformed plan hash" });
      }
      if (!/^sha256:[0-9a-f]{64}$/.test(hash)) return send(res, 400, { error: "malformed plan hash" });
      const bundle = bundles.get(hash);
      if (!bundle) return send(res, 404, { error: "no pending plan with that hash" });
      if (!opts.policyWrite) {
        return send(res, 200, { unavailable: "this console has no repository credential to compare with" });
      }
      const targetName = planTargets.get(hash);
      const relayName = opts.relays.find((r) => r.name === targetName)?.name;
      // The generation the fleet is on, read from the same site view the console draws. Taken from
      // the hosts rather than from the issued target: what matters to the approver is what is
      // running, and a rollout in flight is exactly when those two differ.
      let deployed: string | null = null;
      try {
        const view = siteView(await pollRelays(opts.relays.filter((r) => r.name === relayName), timeoutMs));
        const hosts = view.vpcs.flatMap((v) => ("view" in v && v.view ? v.view.hosts : []));
        const gens = [...new Set(hosts.map((h) => h.generation).filter((g): g is string => Boolean(g)))];
        // One generation, or none. A fleet mid-rollout carries two, and picking either would name a
        // base the approver is not comparing against on every host.
        deployed = gens.length === 1 ? gens[0]! : null;
      } catch (e) {
        return send(res, 200, { unavailable: `the fleet could not be read: ${(e as Error).message}` });
      }
      if (!deployed) {
        return send(res, 200, { unavailable: "the hosts are not all on one generation, so there is no single base to compare against" });
      }
      if (sameCommit(deployed, bundle.manifest.generation)) {
        return send(res, 200, { base: deployed, head: bundle.manifest.generation, commits: [], files: [], same: true });
      }
      try {
        const cmp = await compareGenerations(
          opts.policyWrite.creds,
          opts.policyWrite.target,
          deployed,
          bundle.manifest.generation,
          opts.policyWrite.fetch ?? (fetch as unknown as Fetcher),
          Math.floor(now().getTime() / 1000),
        );
        // Split before it reaches the screen. Both halves are reported — hiding the generated files
        // would be its own lie, since the generation being approved does contain them — but they are
        // separated so the authored change is the thing on top.
        const authored = cmp.files.filter((f) => !isGeneratedPolicyFile(f.filename));
        const generated = cmp.files
          .filter((f) => isGeneratedPolicyFile(f.filename))
          .map(({ patch: _patch, ...rest }) => rest);
        return send(res, 200, {
          base: deployed,
          head: bundle.manifest.generation,
          same: false,
          commits: cmp.commits,
          files: authored,
          generated,
        });
      } catch (e) {
        // Reported, never swallowed. An approver who is shown nothing concludes nothing changed.
        return send(res, 200, { unavailable: `the repository could not be compared: ${(e as Error).message}` });
      }
    }

    const rulesetRoute = /^\/plans\/([^/]+)\/ruleset$/.exec(url.pathname);
    if (req.method === "GET" && rulesetRoute) {
      let hash: string;
      try {
        hash = decodeURIComponent(rulesetRoute[1]!);
      } catch {
        return send(res, 400, { error: "malformed plan hash" });
      }
      if (!/^sha256:[0-9a-f]{64}$/.test(hash)) return send(res, 400, { error: "malformed plan hash" });
      const bundle = bundles.get(hash);
      if (!bundle) return send(res, 404, { error: "no pending plan with that hash" });
      const host = url.searchParams.get("host") ?? "";
      const entry = bundle.manifest.hosts[host];
      const ruleset = bundle.rulesets[host];
      if (!entry || ruleset === undefined) {
        return send(res, 404, { error: `this plan carries no ruleset for ${JSON.stringify(host)}` });
      }
      const digest = "sha256:" + createHash("sha256").update(ruleset).digest("hex");
      if (digest !== entry.rulesetHash) {
        // Held bytes that do not match the manifest they were proposed with. **Unreachable through
        // any path a test can drive** — the bytes and the manifest come from the same bundle object,
        // so only memory corruption separates them, and defect injection confirms removing this
        // check breaks nothing. It stays as the same kind of guard as the relay's "artifact
        // unavailable": cheap, and the one thing that must not happen silently is displaying rules
        // under a digest that does not cover them.
        log(`ruleset for ${host} in plan ${hash.slice(0, 20)} does not match its manifest digest`, `계획 ${hash.slice(0, 20)}의 ${host} 규칙셋이 매니페스트 다이제스트와 일치하지 않음`);
        return send(res, 500, { error: "the stored ruleset does not match its manifest digest" });
      }
      return send(res, 200, {
        host,
        generation: bundle.manifest.generation,
        stage: entry.stage,
        rulesetHash: entry.rulesetHash,
        ruleset,
      });
    }

    /**
     * What this plan changes about one host's **rules**, as opposed to its policy source.
     *
     * ## Why the policy diff is not enough
     *
     * `/plans/<hash>/changes` compares the source between the deployed commit and this one, which is
     * the text a person wrote and the right thing to read first. It cannot say what the rules become:
     * one edit to an address object moves every rule that names it, and a rule can move with **no**
     * line of policy changing at all — a resolver returning a different set, a Service selector that
     * widened, a geofeed snapshot that grew. An approver reading only the source is taking the
     * rendering on trust, and the two-person rule is worth what the second person can see.
     *
     * ## Read tier, like `/plans/<hash>/ruleset`
     *
     * Anyone who may read `/site` already learns every host and open port. Refusing them a comparison
     * of rules they can see the effects of would be theatre.
     */
    const diffRoute = /^\/plans\/([^/]+)\/ruleset-diff$/.exec(url.pathname);
    if (req.method === "GET" && diffRoute) {
      let hash: string;
      try {
        hash = decodeURIComponent(diffRoute[1]!);
      } catch {
        return send(res, 400, { error: "malformed plan hash" });
      }
      if (!/^sha256:[0-9a-f]{64}$/.test(hash)) return send(res, 400, { error: "malformed plan hash" });
      const bundle = bundles.get(hash);
      if (!bundle) return send(res, 404, { error: "no pending plan with that hash" });
      const host = url.searchParams.get("host") ?? "";
      const after = bundle.rulesets[host];
      if (after === undefined) {
        return send(res, 404, { error: `this plan carries no ruleset for ${JSON.stringify(host)}` });
      }
      const base = lastPublished.get(planTargets.get(hash) ?? "");
      if (!base) {
        // Said plainly. A restart loses this, and a generation published through the direct path
        // never passed through here — in both cases there is no base, and inventing one would be a
        // comparison against something the fleet is not running.
        return send(res, 200, {
          host,
          unavailable:
            "this manager has not published to that VPC since it started, so it holds no rules to " +
            "compare against. The policy diff at /plans/<hash>/changes does not need one.",
        });
      }
      const before = base.bundle.rulesets[host];
      if (before === undefined) {
        return send(res, 200, { host, base: base.generation, head: bundle.manifest.generation, added: true });
      }
      const diff = diffRulesets(before, after);
      if (!diff) {
        return send(res, 200, { host, unavailable: "one of the two rulesets could not be read as nft JSON" });
      }
      return send(res, 200, { host, base: base.generation, head: bundle.manifest.generation, ...diff });
    }

    // Pending plans. Read-only, and the screen an approver works from.
    if (req.method === "GET" && url.pathname === "/plans") {
      return send(res, 200, {
        plans: listPlans(approvals, now(), limits).map((p) => publicPlan(p, planTargets.get(p.hash) ?? null)),
        limits,
        // Who is asking, and whether they may write at all.
        //
        // The console needs both to decide what to *offer*. Without `you` it cannot tell which plans
        // the viewer proposed, so it would show an approve button that always fails with 403 — and a
        // control that exists to be refused teaches an operator to ignore refusals. Without `canWrite`
        // a reader sees buttons they can never use.
        //
        // Neither is an authorisation decision. The server re-checks both on `POST /approve` against
        // the certificate on that request; this is the UI being honest about what will happen, not the
        // UI being trusted.
        you: who,
        canWrite: mayWrite,
        // The VPCs this manager can propose to, so the console can offer them by name rather than
        // asking an operator to type one. Absent when there is no policy to render: a target picker
        // with nothing to propose is a control that exists to be refused.
        ...(opts.policySource ? { targets: opts.relays.map((r) => r.name) } : {}),
        // Whether this caller may approve a plan they proposed themselves.
        //
        // **Without it the console could not offer solo approval at all**, and solo approval is
        // OIDC-only by design — a certificate carries no role claim — so the console is the only
        // place it can ever be used. The server has passed `mayApproveOwn` into `POST /approve`
        // since the role was added; the screen went on hiding the button whenever `proposedBy ===
        // you`, which made the whole capability unreachable except by hand-crafting a request.
        //
        // The comment above explains sending `you` so the console does not offer a button that will
        // fail. This is the same argument in the other direction: a button that would succeed must
        // not be hidden. Neither is an authorisation decision — `POST /approve` re-derives this from
        // the session on the request.
        maySoloApprove,
        // The CSRF token for this session, and only for a session. A certificate caller has none and
        // needs none: the browser does not attach a client certificate to a cross-origin request the
        // way it attaches a cookie, and the `Origin`/`Sec-Fetch-Site` check above already covers that
        // path.
        //
        // Handed out here rather than embedded in the page because the page is fetched once and this
        // is polled — a token baked into HTML would be the one from whenever the tab was opened, and
        // would stop working the moment the session was replaced.
        //
        // Safe to return: it is readable only by a caller that already holds the session cookie, and
        // its whole purpose is to be echoed back by that caller's own script.
        ...(session && principal.via === "oidc" ? { csrf: session.csrf } : {}),
      });
    }

    // ── The write path ────────────────────────────────────────────────────────
    //
    // Three endpoints, and the ordering between them is the permission model
    // (docs/인터페이스-설계.md 결정 4). Every one of them is refused unless the caller is in
    // `writerCNs`, which is a separate list from the readers: being able to see the fleet and being
    // able to change it are different powers, and the second is strictly larger.

    /**
     * Turn a validated bundle into a pending plan.
     *
     * Shared by the CLI's `POST /plan`, which submits a bundle it rendered, and the console's
     * `POST /policy/plan`, which asks this process to render one. **One copy on purpose** — the
     * hash, the retention sweep and the log line are the parts that decide what an approver later
     * sees, and two of them would drift the way every other pair in this system has.
     */
    const recordProposal = (
      response: ServerResponse,
      targetName: string,
      bundle: PlanBundle,
      by: string,
    ) => {
      // Computed here, from the bytes that arrived. Never taken from the request — a submitted hash
      // would be the proposer's claim about content the approver never sees, and then the approval
      // check is decorative.
      const hash = planHash(targetName, bundle);
      try {
        const plan = propose(
          approvals,
          { hash, generation: bundle.manifest.generation, summary: summarise(bundle), by, now: now() },
          limits,
        );
        // The bundle is held beside the plan rather than inside it: `Plan` is what gets serialised to
        // an operator, and a fleet's worth of rendered rulesets does not belong in a listing.
        bundles.set(hash, bundle);
        planTargets.set(hash, targetName);
        // Both maps are keyed by plan hash and `approvals` is the only thing that expires, so they are
        // trimmed against it. Without this, a manager that has been proposed to for a month is holding
        // every bundle it ever saw — and each one is a fleet's worth of rulesets.
        for (const key of bundles.keys()) {
          if (!approvals.plans.has(key)) {
            bundles.delete(key);
            planTargets.delete(key);
          }
        }
        log(`plan ${hash.slice(0, 20)} proposed by ${by} for ${targetName} (generation ${bundle.manifest.generation})`, `${by}이(가) ${targetName}에 계획 ${hash.slice(0, 20)}을(를) 제안함 (세대 ${bundle.manifest.generation})`);
        return send(response, 200, publicPlan(plan, targetName));
      } catch (e) {
        return sendApprovalError(response, e);
      }
    };

    if (req.method === "POST" && url.pathname === "/plan") {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      let body: { target?: string; bundle?: unknown };
      try {
        body = JSON.parse(await readBody(req, MAX_PLAN_BYTES)) as typeof body;
      } catch (e) {
        return send(res, 400, { error: `bad request body: ${(e as Error).message}` });
      }
      const target = opts.relays.find((r) => r.name === body.target);
      if (!target) {
        return send(res, 400, {
          error: `unknown target ${JSON.stringify(body.target ?? null)} — this manager knows ` +
            `${opts.relays.map((r) => r.name).join(", ")}`,
        });
      }
      let bundle;
      try {
        bundle = validateBundle(body.bundle);
      } catch (e) {
        return send(res, 400, { error: (e as Error).message });
      }
      // Computed here, from the bytes that arrived. Never taken from the request — a submitted hash
      // would be the proposer's claim about content the approver never sees, and then the approval
      // check is decorative.
      return recordProposal(res, target.name, bundle, who);
    }

    /**
     * Propose the merged policy as a plan, from the console.
     *
     * ## Why this could not exist until now
     *
     * Proposing means rendering, and the manager's own header said so: "proposing means rendering the
     * policy, the policy repository is not in this image, and it must not be." That was arithmetic,
     * not caution — a TypeScript module's top level is code and this process holds the signing key.
     *
     * The premise changed when `heliopause-policy-render` arrived. The policy is *evaluated* in a pod
     * with no credential and arrives here as JSON; rendering it into rulesets is this process running
     * its own code over data, which is what it does with every other request body. So the console can
     * propose now, and until this route existed the browser could approve and publish a plan it had
     * no way to create — the loop closed everywhere except at its start.
     *
     * The bundle is built here rather than accepted from the browser deliberately. A console that
     * submitted rulesets would be a console that could submit *any* rulesets, and the whole point of
     * the two-person rule is that the approver reads what the proposer could not choose freely.
     */
    if (req.method === "POST" && url.pathname === "/policy/plan") {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      if (!opts.policySource) {
        return send(res, 404, { error: "this deployment does not carry a policy repository" });
      }
      let body: { target?: string };
      try {
        body = JSON.parse(await readBody(req)) as typeof body;
      } catch (e) {
        return send(res, 400, { error: `bad request body: ${(e as Error).message}` });
      }
      const target = opts.relays.find((r) => r.name === body.target);
      if (!target) {
        return send(res, 400, {
          error: `unknown target ${JSON.stringify(body.target ?? null)} — this manager knows ` +
            `${opts.relays.map((r) => r.name).join(", ")}`,
        });
      }
      let source;
      try {
        source = await fetchPolicySource(opts.policySource, timeoutMs);
      } catch (e) {
        return send(res, 503, { error: `the policy could not be read: ${(e as Error).message}` });
      }
      // The generation *names* the commit, so a checkout that cannot say which commit it is at, or is
      // not exactly at one, cannot be published from. `heliopause-publish` refuses the same two
      // states for the same reason; the read-only screen tolerates them because a label is not a name.
      if (source.head.sha === null) {
        return send(res, 409, { error: "the policy checkout does not report a commit — nothing to name this generation" });
      }
      if (source.head.dirty) {
        return send(res, 409, { error: `the policy checkout at ${source.head.sha} has uncommitted edits` });
      }
      let bundle: PlanBundle;
      try {
        const site = screenSiteOf(source);
        const plan = planPublish({
          cfg: site.cfg,
          generation: source.head.sha,
          issuedAt: now().toISOString(),
          hosts: site.hosts,
          ...(site.workload ? { workload: site.workload } : {}),
          ...(site.resolveService ? { resolveService: site.resolveService } : {}),
        } as Parameters<typeof planPublish>[0]);
        bundle = bundleFromPlan(plan);
      } catch (e) {
        // The renderer's own sentence. "This rule names a port the workload does not listen on" and
        // "the policy repository is unreachable" send an operator to completely different places.
        return send(res, 400, { error: `the policy did not render: ${(e as Error).message}` });
      }
      return recordProposal(res, target.name, bundle, who);
    }

    if (req.method === "POST" && url.pathname === "/approve") {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      let body: { hash?: string; otp?: string };
      try {
        body = JSON.parse(await readBody(req)) as typeof body;
      } catch (e) {
        return send(res, 400, { error: `bad request body: ${(e as Error).message}` });
      }
      if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
      try {
        // `alsoKnownAs` is what turns "the same name" into "the same person". An OIDC principal
        // arrives already collapsed onto one certificate name by its alias, and that name's other
        // certificates are the ones this adds — see `sameHumanAs`.
        const plan = approve(
          approvals,
          {
            hash: String(body.hash ?? ""),
            by: who,
            now: now(),
            mayApproveOwn: maySoloApprove,
            alsoKnownAs: sameHumanAs.get(who) ?? [],
          },
          limits,
        );
        log(
          `plan ${plan.hash.slice(0, 20)} approved by ${who} (proposed by ${plan.proposedBy})` +
            (plan.approval?.solo ? " — SOLO APPROVAL, no second operator was involved" : ""),
          `${who}이(가) 계획 ${plan.hash.slice(0, 20)}을(를) 승인함 (제안자 ${plan.proposedBy})` +
            (plan.approval?.solo ? " — 단독 승인, 두 번째 운영자가 관여하지 않음" : ""),
        );
        return send(res, 200, publicPlan(plan, planTargets.get(plan.hash) ?? null));
      } catch (e) {
        return sendApprovalError(res, e);
      }
    }

    if (req.method === "POST" && url.pathname === "/publish") {
      if (!mayWrite) return refuseWrite(res, who, url.pathname, principal.via);
      let body: { hash?: string; otp?: string };
      try {
        body = JSON.parse(await readBody(req)) as typeof body;
      } catch (e) {
        return send(res, 400, { error: `bad request body: ${(e as Error).message}` });
      }
      if ((await requireOtp(principal, body, res, url.pathname)) === "answered") return;
      const hash = String(body.hash ?? "");
      // Claimed before anything is pushed, so two concurrent publishes cannot both pass the check.
      // Released below only if nothing was written anywhere — see `release`.
      let plan;
      try {
        plan = claimForPublish(approvals, { hash, by: who, now: now() }, limits);
      } catch (e) {
        return sendApprovalError(res, e);
      }
      const bundle = bundles.get(hash);
      const target = opts.relays.find((r) => r.name === planTargets.get(hash));
      if (!bundle || !target) {
        // The plan survived a restart in neither map, or the target vanished from configuration. The
        // claim is released because nothing was pushed: this must read as "re-propose it", not as "that
        // generation is already published".
        release(approvals, hash);
        return send(res, 409, {
          error: `plan ${hash} is no longer held by this manager (it restarted, or its target VPC was ` +
            `reconfigured) — re-propose it`,
        });
      }

      let pushed;
      try {
        if (!opts.artifactSigning) {
          throw new Error("manager has no dedicated artifact signing key configured");
        }
        // Issued once per publish, not once per host. The process-local issuer advances by a
        // millisecond when a fixed/test clock publishes twice, so durable agent replay watermarks
        // never see two different plans with the same timestamp.
        const authorizedAt = authorizationTimestamps.next(now());
        const authorizationMode = plan.approval?.solo ? "solo-otp" : "two-person";
        const authorizedBundle = signAuthorizedArtifactBundle({
          target: target.name,
          bundle,
          authorizedAt,
          expiresAt: new Date(authorizedAt.getTime() + authorizationTtlSec * 1000),
          authorizationMode,
        }, opts.artifactSigning.privateKey);
        const tls = await loadRelayCreds(target);
        pushed = await relayCall<{ generation: string; serving: string | null }>(
          target.url,
          "/publish",
          "POST",
          JSON.stringify(authorizedBundle),
          tls,
          // Longer than a status poll. This one writes a fleet's worth of rulesets to disk on the far
          // side, and a timeout here would abandon a push that may well have landed.
          publishTimeoutMs,
        );
      } catch (e) {
        // Released: the push reached nothing, so the plan must stay publishable. Without this, a
        // network blip leaves an approved plan permanently unusable — re-proposing yields the same
        // hash, which is then refused as already published, and that reads as "publishing is broken"
        // during whatever incident prompted the change.
        release(approvals, hash);
        log(`publish of ${hash.slice(0, 20)} to ${target.name} FAILED: ${(e as Error).message}`, `${target.name}에 계획 ${hash.slice(0, 20)} 발행 실패: ${(e as Error).message}`);
        return send(res, 502, {
          error: `${target.name} did not accept the generation: ${(e as Error).message}`,
          // Said explicitly, because the operator's next question is whether to retry.
          published: false,
        });
      }

      // Remembered only after the relay accepted it, so the base is something the fleet actually got.
      lastPublished.set(target.name, { generation: plan.generation, bundle });
      log(
        `published ${plan.generation} to ${target.name}: proposed by ${plan.proposedBy}, ` +
          `approved by ${plan.approval?.by}, pushed by ${who}, signed by ` +
          `${artifactSigningKeyId(createPublicKey(opts.artifactSigning!.privateKey))}`,
        `${target.name}에 세대 ${plan.generation}을(를) 발행함: 제안 ${plan.proposedBy}, ` +
          `승인 ${plan.approval?.by}, 전송 ${who}, 서명 ` +
          `${artifactSigningKeyId(createPublicKey(opts.artifactSigning!.privateKey))}`,
      );
      return send(res, 200, {
        published: true,
        target: target.name,
        generation: pushed.generation,
        serving: pushed.serving,
        proposedBy: plan.proposedBy,
        approvedBy: plan.approval?.by ?? null,
        publishedBy: who,
      });
    }

    return send(res, 404, { error: "not found" });
  }

  /** Refused, and logged. An authenticated identity trying to change a firewall is worth a line. */
  /**
   * `/auth/login`, `/auth/callback`, `/auth/logout`.
   *
   * Answers with redirects and HTML-free bodies. Nothing here renders a page: a login that fails
   * should say why in a form an operator can read from `curl` as easily as from a browser, and the
   * console itself is behind the authorisation these routes exist to obtain.
   */
  async function handleAuth(
    o: NonNullable<typeof oidc>,
    url: URL,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const selfOrigin = `https://${req.headers["host"] ?? ""}`;

    if (req.method === "GET" && url.pathname === "/auth/login") {
      // Expire only from the oldest end, then evict the oldest live attempt at the hard cap. A full
      // scan on every anonymous request made a login flood quadratic; an unbounded map made it a
      // memory flood. `Map` insertion order gives both operations a bounded oldest-first path.
      const startedAt = Date.now();
      trimPendingOidcLogins(o.pending, startedAt);

      const { verifier, challenge } = pkce();
      const state = randomNonce();
      const n = randomNonce();
      // Stored as given and judged where it is used. **Validating here as well would be a check no
      // test can reach** — the callback's `safeReturnTo` already refuses everything this one would,
      // so injecting a defect into the second copy breaks nothing and it is indistinguishable from
      // dead code. One gate, at the point the value becomes a `Location` header.
      const next = url.searchParams.get("next");
      const returnTo = next && next.length <= 512 ? next : null;
      // The value goes to this browser as a cookie; only its digest is kept here. `state` travels
      // through the IdP in a URL and is therefore something an attacker can hold; this is not.
      const binder = loginBinder();
      o.pending.set(state, {
        verifier, nonce: n, at: startedAt, binder: binder.digest, ...(returnTo ? { returnTo } : {}),
      });
      const d = await o.provider.load();
      const to = authorizeUrl(d, {
        clientId: o.conf.clientId,
        redirectUri: o.conf.redirectUri,
        state,
        nonce: n,
        challenge,
        // `groups` is not optional here: authorisation is decided from that claim, so a login
        // without it produces a principal with no groups and no access.
        scopes: ["openid", "profile", "email", "groups"],
      });
      res.writeHead(302, {
        location: to,
        "set-cookie": loginCookieHeader(binder.value),
        "cache-control": "no-store",
      });
      return void res.end();
    }

    if (req.method === "GET" && url.pathname === "/auth/callback") {
      const state = url.searchParams.get("state") ?? "";
      const code = url.searchParams.get("code") ?? "";
      const idpError = url.searchParams.get("error");
      if (idpError) {
        // The IdP refused. Said plainly rather than as a generic failure — "access_denied" after
        // clicking cancel is not the same problem as a misconfigured client.
        return send(res, 400, { error: `the identity provider refused this login: ${idpError}` });
      }

      // Single use. Deleting on lookup means a replayed callback finds nothing, however well-formed
      // the rest of it is — which is what a captured callback URL amounts to.
      //
      // The map lookup *is* the check: `state` was generated here, from the CSPRNG, and only this
      // server has ever held it. There is no stored copy to compare against, so there is nothing for
      // a constant-time comparison to do — an earlier draft called one on `state` against itself,
      // which is a check that always passes.
      // Enforce the TTL at use time as well as at creation time. If no later login arrived to run
      // the insertion-side cleanup, an abandoned state must still not remain valid indefinitely.
      const found = state ? consumePendingOidcLogin(o.pending, state, Date.now()) : undefined;
      if (!found) {
        log(`login callback with an unknown state from ${req.socket.remoteAddress ?? "?"}`, `${req.socket.remoteAddress ?? "?"}에서 알 수 없는 state로 로그인 콜백을 보냄`);
        return send(res, 400, { error: "this login did not start here, or it has expired" });
      }

      // ## `state` says the login started here. This says it started in *this browser*.
      //
      // They are different claims and only the second one stops a login CSRF. `state` travels
      // through the identity provider in a URL, so an attacker who begins a login of their own holds
      // a valid one — and a victim walked to `/auth/callback?state=…&code=…` would be handed the
      // attacker's session, on a console that can approve and publish. See `session.ts`.
      //
      // The cookie is cleared on every outcome below, including this refusal: it is spent whether or
      // not it matched, and leaving it would let a second attempt reuse it.
      if (!loginBinderMatches(readCookie(req.headers["cookie"], LOGIN_COOKIE), found.binder)) {
        log(
          `login callback from ${req.socket.remoteAddress ?? "?"} did not carry the browser that started it`,
          `${req.socket.remoteAddress ?? "?"}의 로그인 콜백이 로그인을 시작한 브라우저를 증명하지 못함`,
        );
        res.writeHead(400, {
          "content-type": "application/json",
          "set-cookie": clearLoginCookieHeader(),
          "cache-control": "no-store",
        });
        return void res.end(JSON.stringify({
          error: "this login did not start in this browser — open /auth/login here and try again",
        }));
      }

      let identity;
      try {
        identity = await exchange(o.provider, {
          code,
          clientId: o.conf.clientId,
          ...(o.conf.clientSecret ? { clientSecret: o.conf.clientSecret } : {}),
          redirectUri: o.conf.redirectUri,
          verifier: found.verifier,
          expectedNonce: found.nonce,
        }, o.conf.fetchImpl ?? fetch);
      } catch (e) {
        log(`login failed: ${(e as Error).message}`, `로그인 실패: ${(e as Error).message}`);
        return send(res, 401, { error: `login failed: ${(e as Error).message}` });
      }

      const decision = authorize(identity, {
        operatorGroups: o.conf.operatorGroups,
        writerGroups: o.conf.writerGroups,
        aliases: o.conf.aliases,
      });
      if (!decision.principal) {
        log(`login refused for ${identity.email ?? identity.sub}: ${decision.reason}`, `${identity.email ?? identity.sub}의 로그인 거부: ${decision.reason}`);
        return send(res, 403, { error: `signed in, but not authorised: ${decision.reason}` });
      }

      const evictedBefore = o.sessions.evictionReport.count;
      const s = o.sessions.create({ ...decision.principal, canWrite: decision.canWrite });
      log(
        `session for ${s.principal.name} via oidc (sub ${identity.sub}), ` +
          `${decision.canWrite ? "may write" : "read only"} — ${decision.reason}`,
        `${s.principal.name}의 OIDC 세션 (sub ${identity.sub}), ` +
          `${decision.canWrite ? "쓰기 가능" : "읽기 전용"} — ${decision.reason}`,
      );
      // The session table is capped, and reaching the cap throws out the oldest **live** session
      // rather than refusing the new login — otherwise anyone could lock the operator out by filling
      // it. The cost is that a real operator can be signed out by somebody else's login loop, and
      // all they see is that they were signed out. Said here so the other half exists in the journal.
      const evicted = o.sessions.evictionReport;
      if (evicted.count > evictedBefore) {
        log(
          `session table is full — evicted the oldest live session (${evicted.last}) to admit this ` +
            `login; ${evicted.count} evicted since start`,
          `세션 테이블이 가득 참 — 이 로그인을 받기 위해 가장 오래된 활성 세션(${evicted.last})을 축출함; ` +
            `시작 이후 ${evicted.count}건`,
        );
      }
      // Back to the page that sent them here, if it named one this server will follow.
      //
      // **This is the only gate**, and it is on the way out on purpose. The stored value came from a
      // query parameter, so it is caller-controlled; what makes it safe is not where it was written
      // but that nothing turns it into a `Location` without passing `safeReturnTo` first. Deleting
      // this call fails `refuses to be turned into an open redirect`.
      res.writeHead(302, {
        location: safeReturnTo(found.returnTo ?? null) ?? "/",
        // Two, in one header: the session, and the removal of the login binder. The binder has done
        // its job at this point and a value left in a browser is a value that can be replayed into
        // the next attempt.
        "set-cookie": [cookieHeader(s), clearLoginCookieHeader()],
        "cache-control": "no-store",
      });
      return void res.end();
    }

    if (req.method === "POST" && url.pathname === "/auth/role-change") {
      // Unauthenticated by design: the IdP posts this and the signature is the authentication. There
      // is nothing else it could present — it holds no session and no certificate here.
      //
      // Answers 204 on anything it decides not to act on, and a status on anything it refuses. The
      // IdP does not retry (KeyStone: "재시도 없음"), so a body here is for a human reading the
      // delivery log, not for a machine.
      let form: URLSearchParams;
      try {
        form = new URLSearchParams(await readBody(req));
      } catch (e) {
        return send(res, 400, { error: `bad request body: ${(e as Error).message}` });
      }
      const token = form.get("role_change_token") ?? "";
      if (!token) return send(res, 400, { error: "no role_change_token in the body" });

      let change;
      try {
        change = await verifyRoleChange(o.provider, token, {
          clientId: o.conf.clientId,
          issuer: o.conf.issuer,
          ledger: o.ledger,
          eventKey: o.conf.roleChangeEvent,
        });
      } catch (e) {
        // Logged loudly. A refused role change means an authority reduction did not take effect, and
        // the only place that fact exists is this line.
        log(`role-change REFUSED: ${(e as Error).message}`, `역할 변경 거부: ${(e as Error).message}`);
        return send(res, (e as { status?: number }).status ?? 400, { error: (e as Error).message });
      }

      // Re-decide with the new claims, through the same function a login uses. Two code paths that
      // both answer "what may this identity do" is how they come to disagree.
      const outcome = o.sessions.applyToSubject(change.sub, (current) => {
        const d = authorize(
          {
            sub: change.sub,
            username: null,
            email: null,
            groups: change.roles,
            expiresAt: new Date(0),
          },
          {
            operatorGroups: o.conf.operatorGroups,
            writerGroups: o.conf.writerGroups,
            aliases: o.conf.aliases,
          },
        );
        // No operator role any more — end the session rather than demote it to one that
        // authenticates and can do nothing.
        if (!d.principal) return null;
        // The name is kept from the live session. `authorize` would rederive it from claims this
        // token does not carry (it has no email or username), and a principal whose name changed
        // mid-session would break the two-person rule's string comparison.
        return { ...d.principal, name: current.name, canWrite: d.canWrite };
      });

      log(
        `role-change for sub ${change.sub}: roles [${change.roles.join(", ")}] — ` +
          `${outcome.updated} session(s) updated, ${outcome.ended} ended`,
        `sub ${change.sub}의 역할 변경: 역할 [${change.roles.join(", ")}] — ` +
          `세션 ${outcome.updated}개 갱신, ${outcome.ended}개 종료`,
      );
      res.writeHead(204, { "cache-control": "no-store" });
      return void res.end();
    }

    if (req.method === "POST" && url.pathname === "/auth/backchannel-logout") {
      // ## The endpoint that makes the client's Back-channel Logout URI worth filling in
      //
      // KeyStone has discovered logout targets by subject since 2026-08-06, so an administrator's
      // force-logout does reach clients that registered an endpoint. This console had none, and the
      // URI was deliberately left blank — **filling it in without this route would be worse than
      // leaving it empty**, because the administrator would see a successful logout while every
      // session kept working.
      //
      // Unauthenticated by design, like `/auth/role-change`: the IdP holds no session and no
      // certificate here, and the token's signature is the authentication.
      let form: URLSearchParams;
      try {
        form = new URLSearchParams(await readBody(req));
      } catch (e) {
        return send(res, 400, { error: `bad request body: ${(e as Error).message}` });
      }
      const token = form.get("logout_token") ?? "";
      if (!token) return send(res, 400, { error: "no logout_token in the body" });

      let logout;
      try {
        logout = await verifyBackchannelLogout(o.provider, token, {
          clientId: o.conf.clientId,
          issuer: o.conf.issuer,
          // The same ledger as role changes. One `jti` space, because a token is single-use whatever
          // it says, and two ledgers would let the same id be spent once in each.
          ledger: o.ledger,
        });
      } catch (e) {
        // Loud, for the same reason a refused role change is: an administrator believes this person
        // is signed out, and this line is the only place that says otherwise.
        log(`backchannel-logout REFUSED: ${(e as Error).message}`, `백채널 로그아웃 거부: ${(e as Error).message}`);
        return send(res, (e as { status?: number }).status ?? 400, { error: (e as Error).message });
      }

      // Every session this subject holds. `backchannel_logout_session_required` is off, so the token
      // names a person and not a session — see `verifyBackchannelLogout`.
      const outcome = o.sessions.applyToSubject(logout.sub, () => null);
      log(`backchannel-logout for sub ${logout.sub}: ${outcome.ended} session(s) ended`, `sub ${logout.sub}의 백채널 로그아웃: 세션 ${outcome.ended}개 종료`);
      // 204 even when nothing matched. A person who is not signed in has been logged out as far as
      // the administrator is concerned, and a 404 here would read as a delivery failure worth
      // retrying — which the IdP does not do anyway.
      res.writeHead(204, { "cache-control": "no-store" });
      return void res.end();
    }

    if (req.method === "POST" && url.pathname === "/auth/logout") {
      // POST, so a cross-site page cannot end an operator's session with an image tag. The Origin
      // check is the same one the write routes use; there is no CSRF token because ending your own
      // session is not an action worth a token, and refusing it on a technicality would leave a
      // session alive that its owner asked to destroy.
      const origin = req.headers["origin"];
      if (typeof origin === "string" && origin !== selfOrigin) {
        return send(res, 403, { error: "cross-site requests cannot end a session" });
      }
      const id = readCookie(req.headers["cookie"], COOKIE);
      const s = o.sessions.get(id);
      if (s) log(`session for ${s.principal.name} ended`, `${s.principal.name}의 세션 종료`);
      o.sessions.destroy(id);

      // ## The local session is gone; the IdP's is not
      //
      // Destroying this cookie ends nothing at the identity provider, and the authorization request
      // is answered from **its** session. Before `prompt=login` and this redirect, sign-out followed
      // by sign-in put the same operator back in with no credential asked for — on a shared
      // workstation, a sign-out button that signs nobody out.
      //
      // The URL is handed back rather than sent as a 302 because this is a `fetch` from the console,
      // and a redirect answered to `fetch` is followed by `fetch`, not by the browser. The console
      // navigates. `null` — no `end_session_endpoint`, or no provider at all — means it goes to `/`
      // as before, which is still a destroyed session behind a login page.
      //
      // Computed after the destroy, deliberately: whether the IdP offers this must not decide
      // whether the local session ends.
      let endSession: string | null = null;
      if (o.provider) {
        try {
          endSession = endSessionUrl(await o.provider.load(), {
            clientId: o.conf.clientId,
            postLogoutRedirectUri: postLogoutRedirectUri(o.conf.redirectUri),
          });
        } catch (e) {
          // The discovery document could not be read. The session is already destroyed, so this is
          // a lost convenience and not a failed logout; saying so beats a 500 on a sign-out.
          log(
            `logout: could not read the provider document for RP-initiated logout: ${(e as Error).message}`,
            `로그아웃: RP-initiated 로그아웃을 위한 provider 문서를 읽지 못함: ${(e as Error).message}`,
          );
        }
      }
      res.writeHead(200, {
        "content-type": "application/json",
        "set-cookie": clearCookieHeader(),
        "cache-control": "no-store",
      });
      return void res.end(JSON.stringify({ endSession }));
    }

    return send(res, 404, { error: `no such route ${url.pathname}` });
  }

  /**
   * Everything an app token is allowed to reach, and the two refusals in front of it.
   *
   * The route table is explicit. Token minting and CSR reads remain non-destructive;
   * `enrollment:host-deregister` is a separately issued destructive grant, constrained by the same
   * hostname pattern and an immutable lifecycle id. It still cannot sign, upload, reject, or invoke
   * arbitrary token/certificate revocation routes.
   *
   * ## Why an unknown token and a wrong route answer differently
   *
   * An unknown, expired or revoked token is 401 and says only "unauthorized app token": from outside,
   * the three are one answer, because telling a holder which of them applies tells them whether the
   * value they hold was ever real. A *valid* token asking for a route outside its grant is 403 and
   * names the token, because the person reading that log is an operator deciding whether to widen a
   * scope or fix a caller, and "401" would send them looking for a credential problem that is not
   * there.
   *
   * ## The two bootstrap routes answer 401 here, and that is the ordering, not a bug
   *
   * `POST /infra/node-csrs` and `GET /infra/node-csrs/<id>/certificate` are dispatched **above** this
   * split, and their gate is `looksLikeNodeToken`. An app token fails that shape test and is refused
   * `unauthorized node token` before this function is reached — so those two never appear in the
   * route table below and never could. That is the right answer rather than an accident: they are
   * the agent's own credential path, an app token has no CSR of its own, and moving the split above
   * them would put a lookup for app-token shapes in front of the one route every fleet host has to
   * reach at boot.
   *
   * ## What the expiry header is for
   *
   * Every accepted answer carries `X-Heliopause-App-Token-Expires-At`. The caller already holds the
   * token, so its expiry tells them nothing they could not learn by trying — and without it the first
   * sign of a lapsed credential is a 401 in the middle of somebody's provisioning saga. It is absent
   * from refusals on purpose: a 401 must not become a way to ask whether a guessed token exists and
   * when it dies.
   */
  async function handleAppToken(
    plaintext: string, url: URL, req: IncomingMessage, res: ServerResponse, storeFile: string,
  ): Promise<void> {
    try {
      // Same bound as the certificate-less enrollment routes, and applied for the same reason: the
      // read below is synchronous and the transaction after it takes the `O_EXCL` lock.
      if (enrollmentFloodRefused(req, res)) return;

      // The cross-site refusal is kept exactly as it is for operators. A dispatcher sends neither
      // header, so it costs that caller nothing; a browser page that somehow obtained an app token
      // is precisely the case this refuses. The CSRF check is deliberately *not* kept — it reads a
      // cookie session, and an app token never has one.
      if ((req.method === "POST" || req.method === "PUT") && crossSiteRequest(req)) {
        log(
          `refused ${url.pathname} for an app token: cross-site request`,
          `앱 토큰의 ${url.pathname} 거부: 교차 사이트 요청`,
        );
        return send(res, 403, { error: "cross-site requests cannot change the fleet" });
      }

      const deregistrationRoute = /^\/enrollment\/host-deregistrations\/([^/]+)\/([^/]+)(?:\/(infrastructure-destroyed))?$/.exec(url.pathname);
      const scope: AppTokenScope | null =
        req.method === "POST" && url.pathname === "/enrollment/tokens" ? "enrollment:token-create"
          : req.method === "GET" && url.pathname === "/enrollment/requests" ? "enrollment:requests-read"
            : deregistrationRoute && (req.method === "GET" || req.method === "PUT") ? "enrollment:host-deregister"
            : null;

      // ## The gate: a read, and what it does and does not settle
      //
      // Everything refused from here down to the route split — an unknown, expired or revoked token
      // (401), a route outside the table (403), a scope the token does not carry (403) — is settled
      // **before any lock is taken**, from this one read. `lastUsedAt` is not persisted for them: a
      // use that was refused is not a use.
      //
      // What is *not* settled here is the hostname against the pattern. That check is deliberately
      // inside the write transaction below, next to the issue it guards — a 403 taken from this read
      // and an issue taken from a later document are two decisions about two documents, and a revoke
      // or a pattern change landing between them would be honoured by neither. The cost is that a
      // pattern-mismatch 403 does take the lock. That is the correct side to err on.
      //
      // The read route answers **from this same document**. A second `requireEnrollmentDocument`
      // would parse the file again with no lock held between the two, so it is not a fresher answer
      // — it is a second answer to the same question, and the one that arrives second is no more
      // authoritative than the one that arrived first. The `POST` path re-checks inside its
      // transaction because there the lock *is* the boundary: the document it authorises against is
      // the document it commits.
      const document = requireEnrollmentDocument(storeFile);
      const gate = lookupAppToken(document, plaintext);
      if (!gate) {
        log(`refused ${url.pathname}: unknown, expired or revoked app token`, `${url.pathname} 거부: 모르거나 만료·폐기된 앱 토큰`);
        return send(res, 401, { error: "unauthorized app token" });
      }
      if (scope === null || !gate.scopes.includes(scope)) {
        log(
          `refused ${url.pathname} for app token ${gate.label} (${gate.id}): outside its scopes (${gate.scopes.join(",")})`,
          `앱 토큰 ${gate.label} (${gate.id})의 ${url.pathname} 거부: 스코프(${gate.scopes.join(",")}) 밖`,
        );
        return send(res, 403, { error: `app token ${gate.label} is not authorised for ${url.pathname}` });
      }

      if (scope === "enrollment:requests-read") {
        // 🔴 Reading the queue must not take the `O_EXCL` lock, and this route used to — it wrapped
        // itself in `enrollmentWrite` for no reason but to persist `lastUsedAt`, paying an exclusive
        // lock, a full re-serialisation and an `fsync` for a request that changes nothing. A poller
        // on this route would then serialise against every token issue and every certificate upload
        // in the deployment.
        //
        // So `lastUsedAt` records **token creation only**. `lookupAppToken` still set it on the
        // document read above, and that document is discarded — deliberately. The field answers "is
        // anything still minting with this credential", which is the question asked before revoking
        // one; it does not answer "did anyone read the queue". The README says so where the field is
        // documented, because a timestamp that means less than its name is worse than no timestamp.
        //
        // ## The queue is narrowed to the token's own pattern
        //
        // 🔴 This returned the whole fleet's queue. A `*.dev` token could read every hostname and
        // every public-key digest in `prod` and `util` — zones it cannot mint for and has no business
        // enumerating. The pattern already bounds what the token may *create*; it now bounds what it
        // may *see*, so the two halves of the grant say the same thing.
        //
        // A `?hostname=` outside the pattern is an empty list rather than a 403. A refusal there
        // would answer "is this host inside your pattern?" for any name the caller cares to try,
        // turning a read into an oracle for a boundary the caller is not supposed to map.
        const filter = csrQueryFilter(url);
        const requests = document.requests.filter((request) =>
          appTokenAllowsHostname(gate.hostnamePattern, request.hostname) && matchesCsrFilter(request, filter));
        return send(res, 200, { requests }, { "x-heliopause-app-token-expires-at": gate.expiresAt });
      }

      if (scope === "enrollment:host-deregister" && deregistrationRoute) {
        let wanted: string;
        let externalOperationId: string;
        try {
          wanted = normalizeEnrollmentHostname(decodeURIComponent(deregistrationRoute[1]!));
          externalOperationId = normalizeExternalOperationId(decodeURIComponent(deregistrationRoute[2]!));
        } catch {
          throw new EnrollmentError("host deregistration path is malformed");
        }
        if (!appTokenAllowsHostname(gate.hostnamePattern, wanted)) {
          return send(res, 404, { error: "host deregistration not found" });
        }
        const responseHeaders = { "x-heliopause-app-token-expires-at": gate.expiresAt };
        if (req.method === "GET") {
          if (deregistrationRoute[3]) return send(res, 403, { error: `app token ${gate.label} is not authorised for ${url.pathname}` });
          const row = enrollmentWrite(storeFile, (current) => {
            const authorised = authoriseAppToken(current, plaintext, scope, url.pathname);
            if (!appTokenAllowsHostname(authorised.hostnamePattern, wanted)) {
              throw new EnrollmentError("host deregistration not found", 404);
            }
            const operation = current.hostDeregistrations.find((candidate) =>
              candidate.hostname === wanted && candidate.externalOperationId === externalOperationId);
            if (!operation || operation.scope.hostnamePattern !== authorised.hostnamePattern) {
              throw new EnrollmentError("host deregistration not found", 404);
            }
            return operation.status === "completed"
              ? operation
              : reconcileHostDeregistrationRelays(operation, opts.relays.map((relay) => relay.name));
          });
          return send(res, 200, { operation: row }, responseHeaders);
        }

        const rawBody: unknown = JSON.parse(await readBody(req));
        if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
          throw new EnrollmentError("request body must be an object");
        }
        const parsed = rawBody as Record<string, unknown>;
        const allowedFields = deregistrationRoute[3]
          ? ["hostLifecycleId", "provider", "providerInstanceId", "destroyedAt"]
          : ["hostLifecycleId", "reason", "requestedBy"];
        if (Object.keys(parsed).some((key) => !allowedFields.includes(key))) {
          throw new EnrollmentError("request contains unsupported fields");
        }
        if (typeof parsed.hostLifecycleId !== "string") throw new EnrollmentError("hostLifecycleId must be a string");
        if (deregistrationRoute[3] === "infrastructure-destroyed") {
          if (parsed.provider !== "vultr") throw new EnrollmentError('provider must be exactly "vultr"');
          if (typeof parsed.providerInstanceId !== "string") throw new EnrollmentError("providerInstanceId must be a string");
          if (typeof parsed.destroyedAt !== "string") throw new EnrollmentError("destroyedAt must be a string");
          const row = enrollmentWrite(storeFile, (current) => {
            const authorised = authoriseAppToken(current, plaintext, scope, url.pathname);
            if (!appTokenAllowsHostname(authorised.hostnamePattern, wanted)) {
              throw new EnrollmentError("host deregistration not found", 404);
            }
            const existing = current.hostDeregistrations.find((candidate) =>
              candidate.hostname === wanted && candidate.externalOperationId === externalOperationId);
            if (!existing || existing.scope.hostnamePattern !== authorised.hostnamePattern) {
              throw new EnrollmentError("host deregistration not found", 404);
            }
            return confirmHostInfrastructureDestroyed(current, {
              hostname: wanted, externalOperationId, hostLifecycleId: parsed.hostLifecycleId as string,
              provider: "vultr", providerInstanceId: parsed.providerInstanceId as string,
              destroyedAt: parsed.destroyedAt as string, actor: appTokenCreatedBy(authorised.label, authorised.id),
            });
          });
          return send(res, row.status === "completed" ? 200 : 202, { operation: row }, responseHeaders);
        }
        if (parsed.reason !== "instance-destroy") throw new EnrollmentError('reason must be exactly "instance-destroy"');
        if (typeof parsed.requestedBy !== "string") throw new EnrollmentError("requestedBy must be a string");
        const result = enrollmentWrite(storeFile, (current) => {
          const authorised = authoriseAppToken(current, plaintext, scope, url.pathname);
          if (!appTokenAllowsHostname(authorised.hostnamePattern, wanted)) {
            throw new EnrollmentError("host deregistration not found", 404);
          }
          const existing = current.hostDeregistrations.find((candidate) =>
            candidate.hostname === wanted && candidate.externalOperationId === externalOperationId);
          if (existing && existing.scope.hostnamePattern !== authorised.hostnamePattern) {
            throw new EnrollmentError("host deregistration not found", 404);
          }
          return beginHostDeregistration(current, {
            hostname: wanted, externalOperationId, hostLifecycleId: parsed.hostLifecycleId as string,
            reason: "instance-destroy", requestedBy: parsed.requestedBy as string,
            actor: appTokenCreatedBy(authorised.label, authorised.id),
            scope: { appTokenId: authorised.id, label: authorised.label, hostnamePattern: authorised.hostnamePattern },
            relayNames: opts.relays.map((relay) => relay.name),
          });
        });
        if (result.row.credentials.state !== "blocked") await replicateRevocations();
        const current = requireEnrollmentDocument(storeFile).hostDeregistrations.find((candidate) =>
          candidate.hostname === wanted && candidate.externalOperationId === externalOperationId)!;
        return send(res, 202, { operation: current }, {
          ...responseHeaders,
          location: `/enrollment/host-deregistrations/${encodeURIComponent(wanted)}/${encodeURIComponent(externalOperationId)}`,
        });
      }

      const body = JSON.parse(await readBody(req)) as {
        hostname?: unknown; hostLifecycleId?: unknown; label?: unknown; revokeExisting?: unknown; ttlSec?: unknown; otp?: unknown;
      };
      // An OTP arriving here is not a harmless extra field: it means the caller believes it is on the
      // operator path, where a one-time code is checked against a person. Ignoring it would let that
      // belief live in somebody's configuration until the day they rely on a second factor that was
      // never read. Refused rather than dropped.
      if (body.otp !== undefined) {
        throw new EnrollmentError(
          "an app token has no operator behind it, so a one-time code cannot be checked — omit `otp`",
        );
      }
      // Type-checked, never coerced: `String(undefined)`, `Boolean("false")` and `Number("x")` each
      // turn a malformed field into a plausible value. See `security-audits/2026-08-25-audit-todo.md`
      // A1 for the measured version of that mistake.
      if (typeof body.hostname !== "string") throw new EnrollmentError("hostname must be a string");
      if (typeof body.hostLifecycleId !== "string") throw new EnrollmentError("hostLifecycleId must be a string");
      const hostLifecycleId = body.hostLifecycleId;
      const label = typeof body.label === "string" ? body.label : undefined;
      if (body.label !== undefined && label === undefined) throw new EnrollmentError("label must be a string");
      const revokeExisting = typeof body.revokeExisting === "boolean" ? body.revokeExisting : undefined;
      if (body.revokeExisting !== undefined && revokeExisting === undefined) {
        throw new EnrollmentError("revokeExisting must be a boolean");
      }
      const ttlSec = typeof body.ttlSec === "number" ? body.ttlSec : undefined;
      if (body.ttlSec !== undefined && ttlSec === undefined) throw new EnrollmentError("ttlSec must be a number");
      // Normalised before the pattern is consulted so that a hostname which is not a hostname is a
      // 400 rather than a 403 — "yours is not among these" is the wrong advice for a typo.
      const wanted = normalizeEnrollmentHostname(body.hostname);

      // One transaction: authorise, check the pattern, issue. Split into two, a revoke landing
      // between them would be checked against a token the store no longer honours.
      const issued = enrollmentWrite(storeFile, (document) => {
        const row = authoriseAppToken(document, plaintext, scope, url.pathname);
        if (!appTokenAllowsHostname(row.hostnamePattern, wanted)) {
          // Both halves named on purpose: the operator reading this has to decide whether the caller
          // asked for the wrong host or the token was issued with the wrong pattern.
          throw new EnrollmentError(
            `app token ${row.label} is scoped to ${row.hostnamePattern}, and ${wanted} is outside it`,
            403,
          );
        }
        return {
          label: row.label, id: row.id, expiresAt: row.expiresAt,
          ...createNodeToken(document, {
            hostname: wanted,
            hostLifecycleId,
            ...(label === undefined ? {} : { label }),
            // Both halves, because **a label is not an identifier**: two live app tokens may share
            // one so that a rotation has no gap, and `app:dispatcher` alone cannot say which of them
            // minted this. The id is also in the audit row's `detail.appTokenId`, structured, for
            // the reader that is a query rather than a person.
            //
            // Composed by the store rather than here: the field is truncated on the way in, and a
            // 120-character label made that truncation eat the id — see `appTokenCreatedBy`.
            createdBy: appTokenCreatedBy(row.label, row.id),
            appTokenId: row.id,
            ...(revokeExisting === undefined ? {} : { revokeExisting }),
            ...(ttlSec === undefined ? {} : { ttlSec }),
          }),
        };
      });
      const { tokenHash: _secret, ...row } = issued.row;
      // The label and the two ids, never the plaintext and never the hash. What an operator needs
      // from this line is which program asked and for which host.
      log(
        `issued node token ${row.id} for ${row.hostname} to app token ${issued.label} (${issued.id})`,
        `앱 토큰 ${issued.label} (${issued.id})에 ${row.hostname}용 노드 토큰 ${row.id} 발급`,
      );
      return send(res, 201, { ok: true, id: row.id, token: issued.token, row },
        { "x-heliopause-app-token-expires-at": issued.expiresAt });
    } catch (e) { return sendEnrollmentError(res, e); }
  }

  /**
   * The authoritative app-token check, run inside a transaction.
   *
   * The gate in `handleAppToken` answers 401 and 403 from a read taken before the lock. This repeats
   * it against the document the write will be committed against, so a revoke that lands in between
   * is honoured rather than raced past.
   */
  function authoriseAppToken(
    document: EnrollmentDocument, plaintext: string, scope: AppTokenScope, path: string,
  ): AppTokenRecord {
    const row = lookupAppToken(document, plaintext);
    if (!row) throw new EnrollmentError("unauthorized app token", 401);
    if (!row.scopes.includes(scope)) throw new EnrollmentError(`app token ${row.label} is not authorised for ${path}`, 403);
    return row;
  }

  /**
   * The refusal for a caller who may read and may not change.
   *
   * `via` is not cosmetic. The message used to say "this certificate", which is advice pointing at
   * the wrong thing for somebody who signed in through a browser — they would go looking at a
   * certificate they never presented. A refusal that misdirects costs more than a vague one.
   */
  /**
   * Require a one-time code before a request that approves or publishes.
   *
   * Returns `null` when the request may proceed; otherwise it has already answered.
   *
   * ## Why the user id is resolved here and not at login
   *
   * An OIDC principal carries its own — the `sub` claim is the KeyStone user id. A certificate
   * carries none, so the mapping is configuration. Resolving both in one place means there is one
   * answer to "who is this, to the IdP", and one refusal when there isn't one.
   */
  async function requireOtp(
    p: Principal,
    body: { otp?: unknown },
    res: ServerResponse,
    path: string,
  ): Promise<"ok" | "answered"> {
    // Captured before the first `await`. TypeScript's narrowing of `opts.otp` does not survive the
    // suspension points below, and reaching for `opts.otp!` there would be asserting a fact this
    // line can simply hold.
    const otp = opts.otp;
    if (!otp) return "ok";

    const userId = p.via === "oidc" ? p.sub : otp.users.get(p.name);
    if (!userId) {
      // Refused rather than waved through. A writer this deployment cannot identify to the IdP is a
      // writer whose second factor cannot be checked, and the safe reading of that is "not yet".
      log(`${path} REFUSED for ${p.name}: no IdP user id mapped`, `${p.name}의 ${path} 거부: 매핑된 IdP 사용자 ID가 없음`);
      return answered(
        res, 403,
        `${p.name} may write but is not mapped to an identity provider account, so a one-time code ` +
          `cannot be checked. Add it to the manager's OTP user map.`,
      );
    }

    const code = typeof body.otp === "string" ? body.otp : "";
    if (!code) {
      return answered(res, 401, "this action needs a one-time code — send it as `otp` in the request body");
    }

    const r = await verifyOtp(
      { baseUrl: otp.issuerUrl, serviceToken: otp.serviceToken, userId, code },
      otp.fetchImpl ?? fetch,
    );
    if (r.ok) return "ok";
    // Logged with the reason, because two of these are the deployment's fault and would otherwise be
    // invisible — an operator seeing 503 has no way to tell a broken service token from a slow IdP.
    log(`${path} REFUSED for ${p.name}: one-time code ${r.reason} (${r.detail})`, `${p.name}의 ${path} 거부: 일회용 코드 ${r.reason} (${r.detail})`);
    return answered(res, statusFor(r.reason), r.detail);
  }

  function answered(res: ServerResponse, status: number, error: string): "answered" {
    send(res, status, { error });
    return "answered";
  }

  function refuseWrite(res: ServerResponse, name: string, path: string, via: Principal["via"]) {
    log(`${path} REFUSED for ${name}: reads the fleet but may not change it`, `${name}의 ${path} 거부: 함대는 읽을 수 있지만 변경할 수 없음`);
    return send(res, 403, {
      error:
        via === "certificate"
          ? "this certificate may read the site but is not authorised to change the fleet"
          : "this account may read the site but is not authorised to change the fleet — " +
            "its groups do not grant write access, or it has no alias to a certificate name",
    });
  }

  function sendApprovalError(res: ServerResponse, e: unknown) {
    if (e instanceof ApprovalError) {
      log(`refused: ${e.message}`, `거부: ${e.message}`);
      return send(res, e.status, { error: e.message });
    }
    throw e;
  }

  // ## What the identity provider has to be configured with, said out loud
  //
  // Three values on this side have a counterpart on the IdP's side, and **all three fail silently
  // when the two disagree** — which is the only reason this line exists.
  //
  //   · the redirect URI          registered wrong → login breaks loudly. This one is fine.
  //   · the back-channel logout   **not registered → an administrator's force-logout reaches
  //                               nobody, and the IdP reports success.** `session.ts` records that
  //                               the route was built first precisely so this could be filled in;
  //                               it is still blank, and nothing anywhere said so.
  //   · the role-change event key RFC 8417 leaves it to the issuer, so a mismatch is not an error:
  //                               the token verifies, the key does not match, and the authority
  //                               change is discarded as "carries no role-change event". `set.ts`
  //                               refused to default it for exactly this reason.
  //
  // The manager cannot read the IdP's client registration, so it cannot check any of them. What it
  // can do is state what it expects, once, where an operator comparing the two has something to
  // compare against. Before this, the startup journal said nothing about OIDC at all.
  if (oidc) {
    // Derived from the redirect URI rather than configured separately: they are the same origin by
    // construction, and a second variable would be a second thing to get wrong.
    let logoutUri = "(cannot derive — check HELIOPAUSE_OIDC_REDIRECT_URI)";
    let postLogoutUri = logoutUri;
    try {
      logoutUri = new URL("/auth/backchannel-logout", oidc.conf.redirectUri).toString();
      postLogoutUri = postLogoutRedirectUri(oidc.conf.redirectUri);
    } catch { /* the redirect URI is not a URL; the login path will say so first */ }
    log(
      `oidc: issuer ${oidc.conf.issuer}, client ${oidc.conf.clientId}. The IdP must have these ` +
        `registered for this deployment — nothing here can verify them:\n` +
        `[manager]   redirect URI            ${oidc.conf.redirectUri}\n` +
        `[manager]   back-channel logout URI ${logoutUri}  (session_required: off)\n` +
        `[manager]   post-logout redirect    ${postLogoutUri}\n` +
        `[manager]   role-change event key   ${oidc.conf.roleChangeEvent}\n` +
        `[manager]   A blank logout URI means a force-logout at the IdP ends nothing here and still ` +
        `reports success. A role-change key that differs from the issuer's means every authority ` +
        `change is discarded silently.`,
      `oidc: 발급자 ${oidc.conf.issuer}, 클라이언트 ${oidc.conf.clientId}. IdP 에 아래가 등록돼 ` +
        `있어야 하며 이쪽에서는 확인할 수 없음:\n` +
        `[manager]   리다이렉트 URI      ${oidc.conf.redirectUri}\n` +
        `[manager]   백채널 로그아웃 URI ${logoutUri}  (session_required: off)\n` +
        `[manager]   로그아웃 후 리다이렉트 ${postLogoutUri}\n` +
        `[manager]   역할 변경 이벤트 키 ${oidc.conf.roleChangeEvent}\n` +
        `[manager]   로그아웃 URI 가 비어 있으면 IdP 의 강제 로그아웃이 여기서 아무것도 끝내지 ` +
        `못하면서 성공을 보고함. 역할 변경 키가 발급자의 것과 다르면 모든 권한 변경이 조용히 버려짐.`,
    );
  }

  await new Promise<void>((resolve, reject) => {
    const failed = (error: Error) => reject(error);
    server.once("error", failed);
    server.listen(opts.port, opts.hostname ?? "::", () => {
      server.off("error", failed);
      resolve();
    });
  });
  logEvent("server.listening", {
    address: `${opts.hostname ?? "::"}:${opts.port}, aggregating ${opts.relays.length} relay(s): ${opts.relays.map((r) => r.name).join(", ")}`,
  });
  // The refresh timer is `unref`ed, so it cannot keep the process alive on its own — but it can
  // still fire against a closed server in a test that starts several managers. Tying it to `close`
  // means the caller's existing cleanup is enough and no test has to know this timer exists.
  if (refreshTimer) server.once("close", () => clearInterval(refreshTimer));
  // The retry ladder reschedules itself, so the handle at close is not the one that was created at
  // startup — it is read at that moment rather than captured. Unref'd already, so this is about not
  // leaving a timer firing against a closed server in a test process that keeps running.
  server.once("close", () => { retryStopped = true; if (retryTimer) clearTimeout(retryTimer); });
  let revocationTimer: ReturnType<typeof setInterval> | null = null;
  if (opts.enrollment) {
    void replicateRevocations();
    revocationTimer = setInterval(() => void replicateRevocations(), 60_000);
    revocationTimer.unref();
    server.once("close", () => clearInterval(revocationTimer!));
  }
  if (opts.policyWorker && opts.enrollment && opts.policySource && opts.policyWrite) {
    const stopPolicyWorker = startHostDeregistrationPolicyWorker({
      storeFile: opts.enrollment.storeFile,
      retiredHostsPath: opts.policyWorker.retiredHostsPath,
      creds: opts.policyWrite.creds,
      target: opts.policyWrite.target,
      fetcher: opts.policyWrite.fetch ?? (fetch as unknown as Fetcher),
      relayNames: opts.relays.map((relay) => relay.name),
      renderer: async () => {
        const [source, head] = await Promise.all([
          fetchPolicySource(opts.policySource!, timeoutMs),
          currentRepoHead(),
        ]);
        if ("error" in head) throw new Error(`policy repository head is unavailable: ${head.error}`);
        return {
          headSha: source.head.sha,
          dirty: source.head.dirty,
          repositoryHead: head.sha,
          hosts: screenSiteOf(source).hosts.map((host) => host.id),
        };
      },
      relays: async () => (await pollRelays(opts.relays, timeoutMs)).map((result) => result.ok
        ? {
            name: result.name,
            ok: true,
            generation: result.view.generation,
            hosts: result.view.hosts.map((host) => host.host),
          }
        : { name: result.name, ok: false, generation: null, hosts: [], error: result.error }),
      propose: proposePolicyRetirement,
      now,
      actor: "policy-worker",
    }, opts.policyWorker.intervalMs, (error) => {
      log(`policy worker retry: ${error.message}`, `정책 worker 재시도: ${error.message}`);
    });
    server.once("close", stopPolicyWorker);
  }

  return { server };
}

/** Unreadable is not zero. The chrome treats a missing field as "no badge". */
function pendingCsrCount(storeFile: string | undefined): number | undefined {
  if (!storeFile) return undefined;
  try {
    return requireEnrollmentDocument(storeFile).requests.filter(
      (row) => row.status === "pending" || row.status === "conflict",
    ).length;
  } catch {
    return undefined;
  }
}

/**
 * The plan as an operator sees it. Identical to the stored one today, and separate anyway.
 *
 * The stored plan is about to grow fields that are the manager's business rather than the caller's,
 * and a projection means adding one cannot leak it by default. The read path made the same choice for
 * the same reason.
 *
 * `target` is one of those fields. It lives in `planTargets`, not on `Plan`, because a restart
 * drops the mapping — the same way it drops the bundle. Omitting it would make every VPC's
 * plans look the same on the approval screen.
 */
function publicPlan(p: Plan, target: string | null) {
  return {
    hash: p.hash,
    generation: p.generation,
    proposedBy: p.proposedBy,
    proposedAt: p.proposedAt,
    summary: p.summary,
    approval: p.approval,
    publishedAt: p.publishedAt,
    target,
  };
}

/**
 * What an approver reads instead of a fleet's worth of nftables text.
 *
 * Per host: stage, rule count, digest. Deliberately not the rules themselves — an approval screen that
 * requires reading six rendered rulesets is an approval screen nobody reads, and the digest is what
 * ties this summary to the bytes that will be published. An operator who wants the rules has the plan
 * hash and the policy repository, which is where a diff is actually legible.
 */
function summarise(b: PlanBundle): PlanSummary {
  return {
    hosts: Object.keys(b.manifest.hosts)
      .sort()
      .map((host) => {
        const e = b.manifest.hosts[host]!;
        return {
          host,
          stage: e.stage,
          // Counted from the rendered artifact rather than carried from the planner, so the number an
          // approver reads describes the bytes in this bundle and not a claim about them.
          ruleCount: countRules(b.rulesets[host]),
          rulesetHash: e.rulesetHash,
        };
      }),
  };
}

/**
 * How many rules a rendered artifact adds.
 *
 * The artifact is an **nftables JSON** command list, not nft text — `{"nftables":[{"add":{"rule":…}},…]}`.
 * A regex written for the text syntax matches nothing in it, which is how the first version of this
 * reported `0 rules` for a real generation: a summary an approver reads, saying confidently that the
 * plan changes nothing. Measured end to end against a live relay, which is the only reason it was
 * caught — every unit test asserted the count was above zero on fixtures shaped like nft text.
 *
 * Counted structurally, and forgiving of a parse failure: the count is a convenience for a human, and
 * refusing a whole proposal because a summary could not be computed would be the tail wagging the dog.
 * `null`-safe rather than throwing, for the same reason.
 *
 * ## This is deliberately not the publisher's `ruleCount`
 *
 * `renderHostRuleset` counts *policy* rules — `denies + allows + egress` — and excludes the baseline,
 * conntrack and loopback rules it also emits. So the same generation legitimately prints `0 rules` from
 * `heliopause-publish` and `3 rules` here, which measured as a live disagreement between two screens.
 *
 * The number an approver needs is this one: how many rules the kernel will hold if this is published.
 * A count that omits the baseline would describe a ruleset with nothing in it as empty when it still
 * permits SSH. Both labels now say which measure they are, because the failure to avoid is not either
 * number being wrong — it is someone comparing them.
 */
function countRules(artifact: string | undefined): number {
  if (!artifact) return 0;
  try {
    const doc = JSON.parse(artifact) as { nftables?: Array<Record<string, unknown>> };
    return (doc.nftables ?? []).filter((cmd) => {
      const add = (cmd as { add?: Record<string, unknown> }).add;
      return add !== undefined && "rule" in add;
    }).length;
  } catch {
    return 0;
  }
}

/**
 * Read a request body, bounded.
 *
 * A second copy of the relay's helper rather than an import, because the relay's is not exported and
 * exporting it would make the manager depend on the relay module for a five-line utility. The bound is
 * the part that matters and it is stated here.
 */
async function readBody(req: IncomingMessage, limit = 256 * 1024): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    // Bounded before buffering, not after — otherwise the limit is enforced by the OOM killer.
    if (size > limit) throw new Error("request body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Was this POST caused by another site?
 *
 * One copy, two callers — the operator path and the app-token path. A second inline copy is how the
 * two would come to disagree, and the one that would be left behind is the newer one.
 *
 * `Origin: null` is an opaque browser origin (a sandboxed iframe, for example), not the CLI. The CLI
 * sends no `Origin` header at all, so refusing the literal value closes that browser path without
 * changing the command line API. `Sec-Fetch-Site` is checked too because page script cannot forge
 * it, while `Origin` is absent on some navigations.
 */
function crossSiteRequest(req: IncomingMessage): boolean {
  const origin = req.headers["origin"];
  const site = req.headers["sec-fetch-site"];
  const foreignOrigin = typeof origin === "string" && origin !== `https://${req.headers["host"] ?? ""}`;
  const foreignSite = typeof site === "string" && site !== "same-origin" && site !== "none";
  return foreignOrigin || foreignSite;
}

/**
 * The `?status=` and `?hostname=` filter on the CSR queue, parsed once for both principals.
 *
 * One function because there are two callers — an operator with a certificate or a session, and an
 * app token carrying `enrollment:requests-read` — and a filter that means two things depending on
 * who asked is a filter nobody can reason about. `normalizeEnrollmentHostname` throws a 400 for a
 * malformed name, which is the right answer: an unmatchable filter that silently returns an empty
 * list reads as "there are no CSRs", and that is the sentence somebody acts on.
 */
function csrQueryFilter(url: URL): { status: string | null; hostname: string | null } {
  // `?status=` with an empty value means "no filter", not "filter by nothing". That has been this
  // route's behaviour since it was written, `heliopause-enrollment` reaches it by building a query
  // string from possibly-absent flags, and a 400 for a parameter somebody left blank is a
  // regression dressed as strictness. A *non-empty* unknown value is still refused: that is a
  // caller who believes in a status this store does not have.
  const status = url.searchParams.get("status") || null;
  if (status && !["pending", "conflict", "rejected", "signed"].includes(status)) {
    throw new EnrollmentError("invalid status");
  }
  const hostname = url.searchParams.get("hostname") || null;
  return { status, hostname: hostname === null ? null : normalizeEnrollmentHostname(hostname) };
}

const matchesCsrFilter = (row: NodeCsrRecord, filter: { status: string | null; hostname: string | null }): boolean =>
  (!filter.status || row.status === filter.status) && (!filter.hostname || row.hostname === filter.hostname);

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    ...headers,
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    // The static console has carried this since it grew security headers; the API answers did not,
    // and several of them reflect caller input — a host name, a plan hash, a Service reference —
    // back inside an error string. Nothing here is served as a document, so declaring that the
    // declared type is the only one costs nothing and removes a class of surprise.
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
}

function sendEnrollmentError(res: ServerResponse, error: unknown): void {
  if (error instanceof EnrollmentError) return send(res, error.statusCode, { error: error.message });
  if (error instanceof SyntaxError) return send(res, 400, { error: "request body must be valid JSON" });
  throw error;
}
