// The manager's API, as a client. Shared by every CLI that talks to it.
//
// One implementation on purpose. The design requires each write endpoint to ship with its caller
// (docs/인터페이스-설계.md), and the reason it gives is V46: the manager served an unusable certificate
// for five hours while reporting `Ready`, because nothing called the failing direction. A second copy
// of the client would reintroduce the same class of problem one level down — two ways of presenting a
// certificate, one of them exercised.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { request } from "node:https";
import { rootCertificates } from "node:tls";
import { readBoundedNodeBody } from "./bounded-body.ts";

/**
 * How much of the manager's answer a CLI will hold.
 *
 * The largest legitimate one is `/plans/<hash>/ruleset` — a whole host's rendered ruleset — and
 * `/plans/<hash>/changes`, which carries GitHub's unified diff. `MAX_PLAN_BYTES` on the manager is
 * 8 MB for a fleet's worth of rulesets; twice that here, because refusing a legitimate answer would
 * break the approval path and this is a short-lived process on a workstation.
 */
export const MAX_MANAGER_RESPONSE_BYTES = 16 * 1024 * 1024;

export interface Creds {
  cert: Buffer;
  key: Buffer;
  ca: Buffer;
  /** The CN the manager will see. Printed by callers, so an operator can tell who they just acted as. */
  name: string;
}

/**
 * Pick an operator certificate out of a PKI directory.
 *
 * Refuses to guess when there is more than one and no name was given. On a workstation holding both a
 * human's certificate and a service's, guessing means acting as whichever sorts first — and for the
 * write path that is an audit trail naming the wrong person for a firewall change.
 */
export function operatorCreds(pkiDir: string, wanted?: string): Creds {
  const ca = join(pkiDir, "ca.pem");
  if (!existsSync(ca)) {
    throw new Error(
      `no ca.pem in ${pkiDir}. Point --pki at the directory heliopause-pki wrote, or issue a CA ` +
        `with \`heliopause-pki init\`.`,
    );
  }
  const found = readdirSync(pkiDir)
    .filter((f) => f.startsWith("operator-") && f.endsWith(".pem"))
    .map((f) => f.slice("operator-".length, -".pem".length));
  const name = wanted ?? found[0];
  if (!name) {
    throw new Error(
      `no operator certificate in ${pkiDir}. Issue one with:\n` +
        `  heliopause-pki issue ${pkiDir} <your-name> --role=operator\n` +
        `then add its CN to the manager's HELIOPAUSE_OPERATOR_CNS and HELIOPAUSE_WRITER_CNS.`,
    );
  }
  if (!wanted && found.length > 1) {
    throw new Error(`several operator certificates in ${pkiDir} (${found.join(", ")}) — pass --operator=NAME`);
  }
  const base = join(pkiDir, `operator-${name}`);
  if (!existsSync(`${base}.pem`)) throw new Error(`no operator certificate named ${name} in ${pkiDir}`);
  return {
    cert: readFileSync(`${base}.pem`),
    key: readFileSync(`${base}.key`),
    ca: readFileSync(ca),
    name,
  };
}

/** An error carrying the status, so a caller can distinguish "not authorised" from "not approved". */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/**
 * Path the HTTPS request actually sends.
 *
 * `url.pathname` alone drops the query. Lookup and where-used carry the question there; a proxy
 * that asks without it answers a different question and looks like an empty policy.
 */
export function requestPath(url: URL): string {
  return `${url.pathname}${url.search}`;
}

/**
 * One call to the manager.
 *
 * Non-200 becomes an `ApiError` carrying the server's own message. That message is the useful part:
 * the manager distinguishes "you proposed this and cannot approve it" from "this plan expired" from
 * "your certificate may read but not write", and collapsing those into "request failed" would send an
 * operator to look at the wrong thing.
 */
export async function api<T>(
  managerUrl: string,
  path: string,
  method: "GET" | "POST",
  body: unknown,
  creds: Creds,
  timeoutMs = 60_000,
): Promise<T> {
  const url = new URL(path, managerUrl);
  const payload = body === undefined ? null : JSON.stringify(body);
  return new Promise((settleOk, settleFail) => {
    // ## `timeout` is inactivity, so there is a deadline as well
    //
    // `request({ timeout })` is `socket.setTimeout`: every byte resets it. A manager that answers
    // one byte at a time stays inside it forever, and this is the client behind `heliopause-approve`
    // and `heliopause-publish` — the write path. The hang is on *reading the answer*, so a deadline
    // does not tell an operator whether the plan landed; it turns a terminal that never returns into
    // an error they can act on, which is the difference that matters at 3 a.m.
    //
    // Armed before the request so DNS and the TLS handshake are inside it, and cleared on every exit
    // rather than `unref`'d: an unref'd timer still fires, and firing after a successful call would
    // destroy a socket the agent may have handed to the next one.
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const clear = () => { if (deadline !== undefined) clearTimeout(deadline); deadline = undefined; };
    const ok = (v: T) => { clear(); settleOk(v); };
    const fail = (e: unknown) => { clear(); settleFail(e); };

    const req = request(
      {
        hostname: url.hostname,
        port: url.port,
        path: requestPath(url),
        method,
        cert: creds.cert,
        key: creds.key,
        // Supplying `ca` replaces Node's default roots. The operator CA is needed when a manager
        // serves its private certificate, while the standalone public endpoint serves a Web PKI
        // certificate. Trust both instead of making those two supported deployments exclusive.
        ca: [...rootCertificates, creds.ca],
        timeout: timeoutMs,
        ...(payload !== null
          ? { headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } }
          : {}),
      },
      (res) => {
        // Bounded while reading. The manager is trusted to *decide* things and is still on the other
        // side of a socket: a `/plans/<hash>/ruleset` answer carries a whole rendered ruleset and a
        // `/changes` answer carries GitHub's diff, so this is generous — but a CLI that allocates
        // whatever it is sent is one an unhealthy manager can take down.
        readBoundedNodeBody(res, MAX_MANAGER_RESPONSE_BYTES, `manager ${url.host}`).then(
          (buffer) => {
            const text = buffer.toString("utf8");
            if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
              let message = text;
              try {
                message = (JSON.parse(text) as { error?: string }).error ?? text;
              } catch {
                // Not JSON. The raw body is still the best thing to show — it may be a proxy's error page,
                // and saying so beats reporting a parse failure the operator cannot act on.
              }
              return fail(new ApiError(message, res.statusCode ?? 0));
            }
            try {
              ok(JSON.parse(text) as T);
            } catch (e) {
              fail(new ApiError(`manager returned unparseable JSON: ${(e as Error).message}`, 0));
            }
          },
          (e: Error) => fail(new ApiError(e.message, 0)),
        );
      },
    );
    // Inactivity. Kept beside the deadline because the two catch different things — a manager that
    // has gone quiet, and one that is answering too slowly to ever finish.
    req.on("timeout", () => req.destroy(new Error(`no answer from ${managerUrl} within ${timeoutMs}ms`)));
    deadline = setTimeout(() => {
      req.destroy(new Error(`${managerUrl} did not finish answering within ${timeoutMs}ms`));
    }, timeoutMs);
    req.on("error", (e) => fail(new ApiError(`cannot reach ${managerUrl}: ${e.message}`, 0)));
    if (payload !== null) req.write(payload);
    req.end();
  });
}

/** What `POST /plan` and `POST /approve` answer with. */
export interface PlanView {
  hash: string;
  generation: string;
  proposedBy: string;
  proposedAt: string;
  summary: { hosts: Array<{ host: string; stage: string; ruleCount: number; rulesetHash: string }> };
  approval: { by: string; at: string } | null;
  publishedAt: string | null;
  /** VPC this plan was proposed for. Absent on older managers. */
  target?: string | null;
}

/** Print a plan the way both callers want it. */
export function printPlan(p: PlanView): void {
  console.log(`plan       ${p.hash}`);
  if (p.target) console.log(`target     ${p.target}`);
  console.log(`generation ${p.generation}`);
  console.log(`proposed   ${p.proposedBy} at ${p.proposedAt}`);
  console.log(
    p.approval
      ? `approved   ${p.approval.by} at ${p.approval.at}`
      // `--approve` is part of the command, not an optional extra. Without it the CLI lists pending
      // plans — which prints this same line again, so following the instruction verbatim produces
      // output that looks like the approval was attempted and refused. Measured 2026-08-15: an
      // operator ran exactly this, read "not yet", and had approved nothing.
      : `approved   — not yet. A different operator must run: heliopause-approve <url> ${p.hash} --approve`,
  );
  for (const h of p.summary.hosts) {
    // "total rules", against `heliopause-publish`'s "policy rules". Different measures of the same
    // generation — this one includes the baseline and conntrack rules — and both labels say which so
    // nobody reads the difference as a discrepancy.
    console.log(`  ${h.host.padEnd(20)} ${h.stage.padEnd(8)} ${String(h.ruleCount).padStart(4)} total rules  ${h.rulesetHash.slice(0, 20)}`);
  }
}
