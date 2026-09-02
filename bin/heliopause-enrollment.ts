#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  createAppToken, createNodeToken, initializeEnrollmentDocument, normalizeEnrollmentHostname,
  reopenRetiredHostname, requireEnrollmentDocument, rejectNodeCsr,
  revokeAppToken, revokeNodeToken, storeNodeCertificate, type CsrStatus,
  revokeCertificate,
  withEnrollmentTransaction,
} from "../src/enrollment-store.ts";

import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();
const args = process.argv.slice(2);
const positional = args.filter((arg) => !arg.startsWith("--"));
const flags = new Map(args.filter((arg) => arg.startsWith("--")).map((arg) => {
  const [key, ...value] = arg.slice(2).split("="); return [key!, value.length ? value.join("=") : "true"];
}));
const [command, store, subject] = positional;
const usage = `usage:
  heliopause-enrollment init <store.json>
  heliopause-enrollment token-create <store.json> <hostname> [--label=TEXT] [--actor=NAME] [--ttl-sec=SECONDS] [--keep-existing]
  heliopause-enrollment token-list <store.json> [--json]
  heliopause-enrollment token-revoke <store.json> <token-id> [--actor=NAME]
  heliopause-enrollment app-token-create <store.json> --label=TEXT --scopes=A,B --hostname-pattern=PATTERN [--ttl-sec=SECONDS] [--actor=NAME]
  heliopause-enrollment app-token-list <store.json> [--json]
  heliopause-enrollment app-token-revoke <store.json> <app-token-id> [--actor=NAME]
  heliopause-enrollment csr-list <store.json> [--status=pending|conflict|rejected|signed] [--hostname=NAME] [--json]
  heliopause-enrollment csr-show <store.json> <request-id> [--json]
  heliopause-enrollment csr-export <store.json> <request-id> --out=FILE
  heliopause-enrollment csr-reject <store.json> <request-id> --reason=TEXT [--actor=NAME]
  heliopause-enrollment cert-upload <store.json> <request-id> --cert=FILE --ca=FILE --ca-name=NAME [--actor=NAME]
  heliopause-enrollment audit <store.json> [--json]
  heliopause-enrollment cert-revoke <store.json> --cert=FILE --reason=TEXT [--actor=NAME]
  heliopause-enrollment revocation-list <store.json> [--json]
  heliopause-enrollment host-reopen <store.json> <hostname> --operation=ID --reason=TEXT [--actor=NAME]

Use an https manager URL instead of <store.json> for remote operation, with
--pki=DIR [--operator=NAME] [--otp=CODE]. Remote cert-upload needs --cert and --ca-name; the
manager reads the trusted CA from HELIOPAUSE_ENROLLMENT_TRUSTED_CAS.

App token scopes: enrollment:token-create, enrollment:requests-read. A hostname pattern is an exact
hostname or one leading wildcard label, quoted so the shell does not expand it: --hostname-pattern='*.dev'`;

const requiredFlag = (name: string): string => { const value = flags.get(name); if (!value || value === "true") throw new Error(`--${name}=VALUE is required`); return value; };
const actor = (): string => flags.get("actor")?.trim().slice(0, 120) || "operator";
const persist = <T>(fn: (document: ReturnType<typeof requireEnrollmentDocument>) => T): T =>
  withEnrollmentTransaction(store!, fn);
const publicToken = (row: ReturnType<typeof requireEnrollmentDocument>["tokens"][number]) => ({
  id: row.id, hostname: row.hostname, label: row.label, createdBy: row.createdBy,
  createdAt: row.createdAt, expiresAt: row.expiresAt, lastUsedAt: row.lastUsedAt, revokedAt: row.revokedAt,
});
const publicAppToken = ({ tokenHash: _secret, ...row }: ReturnType<typeof requireEnrollmentDocument>["appTokens"][number]) => row;
/** Split once, here, so the store sees the same list whether it was typed locally or posted. */
const scopeList = (): string[] => requiredFlag("scopes").split(",").map((scope) => scope.trim()).filter(Boolean);
/**
 * Say what was opened, what stays shut, and the half this command cannot do.
 *
 * The second half is not a footnote. `policy/retired-hosts.json` is an independent hold —
 * `withoutRetiredHosts` drops a retired id from the rendered host set — so a hostname reopened here
 * and left listed there enrols cleanly and then receives **no ruleset**. A host that reads as
 * configured and has no firewall is a worse outcome than the 409 this command exists to clear, so
 * the follow-up is printed every time rather than left to the runbook.
 */
const reportReopen = (
  changed: boolean,
  operation: { hostname: string; hostLifecycleId: string; externalOperationId: string },
): void => {
  console.log(`${changed ? "reopened" : "already reopened"} ${operation.hostname} (deregistration ${operation.externalOperationId})`);
  console.log(`  lifecycle ${operation.hostLifecycleId} stays deregistered — reuse needs a new lifecycle id`);
  console.log("  next: remove this hostname from policy/retired-hosts.json by reviewed pull request,");
  console.log("        or it will enrol and render no ruleset at all");
};

async function remote(): Promise<void> {
  const { api, operatorCreds } = await import("../src/api-client.ts");
  const creds = operatorCreds(resolve(flags.get("pki") ?? "./pki"), flags.get("operator"));
  const call = <T>(path: string, method: "GET" | "POST", body?: unknown) => api<T>(store!, path, method, body, creds);
  const otp = flags.get("otp");
  if (command === "token-list") {
    const answer = await call<{ tokens: unknown[] }>("/enrollment/tokens", "GET"); console.log(JSON.stringify(answer, null, 2));
  } else if (command === "token-create") {
    if (!subject) throw new Error(usage); const ttlRaw = flags.get("ttl-sec");
    const answer = await call<{ token: string; row: { id: string; hostname: string } }>("/enrollment/tokens", "POST", {
      hostname: subject, label: flags.get("label"), revokeExisting: !flags.has("keep-existing"),
      ...(ttlRaw ? { ttlSec: Number(ttlRaw) } : {}), otp,
    });
    console.log(`created node token ${answer.row.id} for ${answer.row.hostname}`); console.log(answer.token); console.log("  plaintext is shown once");
  } else if (command === "token-revoke") {
    if (!subject) throw new Error(usage); await call(`/enrollment/tokens/${encodeURIComponent(subject)}/revoke`, "POST", { otp }); console.log(`revoked ${subject}`);
  } else if (command === "app-token-list") {
    console.log(JSON.stringify(await call("/enrollment/app-tokens", "GET"), null, 2));
  } else if (command === "app-token-create") {
    const ttlRaw = flags.get("ttl-sec");
    const answer = await call<{ token: string; row: { id: string; label: string; hostnamePattern: string } }>("/enrollment/app-tokens", "POST", {
      label: requiredFlag("label"), scopes: scopeList(), hostnamePattern: requiredFlag("hostname-pattern"),
      ...(ttlRaw ? { ttlSec: Number(ttlRaw) } : {}), otp,
    });
    console.log(`created app token ${answer.row.id} (${answer.row.label}) for ${answer.row.hostnamePattern}`);
    console.log(answer.token); console.log("  plaintext is shown once");
  } else if (command === "app-token-revoke") {
    if (!subject) throw new Error(usage); await call(`/enrollment/app-tokens/${encodeURIComponent(subject)}/revoke`, "POST", { otp }); console.log(`revoked ${subject}`);
  } else if (command === "csr-list" || command === "csr-show" || command === "csr-export") {
    // Filtered by the manager rather than here: the same two parameters mean the same thing to every
    // caller of that route, and a client that filtered locally would quietly diverge from it.
    const query = new URLSearchParams();
    if (flags.get("status")) query.set("status", flags.get("status")!);
    if (flags.get("hostname")) query.set("hostname", flags.get("hostname")!);
    const answer = await call<{ requests: Array<Record<string, unknown> & { id: string; csrPem: string }> }>(`/enrollment/requests${query.size ? `?${query}` : ""}`, "GET");
    const rows = subject ? answer.requests.filter((row) => row.id === subject) : answer.requests;
    if (subject && rows.length === 0) throw new Error(`CSR ${subject} not found`);
    if (command === "csr-export") { const out = requiredFlag("out"); if (existsSync(out)) throw new Error(`refusing to overwrite ${out}`); writeFileSync(out, rows[0]!.csrPem, { mode: 0o644, flag: "wx" }); console.log(`exported ${subject} to ${out}`); }
    else console.log(JSON.stringify({ requests: rows }, null, 2));
  } else if (command === "csr-reject") {
    if (!subject) throw new Error(usage); await call(`/enrollment/requests/${encodeURIComponent(subject)}/reject`, "POST", { reason: requiredFlag("reason"), otp }); console.log(`rejected ${subject}`);
  } else if (command === "cert-upload") {
    if (!subject) throw new Error(usage); await call(`/enrollment/requests/${encodeURIComponent(subject)}/certificate`, "POST", { certificatePem: readFileSync(requiredFlag("cert"), "utf8"), caName: requiredFlag("ca-name"), otp }); console.log(`uploaded certificate for ${subject}`);
  } else if (command === "audit") {
    console.log(JSON.stringify(await call("/enrollment/audit", "GET"), null, 2));
  } else if (command === "cert-revoke") {
    const answer = await call<{ revocation: { fingerprint256: string } }>("/enrollment/revocations", "POST", { certificatePem: readFileSync(requiredFlag("cert"), "utf8"), reason: requiredFlag("reason"), otp });
    console.log(`revoked certificate sha256:${answer.revocation.fingerprint256}`);
  } else if (command === "host-reopen") {
    if (!subject) throw new Error(usage);
    const answer = await call<{ reopened: boolean; operation: { hostname: string; hostLifecycleId: string; externalOperationId: string } }>(
      `/enrollment/host-deregistrations/${encodeURIComponent(subject)}/${encodeURIComponent(requiredFlag("operation"))}/reopen`,
      "POST", { reason: requiredFlag("reason"), otp },
    );
    reportReopen(answer.reopened, answer.operation);
  } else if (command === "revocation-list") {
    console.log(JSON.stringify(await call("/enrollment/revocations", "GET"), null, 2));
  } else throw new Error(usage);
}

try {
  if (!command || !store || args.includes("--help")) throw new Error(usage);
  if (store.startsWith("https://")) {
    await remote();
  } else if (command === "init") {
    initializeEnrollmentDocument(store); console.log(`created ${store}`);
  } else if (command === "token-create") {
    if (!subject) throw new Error(usage);
    const ttlRaw = flags.get("ttl-sec");
    const result = persist((document) => createNodeToken(document, { hostname: subject, label: flags.get("label"), createdBy: actor(),
      revokeExisting: !flags.has("keep-existing"), ...(ttlRaw ? { ttlSec: Number(ttlRaw) } : {}) }));
    console.log(`created node token ${result.row.id} for ${result.row.hostname}`);
    console.log(result.token); console.log("  plaintext is shown once; the store contains only its SHA-256 hash");
  } else if (command === "token-list") {
    const rows = requireEnrollmentDocument(store).tokens.map(publicToken);
    if (flags.has("json")) console.log(JSON.stringify({ tokens: rows }, null, 2));
    else rows.forEach((row) => console.log(`${row.id}\t${row.revokedAt ? "revoked" : "active"}\t${row.hostname}\t${row.lastUsedAt ?? "never used"}\t${row.label ?? ""}`));
  } else if (command === "token-revoke") {
    if (!subject) throw new Error(usage); const row = persist((document) => revokeNodeToken(document, subject, actor())); console.log(`revoked ${row.id} for ${row.hostname}`);
  } else if (command === "app-token-create") {
    const ttlRaw = flags.get("ttl-sec");
    const result = persist((document) => createAppToken(document, {
      label: requiredFlag("label"), scopes: scopeList(), hostnamePattern: requiredFlag("hostname-pattern"),
      createdBy: actor(), ...(ttlRaw ? { ttlSec: Number(ttlRaw) } : {}),
    }));
    console.log(`created app token ${result.row.id} (${result.row.label}) for ${result.row.hostnamePattern}`);
    console.log(`  scopes ${result.row.scopes.join(",")}`);
    console.log(result.token); console.log("  plaintext is shown once; the store contains only its SHA-256 hash");
  } else if (command === "app-token-list") {
    const rows = requireEnrollmentDocument(store).appTokens.map(publicAppToken);
    if (flags.has("json")) console.log(JSON.stringify({ tokens: rows }, null, 2));
    else rows.forEach((row) => console.log(`${row.id}\t${row.revokedAt ? "revoked" : "active"}\t${row.hostnamePattern}\t${row.scopes.join(",")}\t${row.lastUsedAt ?? "never used"}\t${row.label}`));
  } else if (command === "app-token-revoke") {
    if (!subject) throw new Error(usage); const row = persist((document) => revokeAppToken(document, subject, actor())); console.log(`revoked ${row.id} (${row.label})`);
  } else if (command === "csr-list") {
    const status = flags.get("status") as CsrStatus | undefined;
    if (status && !["pending", "conflict", "rejected", "signed"].includes(status)) throw new Error("invalid --status");
    // Normalised through the store's own function, so `--hostname=K3S-01.DEV` matches locally exactly
    // as it does over the API, and a malformed name is refused rather than matching nothing.
    const host = flags.get("hostname") ? normalizeEnrollmentHostname(flags.get("hostname")!) : undefined;
    const rows = requireEnrollmentDocument(store).requests
      .filter((row) => (!status || row.status === status) && (!host || row.hostname === host));
    if (flags.has("json")) console.log(JSON.stringify({ requests: rows }, null, 2));
    else rows.forEach((row) => console.log(`${row.id}\t${row.status}\t${row.hostname}\t${row.csrSha256}\t${row.createdAt}`));
  } else if (command === "csr-show") {
    if (!subject) throw new Error(usage); const row = requireEnrollmentDocument(store).requests.find((request) => request.id === subject); if (!row) throw new Error(`CSR ${subject} not found`);
    if (flags.has("json")) console.log(JSON.stringify(row, null, 2));
    else console.log(`${row.id}\n  host       ${row.hostname}\n  status     ${row.status}\n  csr sha    ${row.csrSha256}\n  public key ${row.publicKeySha256}\n  token      ${row.nodeTokenId}\n  source     ${row.sourceIp ?? "not reported"}\n  created    ${row.createdAt}\n  decided    ${row.decidedAt ?? "pending"} ${row.decidedBy ?? ""}\n  reason     ${row.decisionReason ?? ""}`);
  } else if (command === "csr-export") {
    if (!subject) throw new Error(usage); const out = requiredFlag("out"); if (existsSync(out)) throw new Error(`refusing to overwrite ${out}`);
    const row = requireEnrollmentDocument(store).requests.find((request) => request.id === subject); if (!row) throw new Error(`CSR ${subject} not found`);
    writeFileSync(out, row.csrPem, { mode: 0o644, flag: "wx" }); console.log(`exported ${subject} to ${out}`); console.log(`  sha256 ${row.csrSha256}`);
  } else if (command === "csr-reject") {
    if (!subject) throw new Error(usage); const row = persist((document) => rejectNodeCsr(document, subject, actor(), requiredFlag("reason"))); console.log(`rejected ${row.id} for ${row.hostname}`);
  } else if (command === "cert-upload") {
    if (!subject) throw new Error(usage);
    const row = persist((document) => storeNodeCertificate(document, { requestId: subject,
      certificatePem: readFileSync(requiredFlag("cert"), "utf8"), caPem: readFileSync(requiredFlag("ca"), "utf8"),
      caName: requiredFlag("ca-name"), actor: actor() }));
    console.log(`uploaded certificate for ${row.hostname}`); console.log(`  request ${row.id}\n  sha256  ${row.certificateSha256}\n  expires ${row.certificateNotAfter}`);
  } else if (command === "audit") {
    const rows = requireEnrollmentDocument(store).audit;
    if (flags.has("json")) console.log(JSON.stringify({ events: rows }, null, 2));
    else rows.forEach((row) => console.log(`${row.at}\t${row.actor}\t${row.action}\t${row.target}\t${JSON.stringify(row.detail)}`));
  } else if (command === "cert-revoke") {
    const row = persist((document) => revokeCertificate(document, { certificatePem: readFileSync(requiredFlag("cert"), "utf8"), reason: requiredFlag("reason"), actor: actor() }));
    console.log(`revoked certificate sha256:${row.fingerprint256}`);
  } else if (command === "host-reopen") {
    if (!subject) throw new Error(usage);
    const result = persist((document) => reopenRetiredHostname(document, {
      hostname: subject, externalOperationId: requiredFlag("operation"),
      reason: requiredFlag("reason"), actor: actor(),
    }));
    reportReopen(result.changed, result.row);
  } else if (command === "revocation-list") {
    const rows = requireEnrollmentDocument(store).revocations;
    if (flags.has("json")) console.log(JSON.stringify({ revocations: rows }, null, 2));
    else rows.forEach((row) => console.log(`${row.fingerprint256}\t${row.revokedAt}\t${row.subject ?? ""}\t${row.reason}`));
  } else throw new Error(usage);
} catch (e) {
  console.error((e as Error).message); process.exitCode = 2;
}
