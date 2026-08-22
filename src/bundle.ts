// The unit that gets proposed, approved and published: a manifest plus every host artifact it names.
//
// ## Why a bundle rather than a request the server renders
//
// The obvious shape for `POST /plan` is "the manager renders from policy". It cannot, and the reason
// is a deliberate constraint rather than an oversight: the policy repository is private and is never
// baked into the manager's image, because that image runs in the cluster the policy governs. A
// manager that could render would have to hold the whole site's policy in the most exposed place it
// could be.
//
// So the operator's CLI renders — it already does, it is where the policy is — and submits the
// result. The manager's job is the part that cannot be done on a workstation: remembering who
// proposed what, requiring a second person, and being the only thing that can hand the result to
// every relay.
//
// ## Why the server recomputes the hash
//
// A bundle arrives with no hash at all. The server computes one from the bytes it received and uses
// that — a submitted hash would be a claim by the proposer about content the approver never sees,
// which is exactly the check that decision 4 says must not be decorative:
//
//   "요청에 '승인됨' 플래그를 받지 않는다. 승인은 서버가 기억하는 사실이어야 하고, 요청자가
//    주장하는 값이면 승인 검사는 장식이다."
//
// The same reasoning applies one level down. If the server trusted a claimed digest, an approver
// could read a summary of bundle A while bundle B was stored under A's hash.
//
// ## Why the serialisation is canonical and explicit
//
// `JSON.stringify` of an object depends on key insertion order, so two byte-identical publishes could
// hash differently depending on how the object was built. The hash decides whether an approval
// applies, so it hashes a defined byte sequence — sorted host names, length-prefixed fields — rather
// than whatever the serialiser happened to emit.

import { createHash } from "node:crypto";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Manifest } from "./protocol.ts";
import type { PublishPlan } from "./publish.ts";

/** Everything a relay needs in order to serve a generation. */
export interface PlanBundle {
  manifest: Manifest;
  /** Host id → rendered ruleset text, exactly as `writePublish` would write it. */
  rulesets: Record<string, string>;
  /**
   * Applier host id → Cilium document text. Empty when the generation has no workload half.
   *
   * Kept separate from `rulesets` rather than merged under a suffixed key, so a relay writing the
   * bundle cannot be talked into writing a `.nft` file from a workload entry or the reverse.
   */
  workload: Record<string, string>;
}

/** Build a bundle from a plan the renderer produced. */
export function bundleFromPlan(plan: PublishPlan): PlanBundle {
  const rulesets: Record<string, string> = {};
  for (const a of plan.artifacts) rulesets[a.host] = a.json;
  const workload: Record<string, string> = {};
  if (plan.workload) workload[plan.workload.applier] = plan.workload.json;
  return { manifest: plan.manifest, rulesets, workload };
}

/**
 * Content address of a bundle: `sha256:…`.
 *
 * Covers everything that will be written, including `manifest.issuedAt`. That makes two renderings of
 * identical policy hash differently, which is intended — each rendering is its own plan, and a plan
 * carries the timestamp a relay will serve. Collapsing them would let an approval for one rendering
 * apply to another that says it was issued at a different time.
 */
export function bundleHash(b: PlanBundle): string {
  const h = createHash("sha256");
  // A version tag, so this digest cannot silently change meaning if the encoding is ever revised.
  // Without it, a future change would produce hashes that look like old ones and are not comparable.
  feed(h, "heliopause-bundle-v1");
  feed(h, canonicalManifest(b.manifest));
  for (const [kind, map] of [["ruleset", b.rulesets], ["workload", b.workload]] as const) {
    feed(h, kind);
    // Sorted, so the digest does not depend on object construction order.
    for (const host of Object.keys(map).sort()) {
      feed(h, host);
      feed(h, map[host]!);
    }
  }
  return "sha256:" + h.digest("hex");
}

/**
 * Identity of a *plan*: this bundle, for this VPC.
 *
 * ## Why the target is inside the hash and not beside it
 *
 * A bundle is rendered for one VPC — the relays are per-VPC and each has its own CA, so "publish this"
 * is always "publish this there". If the target lived outside the content address, the same bundle
 * proposed for `dev` and for `prod` would share one hash, and proposing is idempotent: the second
 * proposal would silently return the first plan, and publishing it would push to the wrong VPC while
 * reporting success. The two are different plans and must have different names.
 *
 * The publish request still names only the hash. The target is a fact the server stored when the plan
 * was proposed, which is the same rule the approval follows: nothing that decides where a firewall
 * change lands is re-supplied by the caller who wants it to land.
 */
export function planHash(target: string, bundle: PlanBundle): string {
  const h = createHash("sha256");
  feed(h, "heliopause-plan-v1");
  feed(h, target);
  feed(h, bundleHash(bundle));
  return "sha256:" + h.digest("hex");
}

/**
 * Length-prefixed feed.
 *
 * Concatenating fields directly would make `{a:"x", b:"y"}` and `{a:"xy", b:""}` hash identically —
 * and here those are a host name and a ruleset, so the ambiguity is between two different firewalls.
 */
function feed(h: ReturnType<typeof createHash>, s: string): void {
  const buf = Buffer.from(s, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length);
  h.update(len);
  h.update(buf);
}

/** The manifest with object keys sorted at every level, so its serialisation is a function of its content. */
function canonicalManifest(m: Manifest): string {
  return JSON.stringify(sortKeys(m));
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sortKeys((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

/**
 * Write a bundle into an artifact directory.
 *
 * **Artifacts land before the manifest, and the manifest lands atomically.** The relay polls this
 * directory on a timer and has no idea a write is in progress; if the manifest appeared first, an agent
 * could be handed a generation whose ruleset file did not exist yet, and if the manifest were written
 * in place a poll could read it half-finished. Writing the files first and renaming the manifest over
 * makes the manifest's appearance the single moment the generation exists.
 *
 * This is the one implementation of that ordering. `writePublish` delegates here rather than keeping a
 * second copy, because two of them would be two things to get right and the failure — a torn manifest
 * read by a relay — is invisible until an agent fetches at the wrong instant.
 *
 * Files belonging to hosts no longer in the manifest are left in place rather than deleted. They are
 * unreachable: the relay serves `hosts/<cn>.nft` only for a host its manifest names, so a leftover is
 * dead weight rather than a stale generation. Deleting them would mean this function computes what to
 * remove from a directory listing, and a bug in *that* deletes a live host's ruleset.
 */
export async function writeBundle(dir: string, b: PlanBundle): Promise<void> {
  const hostsDir = join(dir, "hosts");
  await mkdir(hostsDir, { recursive: true });

  for (const [host, text] of Object.entries(b.rulesets)) {
    await writeFile(join(hostsDir, `${host}.nft`), text, "utf8");
  }
  // Before the manifest, like the rulesets, and for the same reason. A workload document that landed
  // after it could be fetched by an applier that had already been told the generation was ready.
  for (const [host, text] of Object.entries(b.workload)) {
    await writeFile(join(hostsDir, `${host}.cnp.json`), text, "utf8");
  }

  const tmp = join(dir, "manifest.json.tmp");
  await writeFile(tmp, JSON.stringify(b.manifest, null, 2) + "\n", "utf8");
  try {
    await rename(tmp, join(dir, "manifest.json"));
  } catch (e) {
    await rm(tmp, { force: true });
    throw e;
  }
}

export class BundleError extends Error {}

/**
 * Check a bundle received over the wire is internally consistent, before anything is stored or written.
 *
 * This is the boundary between "some JSON arrived" and "this describes a generation", and it is the
 * only place that check exists — the relay writes files from it and the manager stores it for
 * approval, and neither re-derives it. So it is strict about the three things that would otherwise
 * become a silently broken generation:
 *
 *   · A host in the manifest with no ruleset — the agent fetches and gets a 404 mid-rollout, on a
 *     generation the manifest says is ready.
 *   · A ruleset for a host the manifest does not name — a file written that nothing will fetch, and a
 *     path controlled by the submitter rather than by the manifest.
 *   · A digest disagreeing with the bytes — the agent's own `rulesetHash` check would catch this and
 *     revert, so accepting it means publishing a generation guaranteed to fail at every host.
 */
export function validateBundle(b: unknown): PlanBundle {
  if (!b || typeof b !== "object") throw new BundleError("bundle is not an object");
  const { manifest, rulesets, workload } = b as Partial<PlanBundle>;
  if (!manifest || typeof manifest !== "object") throw new BundleError("bundle has no manifest");
  if (!manifest.generation) throw new BundleError("manifest has no generation id");
  if (!manifest.hosts || typeof manifest.hosts !== "object") {
    throw new BundleError("manifest has no hosts");
  }
  if (!rulesets || typeof rulesets !== "object") throw new BundleError("bundle has no rulesets");
  const work = workload ?? {};

  const named = Object.keys(manifest.hosts).sort();
  const carried = Object.keys(rulesets).sort();
  for (const host of named) {
    // The same check the relay applies before serving, applied again before writing. The name reaches
    // a path join on the relay, and this bundle crossed a network to get there.
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(host)) {
      throw new BundleError(`manifest names a suspicious host ${JSON.stringify(host)}`);
    }
    if (typeof rulesets[host] !== "string") {
      throw new BundleError(`manifest names ${host} but the bundle carries no ruleset for it`);
    }
    const want = manifest.hosts[host]!.rulesetHash;
    const got = "sha256:" + createHash("sha256").update(rulesets[host]!).digest("hex");
    if (want !== got) {
      throw new BundleError(
        `${host}: manifest says ${want} but the carried ruleset hashes to ${got} — every agent ` +
          `would refuse this artifact and revert`,
      );
    }
  }
  for (const host of carried) {
    if (!named.includes(host)) {
      throw new BundleError(`bundle carries a ruleset for ${host}, which the manifest does not name`);
    }
  }

  for (const host of Object.keys(work)) {
    const entry = manifest.hosts[host];
    if (!entry?.workload) {
      throw new BundleError(
        `bundle carries a workload document for ${host}, whose manifest entry has no workload assignment`,
      );
    }
    if (typeof work[host] !== "string") throw new BundleError(`workload document for ${host} is not text`);
    const got = "sha256:" + createHash("sha256").update(work[host]!).digest("hex");
    if (entry.workload.policiesHash !== got) {
      throw new BundleError(
        `${host}: manifest says workload ${entry.workload.policiesHash} but the carried document hashes to ${got}`,
      );
    }
  }
  // The reverse direction. An entry claiming a workload half with no document would have the applier
  // fetch a generation it cannot complete.
  for (const host of named) {
    if (manifest.hosts[host]!.workload && typeof work[host] !== "string") {
      throw new BundleError(
        `${host} is assigned the workload layer but the bundle carries no document for it`,
      );
    }
  }

  return { manifest, rulesets, workload: work };
}
