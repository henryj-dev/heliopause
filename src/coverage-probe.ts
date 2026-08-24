// The prober. One TCP connection attempt, turned into an outcome nobody has interpreted yet.
//
// ## The error that would make every IPv6 row green
//
// A runner without IPv6 answers every v6 connect with `ENETUNREACH` immediately. Mapped to
// `timeout`, every "must be blocked" check would pass on v6 while nothing was measured at all —
// precisely the failure the design names ("v6 미검증이 v4 통과에 가려진다"), arriving through the
// one screen that is supposed to be independent of the fleet.
//
// So local-stack errors are `error`, never `timeout`, and `probeAll` refuses to attempt a family
// the host cannot route at all rather than filling the table with indistinguishable failures.
//
// ## Why only TCP
//
// The B items are all TCP, and a UDP "connection" tells you nothing without a protocol-aware
// payload — an unanswered UDP probe is indistinguishable from a dropped one. Rather than emit a
// result that cannot mean anything, a UDP target is reported as `error` with the reason, so it
// shows as unmeasured instead of as blocked.
import { connect } from "node:net";
import type { CoverageCheck, CoverageTarget, Family, Outcome, Probe } from "./coverage.ts";

export interface ProbeOptions {
  /** Where this ran. Recorded on every probe and rendered. */
  observedFrom: string;
  timeoutMs?: number;
  /** Injected in tests. */
  now?: () => string;
  /**
   * Third party used to ask whether this machine can originate traffic in a family at all.
   *
   * A name rather than an address, and overridable, for two reasons. A literal here would be a
   * public address in a repository that is meant to be published — the CI guard rejects those, and
   * it is right to: a reader cannot tell a well-known resolver from a host of ours. And which third
   * party is reachable is a property of wherever this runs, which is not something tracked code
   * should be deciding on the runner's behalf.
   */
  reachability?: { host: string; port: number };
}

/** Dual-stacked and answers on 443 from most places. Overridable — see `ProbeOptions`. */
export const DEFAULT_REACHABILITY = { host: "one.one.one.one", port: 443 };

/**
 * Addresses reserved for documentation (RFC 5737, RFC 3849). Nothing routes to them.
 *
 * Used as a **known negative**. `hookPolicy.input: "drop"` makes a correct result look like a
 * timeout, so a row of timeouts proves nothing without a positive taken the same way — the site
 * module already says this about a 2026-08-02 measurement. The inverse is just as true and is what
 * this constant is for: **a row of connects proves nothing without a negative taken the same way.**
 * Some tunnels and proxies complete the local handshake before learning the far end is unreachable,
 * and every "must be blocked" check then reports a hole that is not there.
 */
export const UNROUTABLE = { v4: "192.0.2.1", v6: "2001:db8::1", port: 443 };

/**
 * Errors that say something about this machine rather than about the path.
 *
 * `EAFNOSUPPORT`/`ENETUNREACH` mean the local stack will not even send the packet. `EHOSTUNREACH`
 * is usually a local routing answer too — a router replying "no route" is not the remote firewall
 * dropping traffic, and treating it as one would credit a rule that never saw the packet.
 */
const LOCAL_STACK = new Set(["EAFNOSUPPORT", "ENETUNREACH", "EHOSTUNREACH", "EADDRNOTAVAIL"]);

/**
 * The errno mapping, as a function so it can be pinned by a test.
 *
 * It lived inline until a defect injection showed the inline version could be changed to map
 * `ENETUNREACH` onto `timeout` with every test still passing — the socket-level test could not
 * force that errno portably, so it accepted either answer and therefore checked nothing. This is
 * the mapping that decides whether a runner with no IPv6 renders green.
 */
export function outcomeForError(code: string, message = ""): { outcome: Outcome; detail?: string } {
  if (code === "ECONNREFUSED") return { outcome: "refused", detail: "RST — the host answered" };
  if (LOCAL_STACK.has(code)) {
    return { outcome: "error", detail: `${code} — this machine cannot reach that family, nothing was measured` };
  }
  if (code === "ETIMEDOUT") return { outcome: "timeout" };
  return { outcome: "error", detail: code || message };
}

/** Attempt one connection. Never throws — the outcome is the return value. */
export function probeOne(
  addr: string,
  port: number,
  family: Family,
  opts: ProbeOptions,
): Promise<{ outcome: Outcome; ms: number; detail?: string }> {
  const timeoutMs = opts.timeoutMs ?? 5000;
  const started = Date.now();
  return new Promise((resolve) => {
    let settled = false;
    const done = (outcome: Outcome, detail?: string) => {
      if (settled) return;
      settled = true;
      try {
        sock.destroy();
      } catch {
        // Destroying an already-destroyed socket is not a probe result.
      }
      resolve({ outcome, ms: Date.now() - started, ...(detail ? { detail } : {}) });
    };

    const sock = connect({ host: addr, port, family: family === "v4" ? 4 : 6, autoSelectFamily: false });
    sock.setTimeout(timeoutMs);
    sock.on("connect", () => done("connected"));
    sock.on("timeout", () => done("timeout"));
    sock.on("error", (e: NodeJS.ErrnoException) => {
      const r = outcomeForError(e.code ?? "", e.message);
      done(r.outcome, r.detail);
    });
  });
}

/**
 * Whether this machine can plausibly originate traffic in a family, **and why not**.
 *
 * A refusal or a connect both prove the stack works; only a local-stack error proves it does not.
 * A name that will not resolve in this family fails the same way, which is the honest answer — a
 * machine that cannot resolve AAAA cannot measure IPv6 either.
 *
 * **The reason is returned, not discarded.** The first real run of this recorded "no usable v6
 * path" on every IPv6 cell and nothing else, which left "the runner has no IPv6" and "our prober
 * is broken" looking identical in the stored results. An instrument that reports a negative
 * without its cause makes its own correctness unfalsifiable.
 */
export async function familyUsable(
  family: Family,
  opts: ProbeOptions,
): Promise<{ usable: boolean; reason: string }> {
  const t = opts.reachability ?? DEFAULT_REACHABILITY;
  const r = await probeOne(t.host, t.port, family, { ...opts, timeoutMs: opts.timeoutMs ?? 4000 });
  return {
    usable: r.outcome !== "error",
    reason: `${t.host}:${t.port} answered ${r.outcome}${r.detail ? ` (${r.detail})` : ""}`,
  };
}

export interface ProbeRunOptions extends ProbeOptions {
  /**
   * Families to attempt. Each is checked for usability first; an unusable family yields `error`
   * probes carrying the reason rather than being skipped, so the screen shows a gap instead of
   * silently shrinking the table.
   */
  families?: Family[];
  /** Injected in tests. */
  probe?: typeof probeOne;
  usable?: (family: Family, opts: ProbeOptions) => Promise<{ usable: boolean; reason: string }>;
  /**
   * Injected in tests. Answers "does this vantage point complete handshakes that cannot succeed?"
   */
  fabricates?: (family: Family, opts: ProbeOptions) => Promise<{ fabricates: boolean; reason: string }>;
}

/**
 * Whether this vantage point completes connections to somewhere nothing can answer.
 *
 * A `connected` here means every `blocked` check from this vantage would report a hole, and every
 * `reach` check would pass without proving anything. The whole run is then worthless, which is a
 * far better thing to know than to publish.
 */
export async function familyFabricates(
  family: Family,
  opts: ProbeOptions,
): Promise<{ fabricates: boolean; reason: string }> {
  const addr = family === "v4" ? UNROUTABLE.v4 : UNROUTABLE.v6;
  const r = await probeOne(addr, UNROUTABLE.port, family, { ...opts, timeoutMs: opts.timeoutMs ?? 4000 });
  return {
    fabricates: r.outcome === "connected",
    reason: `${addr}:${UNROUTABLE.port} (documentation range, unroutable) answered ${r.outcome}`,
  };
}

/** Run every applicable target of every check. */
export async function probeAll(
  checks: readonly CoverageCheck[],
  opts: ProbeRunOptions,
): Promise<Probe[]> {
  const families = opts.families ?? (["v4", "v6"] as Family[]);
  const probe = opts.probe ?? probeOne;
  const usable = opts.usable ?? familyUsable;
  const now = opts.now ?? (() => new Date().toISOString());

  const fabricates = opts.fabricates ?? familyFabricates;
  const ok = new Map<Family, boolean>();
  const why = new Map<Family, string>();
  for (const f of families) {
    const r = await usable(f, opts);
    if (!r.usable) {
      ok.set(f, false);
      why.set(f, r.reason);
      continue;
    }
    // Reachable is not the same as truthful. Ask the known negative before believing anything.
    const fab = await fabricates(f, opts);
    ok.set(f, !fab.fabricates);
    why.set(f, fab.fabricates ? `this vantage point fabricates connections — ${fab.reason}` : r.reason);
  }

  const out: Probe[] = [];
  for (const check of checks) {
    // A vantage point policy treats specially cannot answer this question. Refused before the
    // control probe, because there is nothing to learn here regardless of what the control says.
    const blind = (check.meaninglessFrom ?? []).find((v) => opts.observedFrom.includes(v));
    // Measure the measurer first. A vantage point that cannot reach a known-good third party on
    // this port cannot say anything about our hosts on it either, and the failure looks identical
    // to a firewall doing its job.
    //
    // ## Why this holds a reason and not a boolean
    //
    // The three ways a control can fail to vouch for a family are different things, and the cell
    // this produces is read by a person deciding what to fix:
    //
    //   · the control was probed and did not answer   → the network, or the far side
    //   · the control declares no address for this family → the *check*, and nobody would guess it
    //   · this vantage has no usable path on this family  → the runner
    //
    // A boolean collapsed all three into "control target for X was unreachable on v6", which is
    // false for the middle one — it was never configured, and an operator reading that goes looking
    // at a network that is fine. `coverage.ts` is built on the rule that a cell must say why; this
    // is one of the sentences it says.
    const controlWhy = new Map<Family, string | null>();
    for (const family of families) {
      if (!check.control) { controlWhy.set(family, null); continue; }
      const addr = family === "v4" ? check.control.addr4 : check.control.addr6;
      if (!addr) {
        controlWhy.set(
          family,
          `check ${check.id} declares a control target with no ${family} address, so nothing on this` +
            ` family can be vouched for — add one, or drop the ${family} targets`,
        );
        continue;
      }
      if (!ok.get(family)) {
        controlWhy.set(family, `no usable ${family} path to reach the control target from ${opts.observedFrom}`);
        continue;
      }
      const r = await probe(addr, check.control.port, family, opts);
      controlWhy.set(
        family,
        r.outcome === "connected"
          ? null
          : `control target for ${check.id} was unreachable on ${family} from ${opts.observedFrom}` +
            ` — this vantage point cannot measure port ${check.control.port}`,
      );
    }
    for (const t of check.targets) {
      for (const family of families) {
        const addr = addrOf(t, family);
        if (!addr) continue;
        const base = { checkId: check.id, family, addr, port: t.port, observedFrom: opts.observedFrom };
        if (blind) {
          out.push({
            ...base,
            outcome: "error",
            at: now(),
            ms: 0,
            detail:
              `${opts.observedFrom} matches "${blind}", which policy grants privileged access to` +
              ` port ${t.port} — its answer would not be about the internet, so nothing was measured`,
          });
          continue;
        }
        if (!ok.get(family)) {
          out.push({
            ...base,
            outcome: "error",
            at: now(),
            ms: 0,
            detail:
              `no usable ${family} path from ${opts.observedFrom} — nothing was measured;` +
              ` reachability probe: ${why.get(family)}`,
          });
          continue;
        }
        const noControl = controlWhy.get(family);
        if (noControl) {
          out.push({ ...base, outcome: "error", at: now(), ms: 0, detail: `${noControl}, nothing was measured` });
          continue;
        }
        if (t.proto !== "tcp") {
          out.push({
            ...base,
            outcome: "error",
            at: now(),
            ms: 0,
            detail: `${t.proto} is not probed — an unanswered datagram cannot be told from a dropped one`,
          });
          continue;
        }
        const r = await probe(addr, t.port, family, opts);
        out.push({ ...base, outcome: r.outcome, at: now(), ms: r.ms, ...(r.detail ? { detail: r.detail } : {}) });
      }
    }
  }
  return out;
}

function addrOf(t: CoverageTarget, family: Family): string | undefined {
  return family === "v4" ? t.addr4 : t.addr6;
}
