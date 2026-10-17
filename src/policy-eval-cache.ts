import { importsAreReusable, type ImportReport, type ImportScope } from "./policy-import-scope.ts";

export interface SourceStamp {
  stamp: string;
  reuseAllowed: boolean;
}

/**
 * What one evaluation produced: the wire the parent accepted, and the imports the worker recorded.
 *
 * `imports` absent means the worker sent no report. That is treated as not reusable — an answer whose
 * inputs were not recorded is not one to serve again unchanged.
 */
export interface Evaluated {
  wire: string;
  imports?: ImportReport;
}

/**
 * A stamp found to import outside the scan, and the order in which its evaluation started.
 *
 * `started` orders marks between stamps: stamp strings say nothing about which is newer, and an older
 * evaluation that finishes late must not replace the mark of one that started after it.
 */
export interface UnreusableMark {
  stamp: string;
  started: number;
}

/** Start order across every call in this process. Only its ordering is read. */
let evaluationsStarted = 0;

/**
 * Coordinates one site's wire evaluation. The caller supplies the stamp, the parent validation, and
 * the scope an import report is judged against.
 *
 * An answer whose imports reach outside what the stamp can see is **returned and not stored**: the
 * request is served, and the same stamp is marked unreusable so the next call evaluates again rather
 * than joining a cached or in-flight answer. The mark is per stamp — a moved stamp is judged on its
 * own evaluation.
 *
 * @see policy-eval-cache.test.ts
 */
export async function currentPolicyWire(input: {
  sitePath: string;
  cached: Map<string, { stamp: string; wire: string }>;
  inFlight: Map<string, { stamp: string; answer: Promise<string> }>;
  /**
   * Stamps whose evaluation imported something the stamp cannot see, so a later call on that stamp
   * evaluates again instead of reading `cached` or joining `inFlight`.
   *
   * Read only when `reuseAllowed` — a dirty or unknown stamp never reaches the other two maps and does
   * not reach this one either.
   */
  unreusable: Map<string, UnreusableMark>;
  readStamp(): SourceStamp;
  evaluate(): Promise<Evaluated>;
  accepted(moduleWire: string): string;
  /** Where the site module and this renderer's own code live, for the import check. */
  importScope: ImportScope;
  /**
   * An answer whose imports reach outside the stamp, so it was served and not stored. The caller logs
   * it. Called only for a stamp that may be reused — a dirty or unknown stamp is never stored, so it
   * has nothing to report.
   */
  onUnreusable?: () => void;
}): Promise<string> {
  const { sitePath, cached, inFlight, unreusable, readStamp, evaluate, accepted, importScope, onUnreusable } = input;
  const read = readStamp();
  const { stamp, reuseAllowed } = read;
  // A stamp already found to import outside the scan is not served from the cache and not joined: the
  // evaluation that found it returned its answer to the callers waiting then, and every later call
  // evaluates again. A moved stamp is a different key, so it is judged on its own evaluation.
  const blocked = reuseAllowed && unreusable.get(sitePath)?.stamp === stamp;
  const hit = reuseAllowed && !blocked ? cached.get(sitePath) : undefined;
  if (hit && hit.stamp === stamp) return hit.wire;
  const running = reuseAllowed && !blocked ? inFlight.get(sitePath) : undefined;
  if (running && running.stamp === stamp) return running.answer;
  const started = ++evaluationsStarted;
  const answer = (async () => {
    const evaluated = await evaluate();
    const wire = accepted(evaluated.wire);
    // A dirty or unknown stamp is never stored, so there is nothing for the import check to protect
    // and the maps that record its verdict are not touched. Reading them here would be the first
    // access those stamps make.
    if (!reuseAllowed) return wire;
    // ## The judgement names the stamp it was computed for
    //
    // `read` was taken when this evaluation started. Reading it again here would judge this result
    // against a stamp that moved while it ran: the stale evaluation would then mark the **new** stamp
    // unreusable, and the next call on it would re-evaluate. The mark and the deletion below both name
    // `stamp`, so a newer stamp's entry is left where it is.
    //
    // The stored value is still replaced when it names a newer stamp. An older clean completion
    // overwriting the newer answer is the race this coordinator already had, and the tests pin it;
    // closing it here would change that behaviour. The import verdict is the part that must not cross
    // stamps.
    const reusable = importsAreReusable(evaluated.imports ?? { complete: false, urls: [] }, importScope);
    const marked = unreusable.get(sitePath);
    if (reusable) {
      // A reusable result clears only a mark on its own stamp that did not start after it: a mark on
      // another stamp is about that stamp, and a later evaluation of this one found otherwise.
      if (marked !== undefined && marked.stamp === stamp && marked.started < started) unreusable.delete(sitePath);
      cached.set(sitePath, { stamp, wire });
    } else {
      // The mark is replaced only by an evaluation that started later, whichever stamp it names. An
      // older evaluation finishing late leaves the newer stamp's mark where it is.
      if (marked === undefined || marked.started < started) unreusable.set(sitePath, { stamp, started });
      // A stored answer on this stamp is not served again; one on another stamp is not this verdict's.
      if (cached.get(sitePath)?.stamp === stamp) cached.delete(sitePath);
      onUnreusable?.();
    }
    return wire;
  })();
  if (!reuseAllowed) return answer;
  const entry = { stamp, answer };
  inFlight.set(sitePath, entry);
  // A newer stamp may have replaced this entry. Neither outcome may remove that newer evaluation.
  const forget = () => { if (inFlight.get(sitePath) === entry) inFlight.delete(sitePath); };
  answer.then(forget, forget);
  return answer;
}
