export interface SourceStamp {
  stamp: string;
  reuseAllowed: boolean;
}

/** Coordinates one site's wire evaluation. The caller supplies the stamp and parent validation.
 *  @see policy-eval-cache.test.ts */
export async function currentPolicyWire(input: {
  sitePath: string;
  cached: Map<string, { stamp: string; wire: string }>;
  inFlight: Map<string, { stamp: string; answer: Promise<string> }>;
  readStamp(): SourceStamp;
  evaluate(): Promise<string>;
  accepted(moduleWire: string): string;
}): Promise<string> {
  const { sitePath, cached, inFlight, readStamp, evaluate, accepted } = input;
  const { stamp, reuseAllowed } = readStamp();
  const hit = reuseAllowed ? cached.get(sitePath) : undefined;
  if (hit && hit.stamp === stamp) return hit.wire;
  const running = reuseAllowed ? inFlight.get(sitePath) : undefined;
  if (running && running.stamp === stamp) return running.answer;
  const answer = (async () => {
    const moduleWire = await evaluate();
    const wire = accepted(moduleWire);
    if (reuseAllowed) cached.set(sitePath, { stamp, wire });
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
