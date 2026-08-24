// Reading a response body without letting the far side decide how much memory we spend.
//
// ## Why this is a module rather than four inline loops
//
// It was four inline loops, and they did not agree. `oidc.ts` counted bytes **while** reading and
// refused mid-stream; `manager-server.ts` buffered the whole thing and then measured it, which is a
// limit enforced by the OOM killer rather than by the check that claims to enforce it. Two of the
// four had no bound at all.
//
// The processes on the receiving end of these reads are the ones this repository is most careful
// about elsewhere: the policy renderer is *"the untrusted side of that connection — the process that
// runs the policy author's code"*, and a relay is a gateway, the most exposed machine in its VPC.
// So the rule is one rule, in one place, and the callers differ only in the ceiling they pass.
//
// ## Two shapes, because there are genuinely two
//
// `readBoundedStream` takes a WHATWG `ReadableStream` — what `fetch` gives. `readBoundedNodeBody`
// takes a Node `IncomingMessage` — what `https.request` gives. Neither can be expressed in the
// other's terms without an adapter that would be longer than both.
//
// ## The Buffer concatenation is not incidental
//
// `readBoundedNodeBody` collects chunks and concatenates once. The obvious shorter form —
// `payload += chunk` — decodes each chunk independently, so a multi-byte character split across a
// TCP boundary becomes two U+FFFD replacement characters. **The resulting JSON still parses**, so
// the failure is a wrong value rather than an error. Measured: a Korean `detail` field split at
// four different offsets came back corrupted at every one of them, and `JSON.parse` accepted all
// four. `relayCall` had exactly that shape, and the fields it carries — an agent's `detail`, an
// `nft monitor` line, a policy's `maintenance` reason — are the ones most likely to be non-ASCII.

import type { IncomingMessage } from "node:http";

/**
 * Refused for size. A distinct class so a caller can tell "too big" from "could not read",
 * which are different problems with different fixes.
 */
export class BodyTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BodyTooLargeError";
  }
}

/**
 * Refuse early on a `Content-Length` that already exceeds the ceiling.
 *
 * **An optimisation, never the enforcement.** The header can be absent, it can lie, and transparent
 * HTTP decompression can make the decoded body larger than the wire value. The streaming count is
 * what actually holds; this only saves reading a body we already know we will refuse.
 */
export function declaredTooLarge(
  headers: { get(name: string): string | null } | undefined,
  limit: number,
): boolean {
  const declared = headers?.get("content-length");
  return declared !== null && declared !== undefined && Number(declared) > limit;
}

/**
 * Read a WHATWG response body, counting bytes as they arrive.
 *
 * Cancels the stream on refusal rather than draining it: the point of the ceiling is to stop
 * spending, and reading the rest to be polite spends exactly what was being refused.
 */
export async function readBoundedStream(
  body: ReadableStream<Uint8Array>,
  limit: number,
  what: string,
): Promise<Buffer> {
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        void reader.cancel().catch(() => undefined);
        throw new BodyTooLargeError(`${what} response exceeds ${limit} bytes`);
      }
      chunks.push(Buffer.from(value));
    }
  } catch (e) {
    if (e instanceof BodyTooLargeError) throw e;
    throw new Error(`${what} response could not be read: ${(e as Error).message}`);
  }
  return Buffer.concat(chunks, total);
}

/**
 * Read a Node `IncomingMessage`, counting bytes as they arrive.
 *
 * Destroys the response on refusal, for the same reason `readBoundedStream` cancels: an unbounded
 * read here is a manager or a CLI being made to allocate by whatever it just called.
 *
 * Returns a `Buffer`. Decoding is the caller's, and it must happen **once, on the whole thing** —
 * see the note on concatenation in this file's header for what per-chunk decoding does to a
 * multi-byte character.
 */
export function readBoundedNodeBody(
  res: IncomingMessage,
  limit: number,
  what: string,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let failed = false;
    res.on("data", (chunk: Buffer) => {
      if (failed) return;
      total += chunk.length;
      if (total > limit) {
        failed = true;
        res.destroy();
        reject(new BodyTooLargeError(`${what} response exceeds ${limit} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    res.on("end", () => {
      if (!failed) resolve(Buffer.concat(chunks, total));
    });
    res.on("error", (e) => {
      if (!failed) {
        failed = true;
        reject(new Error(`${what} response could not be read: ${e.message}`));
      }
    });
  });
}

/**
 * Read a response as text, bounded, for the `Fetcher` contract.
 *
 * ## Two shapes, and the contract says which bound each one gets
 *
 * `Fetcher` (see `policy-proposal.ts`) declares `body` as **optional**, and that is a statement
 * about what the bound can be, not an oversight:
 *
 *   · `body` present — the real `fetch`, and every production caller. Counted while reading, so
 *     the ceiling is a memory bound: nothing above it is ever allocated.
 *   · `body` absent — a substituted reader that hands back a whole string. The ceiling is still
 *     enforced, but after the string exists, so it bounds what this process will *act on* rather
 *     than what it allocates.
 *
 * The second is weaker and is written down here because it is not visible at the call site. It is
 * the shape the test doubles in this repository use; requiring `body` instead would rewrite all of
 * them without changing what production does, since production already takes the first branch.
 */
export async function readBoundedText(
  res: {
    headers?: { get(name: string): string | null };
    body?: ReadableStream<Uint8Array> | null;
    text?: () => Promise<string>;
  },
  limit: number,
  what: string,
): Promise<string> {
  if (declaredTooLarge(res.headers, limit)) {
    throw new BodyTooLargeError(`${what} response exceeds ${limit} bytes`);
  }
  if (res.body) return (await readBoundedStream(res.body, limit, what)).toString("utf8");
  if (!res.text) throw new Error(`${what} returned no readable body`);
  const text = await res.text();
  if (Buffer.byteLength(text, "utf8") > limit) {
    throw new BodyTooLargeError(`${what} response exceeds ${limit} bytes`);
  }
  return text;
}
