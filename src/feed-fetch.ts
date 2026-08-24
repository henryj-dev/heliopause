// The one place this project reaches the public internet.
//
// Everything else here is injected: `ResolveCidrs` because heliopause has no inventory, `FetchFeed`
// because it has no network. This module is that injection's real implementation, kept in its own file
// so the boundary is visible — `snapshot.ts` and `geofeed.ts` stay testable without a socket, and the
// only code that can be surprised by a hostile response is this one.
//
// ## Why it is deliberately small and strict
//
// The response becomes the source of firewall rules. So the fetch refuses more than a normal HTTP
// client would:
//
//   · HTTPS only — a plaintext feed can be rewritten in transit, and rewriting it rewrites our rules.
//   · No redirects followed — a redirect is a third party telling us to fetch somewhere else, and the
//     registered URL is the thing that was reviewed.
//   · A hard byte ceiling enforced *while reading* — a `Content-Length` header is a claim, not a limit,
//     and a server that ignores it can exhaust memory before any validation runs.
//   · A wall-clock deadline — a feed that trickles forever holds the refresh open forever.
//
// ⚠️ The last one was **stated here and not implemented**, from the first version until 2026-08-24.
// `request({ timeout })` is `socket.setTimeout`, which fires on *inactivity*: every byte resets it.
// Measured — a server writing one byte every 200ms against a 1000ms timeout was still connected six
// seconds later, and at the production settings (30s, 32 MB) one byte every 29 seconds would hold a
// refresh open for roughly thirty years before the byte ceiling ended it. Neither of the other two
// bounds covers this: the ceiling counts bytes and a trickle sends few, and `refreshFeed` is waiting
// on this promise. There is now a real deadline below, and the socket timeout is kept beside it
// because the two catch different things — a dead peer, and a slow one.
//
// None of these are guesses about what could go wrong; each is the direct consequence of the response
// being trusted enough to shape a ruleset.

import { request } from "node:https";
import { FeedError } from "./geofeed.ts";
import type { FetchFeed } from "./snapshot.ts";

export interface FetchLimits {
  /** Refuse a body larger than this, measured as it arrives. */
  maxBytes: number;
  /** Give up on the whole request after this long. */
  timeoutMs: number;
}

export const FETCH_LIMITS: FetchLimits = {
  // Comfortably above Cloudflare's ingress lists (a few hundred bytes) and its geo CSV (~5 MB
  // measured), and far below anything that would strain the manager.
  maxBytes: 32 * 1024 * 1024,
  timeoutMs: 30_000,
};

/**
 * Fetch one feed document over HTTPS.
 *
 * Returns the body as text. Throws `FeedError` for every refusal, so a caller sees one error type
 * whether the failure was ours (a bad URL) or theirs (a 500) — `refreshFeed` turns any of them into
 * "keep the previous snapshot", which is the same response in each case.
 */
export function makeFetchFeed(limits: FetchLimits = FETCH_LIMITS): FetchFeed {
  // `perFeedMaxBytes` is the registered feed's own ceiling, passed down by `refreshFeed`. The
  // smaller of the two wins: `limits.maxBytes` is the absolute bound this process will ever buffer,
  // and a feed that declares a tighter one means it. Absent — a caller that does not know which feed
  // this is — leaves the global bound, which is what happened for every fetch until now.
  return (url: string, perFeedMaxBytes?: number) =>
    new Promise<string>((settleOk, settleErr) => {
      // ## One deadline over the whole request, and every exit clears it
      //
      // Armed before the request rather than inside the response handler: the wait this bounds
      // includes DNS and the TLS handshake, and a peer that completes neither is the cheapest way to
      // hold a refresh open.
      //
      // `resolve`/`reject` are wrapped rather than the timer being `unref`'d. An unref'd timer stops
      // holding the loop but still fires, and firing after a successful fetch would destroy a socket
      // the agent may have handed to the next request. Clearing is the honest version, and it also
      // keeps a passing test from sitting on a live timer for the rest of the deadline.
      let deadline: ReturnType<typeof setTimeout> | undefined;
      const clear = () => { if (deadline !== undefined) clearTimeout(deadline); deadline = undefined; };
      const resolve = (v: string) => { clear(); settleOk(v); };
      const reject = (e: unknown) => { clear(); settleErr(e); };

      const maxBytes = Math.min(
        limits.maxBytes,
        perFeedMaxBytes !== undefined && Number.isFinite(perFeedMaxBytes) && perFeedMaxBytes > 0
          ? perFeedMaxBytes
          : limits.maxBytes,
      );
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        return reject(new FeedError(`feed URL is not a URL: ${url}`));
      }
      if (parsed.protocol !== "https:") {
        return reject(
          new FeedError(
            `feed URL must be https — got ${parsed.protocol}//. A plaintext feed can be rewritten in ` +
              `transit, and rewriting it rewrites the firewall.`,
          ),
        );
      }

      const req = request(
        parsed,
        {
          method: "GET",
          // No redirect following, so this is the only host contacted.
          headers: { accept: "text/plain, text/csv, */*", "user-agent": "heliopause-feed/1" },
          timeout: limits.timeoutMs,
        },
        (res) => {
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400) {
            res.resume();
            return reject(
              new FeedError(
                `feed answered ${status} (redirect to ${res.headers["location"] ?? "?"}) — not followed; ` +
                  `register the final URL so what is fetched is what was reviewed`,
              ),
            );
          }
          if (status !== 200) {
            res.resume();
            return reject(new FeedError(`feed answered ${status}`));
          }

          const chunks: Buffer[] = [];
          let total = 0;
          res.on("data", (c: Buffer) => {
            total += c.length;
            if (total > maxBytes) {
              // ## Reject first, then destroy — the order decides which reason the operator reads
              //
              // `res.destroy()` makes the stream emit `aborted`, and that handler rejects too. A
              // promise keeps the first settlement, so destroying first means the ceiling refusal is
              // reported as **"feed connection aborted mid-body"** — measured 2026-08-24, on the very
              // first run of this module's first test.
              //
              // `refreshFeed` keeps the previous snapshot either way, so nothing downstream behaves
              // differently. The reason is the part a person acts on, and those two send them
              // opposite ways: one reads as a network blip worth retrying, the other says this feed
              // is larger than the ceiling it was registered with and no retry will help.
              reject(new FeedError(`feed body exceeded ${maxBytes} bytes`));
              // Destroyed rather than left to finish. `Content-Length` is a claim; this is the limit.
              res.destroy();
              return;
            }
            chunks.push(c);
          });
          res.on("aborted", () => reject(new FeedError("feed connection aborted mid-body")));
          res.on("error", (e) => reject(new FeedError(`feed read failed: ${e.message}`)));
          res.on("end", () => {
            // A truncated body is not a short feed. Without this an aborted transfer would parse to a
            // prefix of the real list and look like a feed that shrank — which the drift guard would
            // catch, but only by luck of the size, and never by knowing the transfer broke.
            if (res.destroyed && total > maxBytes) return;
            resolve(Buffer.concat(chunks).toString("utf8"));
          });
        },
      );

      // Inactivity. Distinct from the deadline above and worth keeping: it ends a silent peer in
      // `timeoutMs` rather than making every dead connection wait out the full deadline.
      req.on("timeout", () => {
        req.destroy(new FeedError(`feed went silent for ${limits.timeoutMs}ms`));
      });

      deadline = setTimeout(() => {
        req.destroy(
          new FeedError(
            `feed did not finish within ${limits.timeoutMs}ms — a body that arrives slowly enough ` +
              `never trips the idle timeout, so this is the bound that ends it`,
          ),
        );
      }, limits.timeoutMs);
      req.on("error", (e) =>
        reject(e instanceof FeedError ? e : new FeedError(`feed request failed: ${e.message}`)),
      );
      req.end();
    });
}
