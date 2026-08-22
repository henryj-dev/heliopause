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
  return (url: string) =>
    new Promise<string>((resolve, reject) => {
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
            if (total > limits.maxBytes) {
              // Destroyed rather than left to finish. `Content-Length` is a claim; this is the limit.
              res.destroy();
              return reject(new FeedError(`feed body exceeded ${limits.maxBytes} bytes`));
            }
            chunks.push(c);
          });
          res.on("aborted", () => reject(new FeedError("feed connection aborted mid-body")));
          res.on("error", (e) => reject(new FeedError(`feed read failed: ${e.message}`)));
          res.on("end", () => {
            // A truncated body is not a short feed. Without this an aborted transfer would parse to a
            // prefix of the real list and look like a feed that shrank — which the drift guard would
            // catch, but only by luck of the size, and never by knowing the transfer broke.
            if (res.destroyed && total > limits.maxBytes) return;
            resolve(Buffer.concat(chunks).toString("utf8"));
          });
        },
      );

      req.on("timeout", () => {
        req.destroy(new FeedError(`feed did not respond within ${limits.timeoutMs}ms`));
      });
      req.on("error", (e) =>
        reject(e instanceof FeedError ? e : new FeedError(`feed request failed: ${e.message}`)),
      );
      req.end();
    });
}
