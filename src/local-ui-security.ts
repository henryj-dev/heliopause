import type { IncomingHttpHeaders, IncomingMessage } from "node:http";

export const MAX_UI_BODY_BYTES = 64 * 1024;

export class UiRequestError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

/**
 * Is this request a mutation, for the purpose of the Origin check?
 *
 * 🔴 **Derived from the method, not from a list of routes.** The caller used to spell out
 * `(pathname === "/api/propose" && method === "POST") || (pathname.startsWith("/api/policies/") &&
 * (method === "PUT" || method === "DELETE"))`, and a hand-maintained list of mutating routes is a
 * list somebody eventually forgets to extend. Measured: replacing that whole expression with
 * `false` — every route CSRF-open at once — left all 1,835 tests green.
 *
 * The method is the complete answer and needs no maintenance: a safe method does not change state
 * (that is what "safe" means in HTTP), and everything else does. Today's routes agree exactly —
 * every mutation here is POST, PUT or DELETE and every read is GET — but the point is that the next
 * one will agree too, without anyone remembering.
 */
export function isWriteMethod(method: string | undefined): boolean {
  return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
}

/**
 * Does this request carry a body this server will parse as JSON?
 *
 * Same reasoning as `isWriteMethod`: derived rather than listed. A body-bearing method must declare
 * `application/json`, which is what stops a `<form>` — restricted to url-encoded, plain-text and
 * multipart — from reaching a write handler at all. `DELETE` carries no body and is not asked.
 */
export function expectsJsonBody(method: string | undefined): boolean {
  return method === "POST" || method === "PUT" || method === "PATCH";
}

/**
 * Validate the browser-facing boundary of the loopback-only workstation server.
 *
 * Host is checked on every request to stop DNS rebinding from turning an attacker's origin into a
 * reader of the local policy. Mutations additionally require the exact numeric-loopback Origin;
 * unlike a remote CLI, this local UI has no legitimate Origin-less write caller.
 */
export function localUiBoundaryError(
  headers: IncomingHttpHeaders,
  self: URL,
  options: { write: boolean; json: boolean },
): UiRequestError | null {
  if (headers.host !== self.host) return new UiRequestError("Host must be this loopback UI", 421);
  if (options.write && headers.origin !== self.origin) {
    return new UiRequestError("write Origin must be this loopback UI", 403);
  }
  if (
    options.json &&
    String(headers["content-type"] ?? "").split(";", 1)[0]!.trim().toLowerCase() !== "application/json"
  ) {
    return new UiRequestError("content-type must be application/json", 415);
  }
  return null;
}

/** Count bytes as they arrive; `Content-Length` is only an early refusal and is not trusted. */
export function readUiBody(req: IncomingMessage): Promise<string> {
  const declared = Number(req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > MAX_UI_BODY_BYTES) {
    return Promise.reject(new UiRequestError(`request body exceeds ${MAX_UI_BODY_BYTES} bytes`, 413));
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let failed = false;
    req.on("data", (chunk: Buffer | string) => {
      if (failed) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += bytes.byteLength;
      if (total > MAX_UI_BODY_BYTES) {
        // Keep draining the request so the server can return the 413 cleanly instead of resetting the
        // browser's connection. Only storage stops here.
        failed = true;
        reject(new UiRequestError(`request body exceeds ${MAX_UI_BODY_BYTES} bytes`, 413));
        return;
      }
      chunks.push(bytes);
    });
    req.on("end", () => { if (!failed) resolve(Buffer.concat(chunks, total).toString("utf8")); });
    req.on("error", (e) => { if (!failed) reject(e); });
  });
}
