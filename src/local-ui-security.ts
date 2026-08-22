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
