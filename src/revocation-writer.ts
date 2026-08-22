import { createConnection, createServer, type Server, type Socket } from "node:net";
import { readFile, stat } from "node:fs/promises";
import {
  MAX_REVOCATION_SNAPSHOT_BYTES,
  parseRevocationSnapshot,
  serializeRevocationSnapshot,
  writeRevocationSnapshot,
} from "./revocation-snapshot.ts";
import { formatOperatorLog } from "./operator-i18n.ts";
import type { Lang } from "./i18n.ts";

const SOCKET_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 8 * 1024;

export class RevocationWriterUnavailable extends Error {}

export interface RevocationWriterOptions {
  snapshotFile: string;
  socketPath?: string;
  listenFd?: number;
  log?: (message: string) => void;
  logLang?: Lang;
  /** Tests may shorten this; production callers cannot extend the bounded five-second window. */
  requestTimeoutMs?: number;
}

function jsonBytes(value: unknown): Buffer {
  return serializeRevocationSnapshot(value);
}

function answer(socket: Socket, value: unknown): void {
  if (!socket.destroyed) socket.end(JSON.stringify(value) + "\n", () => socket.destroy());
}

/**
 * Minimal monotonic writer. It owns the denylist; the network-facing relay owns only this socket.
 * The protocol deliberately has one operation and no path argument, read API, or delete operation.
 */
export async function startRevocationWriter(opts: RevocationWriterOptions): Promise<{ server: Server }> {
  if ((opts.socketPath ? 1 : 0) + (opts.listenFd === undefined ? 0 : 1) !== 1) {
    throw new Error("revocation writer requires exactly one socketPath or listenFd");
  }
  if ((await stat(opts.snapshotFile)).size > MAX_REVOCATION_SNAPSHOT_BYTES) {
    throw new Error("configured revocation denylist is oversized");
  }
  const initial = await readFile(opts.snapshotFile);
  if (initial.length > MAX_REVOCATION_SNAPSHOT_BYTES) throw new Error("configured revocation denylist is oversized");
  parseRevocationSnapshot(JSON.parse(initial.toString("utf8")));
  const writeLog = opts.log ?? ((message: string) => console.error(`[revocation-writer] ${message}`));
  const logEvent = (key: Parameters<typeof formatOperatorLog>[1], params: Record<string, string | number> = {}) =>
    writeLog(`[revocation-writer] ${formatOperatorLog(opts.logLang ?? "en", key, params)}`);
  const requestTimeoutMs = opts.requestTimeoutMs ?? SOCKET_TIMEOUT_MS;
  if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > SOCKET_TIMEOUT_MS) {
    throw new Error(`revocation writer timeout must be between 1 and ${SOCKET_TIMEOUT_MS} ms`);
  }

  const server = createServer({ allowHalfOpen: true }, (socket) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let answered = false;
    const refuse = (message: string) => {
      if (answered) return;
      answered = true;
      answer(socket, { ok: false, error: message });
    };
    socket.setTimeout(requestTimeoutMs, () => refuse("request timed out"));
    socket.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_REVOCATION_SNAPSHOT_BYTES) {
        socket.pause();
        refuse("request is too large");
      } else {
        chunks.push(chunk);
      }
    });
    socket.on("end", () => {
      if (answered) return;
      answered = true;
      void (async () => {
        try {
          const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          const snapshot = await writeRevocationSnapshot(opts.snapshotFile, value, { mode: 0o644 });
          logEvent("server.revocationInstalled", { count: snapshot.revocations.length });
          answer(socket, { ok: true, count: snapshot.revocations.length });
        } catch {
          // Do not reflect row contents, parser details, or file paths across the privilege boundary.
          answer(socket, { ok: false, error: "snapshot was refused" });
        }
      })();
    });
    socket.on("error", () => {});
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    const onError = (error: Error) => rejectListen(error);
    server.once("error", onError);
    server.once("listening", () => {
      server.off("error", onError);
      resolveListen();
    });
    if (opts.listenFd !== undefined) server.listen({ fd: opts.listenFd });
    else server.listen(opts.socketPath!);
  });
  return { server };
}

/** Send one complete snapshot to the privilege-separated local writer. */
export function installRevocationSnapshot(socketPath: string, value: unknown): Promise<{ count: number }> {
  const body = jsonBytes(value);
  return new Promise((resolveInstall, rejectInstall) => {
    const socket = createConnection(socketPath);
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const finish = (error: Error | null, result?: { count: number }) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) rejectInstall(error);
      else resolveInstall(result!);
    };
    socket.setTimeout(SOCKET_TIMEOUT_MS, () => finish(new RevocationWriterUnavailable("revocation writer timed out")));
    socket.once("connect", () => socket.end(body));
    socket.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_RESPONSE_BYTES) finish(new RevocationWriterUnavailable("revocation writer returned an oversized response"));
      else chunks.push(chunk);
    });
    socket.once("error", () => finish(new RevocationWriterUnavailable("revocation writer is unavailable")));
    socket.once("end", () => {
      try {
        const response = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
          ok?: unknown; count?: unknown;
        };
        if (response.ok !== true || !Number.isSafeInteger(response.count) || (response.count as number) < 0) {
          return finish(new Error("revocation writer refused the snapshot"));
        }
        finish(null, { count: response.count as number });
      } catch {
        finish(new RevocationWriterUnavailable("revocation writer returned an invalid response"));
      }
    });
  });
}
