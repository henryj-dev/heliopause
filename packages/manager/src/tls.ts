import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface ScaffoldTls {
  key: Buffer;
  cert: Buffer;
}

function ephemeralTls(): ScaffoldTls {
  const dir = mkdtempSync(join(tmpdir(), "heliopause-manager-scaffold-"));
  const key = join(dir, "key.pem");
  const cert = join(dir, "cert.pem");
  // One-day throwaway. The live manager never takes this path — it refuses to start
  // without the configured certificate files. openssl is already a manager-image dependency.
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
    { stdio: "ignore" },
  );
  return { key: readFileSync(key), cert: readFileSync(cert) };
}

/** Resolve the scaffold's TLS material without silently ignoring a partial configuration. */
export function resolveTls(env: NodeJS.ProcessEnv): ScaffoldTls {
  const cert = env.HELIOPAUSE_CERT_FILE;
  const key = env.HELIOPAUSE_KEY_FILE;
  if (cert && key) return { cert: readFileSync(cert), key: readFileSync(key) };
  if (cert || key) {
    throw new Error(
      `[manager-scaffold] ${cert ? "HELIOPAUSE_KEY_FILE" : "HELIOPAUSE_CERT_FILE"} is empty ` +
        "while the other is set — refusing to fall back to a self-signed certificate",
    );
  }
  return ephemeralTls();
}
