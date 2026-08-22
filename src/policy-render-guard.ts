/**
 * What makes the policy renderer unsafe to start.
 *
 * ## Why this is a module and not four lines in the entry point
 *
 * It was four lines in the entry point. The one that mattered most — a Kubernetes service account
 * token being present, which is what `automountServiceAccountToken: false` is supposed to prevent —
 * could not be tested at all: the path is `/var/run/secrets/kubernetes.io/serviceaccount/token`, a
 * developer machine does not have it, and a test cannot create it. Defect injection found this by
 * deleting the check and watching every test still pass.
 *
 * An environment override for the path would have made it testable and made it worthless, since
 * anything that can set the environment can also point the check at nothing. So the *logic* moves
 * here where a caller passes the path, and the *wiring* stays in the entry point where a spawn test
 * proves it runs and exits. Two tests, one property, neither able to pass on its own.
 *
 * ## What "armed" means
 *
 * This process runs whatever is in the policy repository — that is its whole job, and it is audit
 * finding C1's containment. Containment only holds if there is nothing here to take. So the renderer
 * refuses to start while it holds a credential, and refusing is the correct outcome: not starting
 * costs the console, starting armed costs the fleet.
 */
import { existsSync } from "node:fs";

/**
 * Names that mean a secret, near enough.
 *
 * Matching on names rather than a list of known variables, because the failure this catches is
 * somebody adding a *new* mount to this Deployment by copying the manager's — and a list of known
 * names cannot contain a variable that did not exist when the list was written.
 */
const CREDENTIAL_NAME = /(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|_KEY_FILE|CLIENT_SECRET|CREDENTIAL)/i;

/**
 * The one credential this process may hold.
 *
 * It authenticates the *caller* rather than authorising this process to reach anything, so holding
 * it grants the policy code nothing. Without this exception the renderer could not be protected by
 * a bearer at all, and the fix an operator would reach for is deleting the check.
 */
export const ALLOWED_CREDENTIAL = "HELIOPAUSE_POLICY_RENDER_TOKEN";

/**
 * The same credential, named as a file path.
 *
 * Preferred over the value in the environment for the reason the manager states about its own
 * secrets: env survives in `/proc/<pid>/environ` and in crash dumps. It has to be allowlisted
 * explicitly because `CREDENTIAL_NAME` matches on `TOKEN` and would otherwise refuse the start —
 * measured, not assumed: `armedReasons({ env: { HELIOPAUSE_POLICY_RENDER_TOKEN_FILE: "x" } })`
 * returned `environment HELIOPAUSE_POLICY_RENDER_TOKEN_FILE` before this line existed, so switching
 * to the file form without it produces a renderer that will not come up.
 *
 * Allowing it grants the policy code nothing, exactly as with the value form: the token authenticates
 * the *caller* of this service rather than authorising this service to reach anything.
 */
export const ALLOWED_CREDENTIAL_FILE = "HELIOPAUSE_POLICY_RENDER_TOKEN_FILE";

/** Where kubelet projects the pod's service account token when it is not disabled. */
export const SERVICE_ACCOUNT_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token";

export interface GuardInput {
  env: Record<string, string | undefined>;
  /** Injected so this is testable; the entry point passes `SERVICE_ACCOUNT_TOKEN`. */
  serviceAccountTokenFile?: string;
  /** Injected for the same reason. */
  exists?: (path: string) => boolean;
}

/**
 * Everything worth stealing that this process currently holds, named.
 *
 * **Names, never values.** The message goes to a container log, which is not as private as the
 * secret it is complaining about — a refusal that prints the key it found has leaked it to whoever
 * can read `kubectl logs`.
 *
 * Empty means safe to start.
 */
export function armedReasons(input: GuardInput): string[] {
  const exists = input.exists ?? existsSync;
  const armed: string[] = [];

  for (const name of Object.keys(input.env)) {
    if (name === ALLOWED_CREDENTIAL || name === ALLOWED_CREDENTIAL_FILE) continue;
    if (CREDENTIAL_NAME.test(name)) armed.push(`environment ${name}`);
  }

  // Present means `automountServiceAccountToken: false` was left off the pod spec. With it, code in
  // the policy repository can talk to the Kubernetes API as this pod's service account — inside the
  // cluster whose firewall this system governs.
  const sa = input.serviceAccountTokenFile ?? SERVICE_ACCOUNT_TOKEN;
  if (exists(sa)) armed.push(`service account token at ${sa}`);

  return armed.sort();
}
