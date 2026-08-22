// The Cloudflare device registry — the source of truth for which address belongs to which operator.
//
// ## Why this file exists
//
// Identity policy is only as strong as the device→address binding, and **Cloudflare assigns those
// addresses**, so they change on re-registration. Maintained by hand they drift silently: the rule
// keeps naming an address that now belongs to someone else, or to nobody. H12 is the sync path.
//
// ## What this module deliberately does not know
//
// **No site ranges appear here.** Which range means "operators" and which is legacy is deployment
// data and lives in `policy/`; this file is tracked and must stay free of it. Classification is the
// caller's job and the zone model (`zones.ts`) already does it — a registration whose address falls
// in no zone shows up as exactly that, rather than being silently dropped by a filter baked in here.
//
// **No recency filter.** Measured 2026-08-12: the three gateway registrations last reported 91–93
// days ago and all three are alive and taking policy. WARP Connector registrations do not refresh
// `last_seen_at` the way an interactive client does, so a 30-day cut would have removed the
// gateway backbone from policy. Silence is not evidence of absence — revocation is a human act and
// `status=active` is the only filter used. This is the rule the relay's `maintenance` flag follows.
import { request } from "node:https";

/** One WARP registration: a device's current mesh addresses and who it belongs to. */
export interface Registration {
  /** Registration id. Changes when the device re-registers — the address may too. */
  id: string;
  deviceId: string;
  deviceName: string;
  userId: string;
  userEmail: string;
  /** Mesh addresses. Both are `nullable` in the API; see `RegistryRead.addressless`. */
  v4: string;
  v6: string;
  lastSeenAt: string;
  tunnelType: string | null;
}

/** A registration the API returned without a usable address. Kept, never expanded into policy. */
export interface Addressless {
  id: string;
  deviceName: string;
  userEmail: string;
  /** Which of the two was missing — both, or one. */
  missing: "v4" | "v6" | "both";
}

export interface RegistryRead {
  registrations: Registration[];
  /**
   * Registrations the API returned with a null address.
   *
   * Reported rather than filtered. Dropping them would shrink the list, and a shrunk list is
   * indistinguishable from a device having been removed — which is the one thing a diff must never
   * get wrong.
   */
  addressless: Addressless[];
  /** How many pages were fetched. Surfaced so a read that needed many pages is visible. */
  pages: number;
}

/** Thrown when the read cannot be trusted to be complete. Never degrade this to an empty list. */
export class TruncatedRead extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TruncatedRead";
  }
}

interface Page {
  rows: Registration[];
  addressless: Addressless[];
  cursor: string;
  count: number;
  /** Total the cursor claims, when it can be decoded. `null` when it cannot. */
  total: number | null;
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

/**
 * The cursor is base64 of `<timestamp>.<opaque>.<base64 json>`, and the trailing segment carries
 * `{"total":N}`. Undocumented, so a failure to decode is not an error — it only means the
 * cross-check in `fetchRegistrations` cannot run for this read.
 */
export function totalFromCursor(cursor: string): number | null {
  const seg = cursor.split(".").at(-1);
  if (!seg) return null;
  try {
    const v = JSON.parse(Buffer.from(seg, "base64").toString("utf8")) as { total?: unknown };
    return typeof v.total === "number" && Number.isFinite(v.total) ? v.total : null;
  } catch {
    return null;
  }
}

/**
 * Turn one API response body into rows.
 *
 * Throws when the envelope says the call failed. A `success: false` body still parses as JSON and
 * still has a `result` key — reading rows off it would produce an empty list that looks like an
 * account with no devices.
 */
export function parsePage(body: unknown): Page {
  const b = body as { success?: unknown; errors?: unknown; result?: unknown; result_info?: unknown };
  if (b?.success !== true) {
    const errs = Array.isArray(b?.errors) ? b.errors.map((e) => JSON.stringify(e)).join("; ") : "";
    throw new Error(`Cloudflare rejected the registrations read: ${errs || "no error detail"}`);
  }
  if (!Array.isArray(b.result)) throw new Error("registrations response had no result array");

  const rows: Registration[] = [];
  const addressless: Addressless[] = [];
  for (const raw of b.result) {
    const x = raw as Record<string, unknown>;
    const user = (x.user ?? {}) as Record<string, unknown>;
    const device = (x.device ?? {}) as Record<string, unknown>;
    const v4 = str(x.virtual_ipv4);
    const v6 = str(x.virtual_ipv6);
    if (!v4 || !v6) {
      addressless.push({
        id: str(x.id),
        deviceName: str(device.name),
        userEmail: str(user.email),
        missing: !v4 && !v6 ? "both" : !v4 ? "v4" : "v6",
      });
      continue;
    }
    rows.push({
      id: str(x.id),
      deviceId: str(device.id),
      deviceName: str(device.name),
      userId: str(user.id),
      userEmail: str(user.email),
      v4,
      v6,
      lastSeenAt: str(x.last_seen_at),
      tunnelType: typeof x.tunnel_type === "string" ? x.tunnel_type : null,
    });
  }

  const info = (b.result_info ?? {}) as Record<string, unknown>;
  const cursor = str(info.cursor);
  return {
    rows,
    addressless,
    cursor,
    count: typeof info.count === "number" ? info.count : rows.length + addressless.length,
    total: cursor ? totalFromCursor(cursor) : null,
  };
}

export interface FetchOptions {
  accountId: string;
  token: string;
  /** Page size. The API caps this; the default matches what the dashboard uses. */
  perPage?: number;
  /**
   * Refuse to keep paging past this many requests.
   *
   * A cap that is hit is a `TruncatedRead`, never a short list. Registrations accumulate — measured
   * 2026-08-12, four people held 32 active ones — so this grows over time and is meant to.
   */
  maxPages?: number;
  /** Injected in tests. Returns the parsed JSON body for one page. */
  get?: (url: string, token: string) => Promise<unknown>;
}

/**
 * Read every active registration.
 *
 * **Termination is `cursor === ""`, not "the page came back short".** Measured 2026-08-12: asking
 * for 50 and receiving all 32 still returns a non-empty cursor, and the follow-up request returns
 * `count: 0, cursor: ""`. A loop that stopped on a short page would work by accident on a full
 * account and stop early on a small one.
 */
export async function fetchRegistrations(opts: FetchOptions): Promise<RegistryRead> {
  const perPage = opts.perPage ?? 100;
  const maxPages = opts.maxPages ?? 50;
  const get = opts.get ?? httpsGetJson;

  const registrations: Registration[] = [];
  const addressless: Addressless[] = [];
  let cursor = "";
  let pages = 0;
  let claimedTotal: number | null = null;

  do {
    if (pages >= maxPages) {
      throw new TruncatedRead(
        `stopped after ${maxPages} pages with a cursor still open — the read is incomplete, not empty`,
      );
    }
    const url =
      `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(opts.accountId)}` +
      `/devices/registrations?status=active&per_page=${perPage}` +
      (cursor ? `&cursor=${encodeURIComponent(cursor)}` : "");
    const page = parsePage(await get(url, opts.token));
    pages += 1;
    registrations.push(...page.rows);
    addressless.push(...page.addressless);
    if (claimedTotal === null) claimedTotal = page.total;
    cursor = page.cursor;
  } while (cursor);

  // Cross-check against the total the first cursor claimed. Advisory — `claimedTotal` is null when
  // the cursor could not be decoded, and an absent check is not a passing one, so this only ever
  // turns a wrong count into a refusal and never turns an unknown one into an approval.
  const seen = registrations.length + addressless.length;
  if (claimedTotal !== null && seen !== claimedTotal) {
    throw new TruncatedRead(
      `read ${seen} registrations but the cursor claimed ${claimedTotal} — refusing to treat this as complete`,
    );
  }

  return { registrations, addressless, pages };
}

/** One device's address moving, or the device appearing/leaving. */
export interface RegistryChange {
  kind: "added" | "removed" | "moved";
  deviceId: string;
  deviceName: string;
  userEmail: string;
  /** Present for `moved` and `removed`. */
  before?: { v4: string; v6: string };
  /** Present for `moved` and `added`. */
  after?: { v4: string; v6: string };
}

/**
 * Compare two reads, keyed by device rather than by registration.
 *
 * Re-registering mints a new registration id, so keying on that would report every re-registration
 * as a removal plus an addition and hide the fact that matters — **the address changed under a
 * device that is still the same device**. That is the drift H12 exists to catch.
 */
export function diffRegistrations(
  before: readonly Registration[],
  after: readonly Registration[],
): RegistryChange[] {
  const byDevice = (rs: readonly Registration[]) => {
    const m = new Map<string, Registration>();
    // Later registrations win, so a device holding two active registrations reports its newest.
    for (const r of [...rs].sort((a, b) => a.lastSeenAt.localeCompare(b.lastSeenAt))) m.set(r.deviceId, r);
    return m;
  };
  const a = byDevice(before);
  const b = byDevice(after);
  const out: RegistryChange[] = [];

  for (const [id, was] of a) {
    const now = b.get(id);
    if (!now) {
      out.push({
        kind: "removed",
        deviceId: id,
        deviceName: was.deviceName,
        userEmail: was.userEmail,
        before: { v4: was.v4, v6: was.v6 },
      });
    } else if (now.v4 !== was.v4 || now.v6 !== was.v6) {
      out.push({
        kind: "moved",
        deviceId: id,
        deviceName: now.deviceName,
        userEmail: now.userEmail,
        before: { v4: was.v4, v6: was.v6 },
        after: { v4: now.v4, v6: now.v6 },
      });
    }
  }
  for (const [id, now] of b) {
    if (a.has(id)) continue;
    out.push({
      kind: "added",
      deviceId: id,
      deviceName: now.deviceName,
      userEmail: now.userEmail,
      after: { v4: now.v4, v6: now.v6 },
    });
  }
  // Stable order so a rendered diff does not churn between reads.
  const rank = { moved: 0, removed: 1, added: 2 } as const;
  return out.sort((x, y) => rank[x.kind] - rank[y.kind] || x.deviceName.localeCompare(y.deviceName));
}

/** A user and the devices registered to them — the `cf-user` expansion H13 needs. */
export interface UserRow {
  userId: string;
  email: string;
  devices: number;
  v4: string[];
  v6: string[];
}

/**
 * Group registrations by user.
 *
 * Keyed on `userId`, not on the address — the email is a label. Measured 2026-08-12 that
 * `Zero Trust Read` alone returns `user.id`, `user.email` and `user.name`, so no PII permission is
 * needed for either the key or the label.
 */
export function userRows(rs: readonly Registration[]): UserRow[] {
  const m = new Map<string, UserRow>();
  for (const r of rs) {
    let u = m.get(r.userId);
    if (!u) {
      u = { userId: r.userId, email: r.userEmail, devices: 0, v4: [], v6: [] };
      m.set(r.userId, u);
    }
    u.devices += 1;
    u.v4.push(r.v4);
    u.v6.push(r.v6);
  }
  for (const u of m.values()) {
    u.v4.sort();
    u.v6.sort();
  }
  return [...m.values()].sort((a, b) => a.email.localeCompare(b.email));
}

function httpsGetJson(url: string, token: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = request(
      url,
      { method: "GET", headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          try {
            resolve(JSON.parse(text));
          } catch {
            // Include the status: an HTML error page from a proxy is the common cause and the
            // parse error alone would send the reader looking at this code instead of the network.
            reject(new Error(`registrations read returned HTTP ${res.statusCode} with a non-JSON body`));
          }
        });
      },
    );
    req.on("error", reject);
    req.setTimeout(20_000, () => req.destroy(new Error("registrations read timed out")));
    req.end();
  });
}
