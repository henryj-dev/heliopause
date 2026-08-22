// GET /api/workload-traffic, as this package is allowed to see it.
//
// Duplicated rather than imported from `heliopause`: the web package must not
// pull the library into a Vite bundle. `unavailable` and an empty summary are
// opposite findings — a missing reader must not render as "no traffic".

export interface TrafficRow {
  endpoint: string;
  direction: string;
  peer: string;
  port: string;
  packets: number;
  bytes: number;
}

export type TrafficView =
  | { kind: "unavailable"; message: string }
  | {
    kind: "summary";
    entries: number;
    withTraffic: number;
    dead: number;
    top: TrafficRow[];
    deadSample: TrafficRow[];
  };

export type TrafficRead =
  | { ok: true; view: TrafficView }
  | { ok: false; reason: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readRow(value: unknown): TrafficRow | null {
  if (!isRecord(value)) return null;
  if (typeof value.endpoint !== "string" || typeof value.direction !== "string") return null;
  if (typeof value.peer !== "string" || typeof value.port !== "string") return null;
  if (typeof value.packets !== "number" || typeof value.bytes !== "number") return null;
  return {
    endpoint: value.endpoint,
    direction: value.direction,
    peer: value.peer,
    port: value.port,
    packets: value.packets,
    bytes: value.bytes,
  };
}

function readRows(value: unknown, label: string): TrafficRow[] | string {
  if (!Array.isArray(value)) return `${label} is not a list`;
  const rows: TrafficRow[] = [];
  for (const item of value) {
    const row = readRow(item);
    if (!row) return `a ${label} row is malformed`;
    rows.push(row);
  }
  return rows;
}

export type TrafficListing = "unavailable" | "empty" | "summary";

/** Empty is a read of entries: 0. Unavailable is "the reader has not produced a dump". */
export function trafficListing(view: TrafficView): TrafficListing {
  if (view.kind === "unavailable") return "unavailable";
  if (view.entries === 0) return "empty";
  return "summary";
}

export function readTrafficView(data: unknown): TrafficRead {
  if (!isRecord(data)) return { ok: false, reason: "traffic view is not an object" };
  if (typeof data.unavailable === "string") {
    return { ok: true, view: { kind: "unavailable", message: data.unavailable } };
  }
  if (typeof data.entries !== "number" || typeof data.withTraffic !== "number" || typeof data.dead !== "number") {
    return { ok: false, reason: "traffic view is missing counts" };
  }
  const top = readRows(data.top, "top");
  if (typeof top === "string") return { ok: false, reason: top };
  const deadSample = readRows(data.deadSample, "deadSample");
  if (typeof deadSample === "string") return { ok: false, reason: deadSample };
  return {
    ok: true,
    view: {
      kind: "summary",
      entries: data.entries,
      withTraffic: data.withTraffic,
      dead: data.dead,
      top,
      deadSample,
    },
  };
}
