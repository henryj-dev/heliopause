// How a later poll is allowed to change what a screen is holding.
//
// 시안 A4: a failed poll must not erase the last view. The operator is looking
// at a generation they may be about to publish; "fetch failed" is not "the
// fleet is gone". 401 is the other case — the session ended, so the view
// must not stay.

export interface Held<T> {
  value: T;
  lastOkAt: number;
  failCount: number;
  lastFail: string | null;
}

export type HeldPollEvent<T> =
  | { kind: "ok"; value: T; at: number }
  | { kind: "fail"; reason: string }
  | { kind: "unauth" };

export function applyHeldPoll<T>(held: Held<T> | null, event: HeldPollEvent<T>): Held<T> | null {
  if (event.kind === "unauth") return null;
  if (event.kind === "ok") {
    return { value: event.value, lastOkAt: event.at, failCount: 0, lastFail: null };
  }
  if (!held) return null;
  return { ...held, failCount: held.failCount + 1, lastFail: event.reason };
}
