// The topbar line 시안 A1 pins: "읽음 2s 전 · 10s 주기 · 실패 0회".
//
// The fleet poll owns the numbers. The bar only paints what the active
// screen last published — leaving the screen clears it.

export interface FreshnessSnap {
  lastOkAt: number;
  intervalMs: number;
  failCount: number;
}

export interface ChromeFreshness {
  readonly snap: FreshnessSnap | null;
  readonly now: number;
  publish(next: FreshnessSnap | null): void;
}

let instance: ChromeFreshness | undefined;
let tick: ReturnType<typeof setInterval> | null = null;

function createFreshness(): ChromeFreshness {
  let snap = $state<FreshnessSnap | null>(null);
  let now = $state(Date.now());

  return {
    get snap() {
      return snap;
    },
    get now() {
      return now;
    },
    publish(next: FreshnessSnap | null) {
      snap = next;
      if (next === null || typeof window === "undefined") return;
      if (tick !== null) return;
      tick = setInterval(() => {
        now = Date.now();
      }, 1_000);
    },
  };
}

export function chromeFreshness(): ChromeFreshness {
  instance ??= createFreshness();
  return instance;
}
