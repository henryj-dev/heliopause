import type { PlanRow } from "./plans.ts";

export function hostRuleTotal(plan: PlanRow): number {
  return plan.summary.hosts.reduce((n, host) => n + host.ruleCount, 0);
}

/** 시안 B1: `sha256:9f31c0a4…7be2`. Short enough to sit next to the stage chip. */
export function shortPlanHash(hash: string): string {
  const hex = hash.startsWith("sha256:") ? hash.slice("sha256:".length) : hash;
  if (hex.length <= 12) return hash;
  return `sha256:${hex.slice(0, 8)}…${hex.slice(-4)}`;
}

/** Seconds left on the plan, from `proposedAt` — the clock the server sweeps. */
export function remainingSec(proposedAt: string, ttlSec: number, nowMs: number): number {
  const start = Date.parse(proposedAt);
  if (!Number.isFinite(start)) return 0;
  return Math.max(0, Math.floor((start + ttlSec * 1000 - nowMs) / 1000));
}

export function clockLabel(sec: number): string {
  const n = Math.max(0, Math.floor(sec));
  const minutes = Math.floor(n / 60);
  const seconds = n % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

export function expireTone(remaining: number): "ok" | "warn" | "bad" {
  if (remaining <= 60) return "bad";
  if (remaining <= 300) return "warn";
  return "ok";
}

export function expireRatio(remaining: number, ttlSec: number): number {
  if (ttlSec <= 0) return 0;
  return Math.min(1, Math.max(0, remaining / ttlSec));
}

export function planPath(hash: string): string {
  return `/changes/${encodeURIComponent(hash)}`;
}

export function planDomId(hash: string): string {
  return "plan-" + hash.replace(/[^a-z0-9]/gi, "");
}
