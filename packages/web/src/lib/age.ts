/** Seconds as `2s` / `2m 14s` / `1h 3m` — the 시안 A4 wording. */
export function ageLabel(sec: number): string {
  const n = Math.max(0, Math.floor(sec));
  if (n < 60) return `${n}s`;
  const minutes = Math.floor(n / 60);
  const seconds = n % 60;
  if (minutes < 60) return seconds === 0 ? `${minutes}m` : `${minutes}m ${seconds}s`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest === 0 ? `${hours}h` : `${hours}h ${rest}m`;
}
