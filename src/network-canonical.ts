import { createHash } from "node:crypto";

/** Stable JSON for inventory evidence; deliberately independent of signed policy bundles.
 * Undefined object properties are omitted, matching optional JSON fields. No coercions,
 * custom serializers, sparse arrays or non-finite numbers may enter evidence hashes.
 */
export function canonicalNetworkJson(value: unknown): string {
  const ancestors = new Set<object>();
  function visit(current: unknown, depth: number): string {
    if (depth > 64) throw new Error("network evidence exceeds maximum depth");
    if (current === null) return "null";
    if (typeof current === "string" || typeof current === "boolean") return JSON.stringify(current);
    if (typeof current === "number") {
      if (!Number.isFinite(current)) throw new Error("network evidence requires finite numbers");
      return JSON.stringify(current);
    }
    if (typeof current !== "object") throw new Error("network evidence must be JSON");
    if (ancestors.has(current)) throw new Error("network evidence cannot contain cycles");
    const prototype = Object.getPrototypeOf(current);
    if (!Array.isArray(current) && prototype !== Object.prototype && prototype !== null) throw new Error("network evidence requires plain objects");
    if (Object.getOwnPropertySymbols(current).length) throw new Error("network evidence cannot contain symbol properties");
    ancestors.add(current);
    try {
      if (Array.isArray(current)) {
        if (Object.keys(current).length !== current.length) throw new Error("network evidence requires dense arrays without extra properties");
        const entries: string[] = [];
        for (let i = 0; i < current.length; i++) {
          const descriptor = Object.getOwnPropertyDescriptor(current, String(i));
          if (!descriptor || !("value" in descriptor)) throw new Error("network evidence requires dense arrays without accessors");
          entries.push(visit(descriptor.value, depth + 1));
        }
        return `[${entries.join(",")}]`;
      }
      const entries: string[] = [];
      for (const key of Object.keys(current).sort()) {
        const descriptor = Object.getOwnPropertyDescriptor(current, key)!;
        if (!("value" in descriptor)) throw new Error("network evidence cannot contain accessors");
        if (descriptor.value !== undefined) entries.push(`${JSON.stringify(key)}:${visit(descriptor.value, depth + 1)}`);
      }
      return `{${entries.join(",")}}`;
    } finally { ancestors.delete(current); }
  }
  return visit(value, 0);
}
export const networkDigest = (value: unknown): string => createHash("sha256").update(canonicalNetworkJson(value)).digest("hex");
