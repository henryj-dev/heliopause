#!/usr/bin/env node
/** Offline templates only; resolving secrets and applying them are separate future responsibilities. */
import { readBoundedStoreFile } from "../src/json-store.ts";
import { compileWireGuard } from "../src/network-wireguard.ts";
import { compileFrr } from "../src/network-frr.ts";
import type { NetworkRegistryDocument } from "../src/network-registry.ts";

const [compiler, path, ...extra] = process.argv.slice(2);
if (compiler === "--help") {
  console.log("Usage: node bin/heliopause-network-compile.ts wireguard|frr INPUT.json\nOffline incomplete templates only; INPUT includes registry, expectedRegistryRevision and spec. No apply or secret resolution.");
} else if ((compiler !== "wireguard" && compiler !== "frr") || !path || extra.length || path.startsWith("-")) {
  console.error("Usage: node bin/heliopause-network-compile.ts wireguard|frr INPUT.json");
  process.exitCode = 1;
} else {
  try {
    const input: unknown = JSON.parse(readBoundedStoreFile(path, 8 * 1024 * 1024));
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("compiler input must be an object");
    const value = input as Record<string, unknown>;
    const allowed = compiler === "wireguard" ? ["registry", "expectedRegistryRevision", "spec", "previous"] : ["registry", "expectedRegistryRevision", "spec"];
    if (Object.keys(value).some(k => !allowed.includes(k))) throw new Error("unknown compiler input field");
    if (!value.registry || typeof value.registry !== "object" || Array.isArray(value.registry) || !Array.isArray((value.registry as Record<string, unknown>).resources)) throw new Error("compiler registry is required");
    const args = value as unknown as { registry: Pick<NetworkRegistryDocument, "revision" | "resources">; expectedRegistryRevision: number; spec: unknown; previous?: unknown };
    const result = compiler === "wireguard" ? compileWireGuard(args) : compileFrr(args);
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 2;
  } catch (error) {
    console.error(error instanceof Error ? error.message : "network compilation failed");
    process.exitCode = 1;
  }
}
