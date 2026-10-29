#!/usr/bin/env node
/** Offline templates only; resolving secrets and applying them are separate future responsibilities. */
import { readBoundedStoreFile } from "../src/json-store.ts";
import { compileWireGuard } from "../src/network-wireguard.ts";
import { compileFrr } from "../src/network-frr.ts";
import { diffBgpFabricPlans, planBgpFabric, type BgpFabricPlan } from "../src/network-fabric.ts";
import type { NetworkRegistryDocument } from "../src/network-registry.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();
const [compiler, path, ...extra] = process.argv.slice(2);
if (compiler === "--help") {
  console.log("Usage: node bin/heliopause-network-compile.ts wireguard|frr|fabric INPUT.json\nOffline incomplete templates only; INPUT includes registry, expectedRegistryRevision and spec (fabric: fabricId and optional previous plan). No apply or secret resolution.");
} else if ((compiler !== "wireguard" && compiler !== "frr" && compiler !== "fabric") || !path || extra.length || path.startsWith("-")) {
  console.error("Usage: node bin/heliopause-network-compile.ts wireguard|frr|fabric INPUT.json");
  process.exitCode = 1;
} else {
  try {
    const input: unknown = JSON.parse(readBoundedStoreFile(path, 8 * 1024 * 1024));
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("compiler input must be an object");
    const value = input as Record<string, unknown>;
    if (compiler === "fabric") {
      if (Object.keys(value).some(k => !["registry", "expectedRegistryRevision", "fabricId", "previous"].includes(k))) throw new Error("unknown compiler input field");
      if (!value.registry || typeof value.registry !== "object" || Array.isArray(value.registry) || !Array.isArray((value.registry as Record<string, unknown>).resources)) throw new Error("compiler registry is required");
      if (typeof value.fabricId !== "string") throw new Error("fabricId is required");
      const result = planBgpFabric({ registry: value.registry as Pick<NetworkRegistryDocument, "revision" | "resources">, expectedRegistryRevision: value.expectedRegistryRevision as number, fabricId: value.fabricId });
      const previous = value.previous as BgpFabricPlan | undefined;
      if (previous !== undefined && (!previous || typeof previous !== "object" || previous.kind !== "bgp-fabric-plan" || !Array.isArray(previous.gateways))) throw new Error("previous must be a bgp-fabric-plan");
      console.log(JSON.stringify(result.ok ? { ...result, changes: diffBgpFabricPlans(previous ?? null, result.plan) } : result, null, 2));
      if (!result.ok) process.exitCode = 2;
    } else {
    const allowed = compiler === "wireguard" ? ["registry", "expectedRegistryRevision", "spec", "previous", "prefixPolicy"] : ["registry", "expectedRegistryRevision", "spec", "prefixPolicy"];
    if (Object.keys(value).some(k => !allowed.includes(k))) throw new Error("unknown compiler input field");
    if (!value.registry || typeof value.registry !== "object" || Array.isArray(value.registry) || !Array.isArray((value.registry as Record<string, unknown>).resources)) throw new Error("compiler registry is required");
    const args = value as unknown as { registry: Pick<NetworkRegistryDocument, "revision" | "resources">; expectedRegistryRevision: number; spec: unknown; previous?: unknown };
    const result = compiler === "wireguard" ? compileWireGuard({ ...args, prefixPolicy: value.prefixPolicy as import("../src/network-prefix-policy.ts").NetworkPrefixPolicy | undefined }) : compileFrr({ ...args, prefixPolicy: value.prefixPolicy as import("../src/network-prefix-policy.ts").NetworkPrefixPolicy | undefined });
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 2;
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : "network compilation failed");
    process.exitCode = 1;
  }
}
