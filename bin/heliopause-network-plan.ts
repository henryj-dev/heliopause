#!/usr/bin/env node
/** Offline analysis only. This entry point has no publish/apply transport. */
import { buildNetworkChangeSet, type NetworkChangeSetInput } from "../src/network-change-set.ts";
import { readBoundedStoreFile } from "../src/json-store.ts";
import { buildNetworkPlan, type NetworkPlanInput } from "../src/network-planner.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();
const args = process.argv.slice(2);
const unified = args[0] === "--unified";
if (unified) args.shift();
if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
  console.log("Usage: node bin/heliopause-network-plan.ts [--unified] INPUT.json\nOffline dry-run only. INPUT includes id, registry, expectedRegistryRevision, observations, bindings and explicit now (epoch milliseconds). Outputs a versioned plan; exit 2 means blocked.");
} else if (args.length !== 1 || args[0]!.startsWith("-")) {
  console.error("Usage: node bin/heliopause-network-plan.ts INPUT.json");
  process.exitCode = 1;
} else {
  try {
    const value: unknown = JSON.parse(readBoundedStoreFile(args[0]!, 8 * 1024 * 1024));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("plan input must be an object");
    const input = value as Record<string, unknown>;
    const allowed = ["id", "registry", "expectedRegistryRevision", "observations", "bindings", "now", "maxAgeMs", "additionalDependencies", "managedScopes", ...(unified ? ["wireguard", "frr", "prefixPolicy", "expectedGenerations", "artifactAssertions", "operationDependencies", "generatedAt"] : [])];
    if (Object.keys(input).some(k => !allowed.includes(k))) throw new Error("unknown plan input field");
    const plan = unified ? buildNetworkChangeSet(input as unknown as NetworkChangeSetInput) : buildNetworkPlan(input as unknown as NetworkPlanInput);
    console.log(JSON.stringify(plan, null, 2));
    if (plan.blockers.length) process.exitCode = 2;
  } catch (error) {
    console.error(error instanceof Error ? error.message : "network planning failed");
    process.exitCode = 1;
  }
}
