import { writeFileSync } from "node:fs";
import { planBgpFabric } from "../../src/network-fabric.ts";
import * as lab from "../../examples/network-fabric-lab.ts";

const [output, version] = process.argv.slice(2);
if (!output || (version !== "8.5.6" && version !== "10.2.1")) throw new Error("usage: build.ts OUTPUT.json 8.5.6|10.2.1");
const resources = lab.fabricLabInventory();
const result = planBgpFabric({ registry: { revision: 1, resources }, expectedRegistryRevision: 1, fabricId: "fabric" });
if (!result.ok) throw new Error(result.diagnostics.join("; "));
// Everything the runner needs besides the plan is derived from the same synthetic helpers.
const sites = Array.from({ length: lab.FABRIC_LAB_SITES }, (_, i) => ({
  block: lab.fabricLabBlock(i), gatewayLan: lab.fabricLabGatewayLan(i), clientLan: lab.fabricLabClientLan(i),
  native: lab.fabricLabNativeAddress(i), external: lab.fabricLabExternalAddress(i), endpoint: lab.fabricLabEndpoint(i),
  placeholderKey: lab.fabricLabPlaceholderKey(i), vip: lab.fabricLabVip(i),
}));
writeFileSync(output, JSON.stringify({ frrVersion: version, clusterSite: lab.FABRIC_LAB_CLUSTER_SITE, sites, plan: result.plan }, null, 2));
