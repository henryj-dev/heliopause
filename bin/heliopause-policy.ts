#!/usr/bin/env node
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  emptyPolicyDocument,
  loadPolicyDocument,
  putPolicy,
  removePolicy,
  replacePolicyPlacements,
  savePolicyDocument,
  type PolicyPlacement,
} from "../src/policy-store.ts";
import { placementsFromSite, policiesFromSite, type PolicyBearingSite } from "../src/site-policy.ts";
import type { EndpointKind, Policy, PolicyAction, Proto, DenyMode } from "../src/policy.ts";

import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();
const args = process.argv.slice(2);
const positional = args.filter((a) => !a.startsWith("--"));
const flags = new Map(args.filter((a) => a.startsWith("--")).map((a) => {
  const [key, ...rest] = a.slice(2).split("=");
  return [key!, rest.length ? rest.join("=") : "true"];
}));
const [command, file, id] = positional;

const usage = `usage:
  heliopause-policy init <file>
  heliopause-policy export-site <site-module> <file>
  heliopause-policy list <file> [--json]
  heliopause-policy get <file> <id> [--json]
  heliopause-policy validate <file>
  heliopause-policy put <file> <id> --name=TEXT --src-kind=KIND [--src-value=VALUE]
      --dst-kind=KIND [--dst-value=VALUE] --proto=tcp|udp|icmp|any --ports=SPEC
      --action=allow|deny [--deny-mode=drop|reject] [--priority=N] [--disabled]
  heliopause-policy delete <file> <id>
  heliopause-policy placement-add <file> <id> --layer=input|egress|workload [--host=HOST]
      [--src-cidrs=CIDR,...] [--dst-cidrs=CIDR,...|--internet]
  heliopause-policy placement-clear <file> <id>

KIND is host|host-group|cidr|object|internet|any|k8s-service|k8s-namespace|
k8s-label|k8s-entity|geofeed. Use host-group for a named group such as cloudflare.`;

const required = (name: string): string => {
  const value = flags.get(name);
  if (value === undefined || value === "") throw new Error(`--${name} is required`);
  return value;
};

const printPolicy = (p: Policy): void => {
  console.log(
    `${p.id}\t${p.enabled ? "enabled" : "disabled"}\t${p.action}\t` +
      `${p.src.kind}:${p.src.value || "*"} -> ${p.dst.kind}:${p.dst.value || "*"}\t` +
      `${p.proto}/${p.ports || "*"}\t${p.name}`,
  );
};
const cidrs = (name: string): string[] => (flags.get(name) ?? "").split(",").map((value) => value.trim()).filter(Boolean);

try {
  if (!command || !file || args.includes("--help")) throw new Error(usage);

  if (command === "init") {
    if (existsSync(file)) throw new Error(`refusing to overwrite existing policy document: ${file}`);
    savePolicyDocument(file, emptyPolicyDocument());
    console.log(`created ${file}`);
  } else if (command === "export-site") {
    if (!id) throw new Error(usage);
    if (existsSync(id)) throw new Error(`refusing to overwrite existing policy document: ${id}`);
    const mod = (await import(pathToFileURL(resolve(file)).href)) as { site?: PolicyBearingSite };
    if (!mod.site) throw new Error(`${file} does not export \`site\``);
    const policies = policiesFromSite(mod.site);
    savePolicyDocument(id, { schemaVersion: 2, policies, placements: placementsFromSite(mod.site) });
    console.log(`created ${id} from ${policies.length} site policies`);
  } else if (command === "list") {
    const doc = loadPolicyDocument(file);
    if (flags.has("json")) console.log(JSON.stringify(doc, null, 2));
    else doc.policies.forEach(printPolicy);
  } else if (command === "get") {
    if (!id) throw new Error(usage);
    const policy = loadPolicyDocument(file).policies.find((p) => p.id === id);
    if (!policy) throw new Error(`policy ${JSON.stringify(id)} does not exist`);
    if (flags.has("json")) console.log(JSON.stringify(policy, null, 2));
    else printPolicy(policy);
  } else if (command === "validate") {
    const doc = loadPolicyDocument(file);
    console.log(`valid schema=${doc.schemaVersion} policies=${doc.policies.length} placements=${doc.placements?.length ?? "site-module"}`);
  } else if (command === "put") {
    if (!id) throw new Error(usage);
    const action = required("action") as PolicyAction;
    const policy: Policy = {
      id,
      name: required("name"),
      src: { kind: required("src-kind") as EndpointKind, value: flags.get("src-value") ?? "" },
      dst: { kind: required("dst-kind") as EndpointKind, value: flags.get("dst-value") ?? "" },
      proto: required("proto") as Proto,
      ports: flags.get("ports") ?? "",
      action,
      denyMode: (flags.get("deny-mode") ?? "drop") as DenyMode,
      priority: Number(flags.get("priority") ?? "100"),
      enabled: !flags.has("disabled"),
      notes: flags.get("notes") ?? "",
    };
    const current = existsSync(file) ? loadPolicyDocument(file) : emptyPolicyDocument();
    const result = putPolicy(current, policy);
    savePolicyDocument(file, result.document);
    console.log(`${result.created ? "created" : "updated"} ${id}`);
  } else if (command === "delete") {
    if (!id) throw new Error(usage);
    savePolicyDocument(file, removePolicy(loadPolicyDocument(file), id));
    console.log(`deleted ${id}`);
  } else if (command === "placement-add") {
    if (!id) throw new Error(usage); const document = loadPolicyDocument(file); const layer = required("layer");
    let placement: PolicyPlacement;
    if (layer === "input") placement = { layer, policyId: id, host: required("host"), srcCidrs: cidrs("src-cidrs"), dstCidrs: cidrs("dst-cidrs") };
    else if (layer === "egress") placement = { layer, policyId: id, host: required("host"), dstCidrs: flags.has("internet") ? null : cidrs("dst-cidrs") };
    else if (layer === "workload") placement = { layer, policyId: id, ...(flags.has("src-cidrs") ? { srcCidrs: cidrs("src-cidrs") } : {}), ...(flags.has("dst-cidrs") ? { dstCidrs: cidrs("dst-cidrs") } : {}) };
    else throw new Error("--layer must be input, egress or workload");
    const current = document.placements?.filter((item) => item.policyId === id) ?? [];
    savePolicyDocument(file, replacePolicyPlacements(document, id, [...current, placement])); console.log(`added ${layer} placement for ${id}`);
  } else if (command === "placement-clear") {
    if (!id) throw new Error(usage); const document = loadPolicyDocument(file);
    savePolicyDocument(file, replacePolicyPlacements(document, id, [])); console.log(`cleared placements for ${id}`);
  } else {
    throw new Error(usage);
  }
} catch (e) {
  console.error((e as Error).message);
  process.exitCode = 2;
}
