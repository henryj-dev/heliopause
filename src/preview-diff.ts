// What each host accepts on its input hook, and what an edit changes about that.
//
// A preview, not a gate: nothing here refuses anything. The gates are the zone check and the
// approval path.
//
// It reads the planned ruleset (`planHostRuleset`), not the policy catalogue, because the source a
// host matches on is `srcCidrs`, which a site module computes per host — a catalogue entry can say
// one range while the host renders another.

import { defineConfig, type Config } from "./config.ts";
import { planHostRuleset, type PlannedRule } from "./nft.ts";
import type { ScreenSite } from "./policy-screen.ts";

/** One accepted input flow: a protocol, a port list as written, and the sources it is open to. */
export interface OpenPort {
  proto: string;
  ports: string;
  /** Source CIDRs, sorted. Empty means any source. */
  sources: string[];
}

export interface HostOpenings {
  host: string;
  open: OpenPort[];
}

export interface HostDiff {
  host: string;
  added: OpenPort[];
  removed: OpenPort[];
}

/** The accepted input rules of a planned ruleset, keyed so two plans can be compared. */
export function openPortsOf(input: readonly PlannedRule[]): OpenPort[] {
  const out: OpenPort[] = [];
  for (const rule of input) {
    if (rule.verdict !== "accept") continue;
    let proto = "";
    let ports = "";
    const sources: string[] = [];
    for (const m of rule.matches) {
      if (m.kind === "dport") {
        proto = m.proto;
        ports = m.ports.join(",");
      } else if (m.kind === "l4proto" && !proto) {
        proto = m.proto;
      } else if (m.kind === "saddr") {
        sources.push(...m.cidrs);
      }
    }
    // Conntrack, loopback and other port-less accepts are not a port a host offers.
    if (!ports) continue;
    out.push({ proto, ports, sources: [...new Set(sources)].sort() });
  }
  return out.sort((a, b) => keyOf(a).localeCompare(keyOf(b)));
}

const keyOf = (o: OpenPort): string => `${o.proto}/${o.ports} <- ${o.sources.join(",") || "any"}`;

/** Every host's openings for one site, as the agent would apply them. */
export function siteOpenings(site: ScreenSite): HostOpenings[] {
  const cfg: Config = defineConfig(site.cfg as Partial<Config>);
  const hosts = (site.hosts ?? []) as readonly {
    id: string;
    items?: Parameters<typeof planHostRuleset>[2];
    egress?: Parameters<typeof planHostRuleset>[3];
  }[];
  return hosts.map((h) => ({
    host: h.id,
    open: openPortsOf(planHostRuleset(cfg, h.id, h.items ?? [], h.egress ?? []).input),
  }));
}

/** Per host, what the edited site opens that the current one does not, and the reverse. */
export function diffOpenings(current: readonly HostOpenings[], edited: readonly HostOpenings[]): HostDiff[] {
  const before = new Map(current.map((h) => [h.host, new Map(h.open.map((o) => [keyOf(o), o]))]));
  const after = new Map(edited.map((h) => [h.host, new Map(h.open.map((o) => [keyOf(o), o]))]));
  const hosts = [...new Set([...before.keys(), ...after.keys()])].sort();
  const out: HostDiff[] = [];
  for (const host of hosts) {
    const b = before.get(host) ?? new Map<string, OpenPort>();
    const a = after.get(host) ?? new Map<string, OpenPort>();
    const added = [...a].filter(([k]) => !b.has(k)).map(([, o]) => o);
    const removed = [...b].filter(([k]) => !a.has(k)).map(([, o]) => o);
    if (added.length || removed.length) out.push({ host, added, removed });
  }
  return out;
}
