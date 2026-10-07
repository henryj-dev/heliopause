// Does `vm` release the module graph? That is #89's body, and `docs/policy-evaluation-realm-design.md`
// §4 left worker-vs-vm open because this was never measured. It is measured now, and §4-a/§4-b hold
// the numbers this script prints.
//
//   node --expose-gc --experimental-vm-modules scripts/measure-realm-memory.mjs [evals] [condition]
//   node --expose-gc --experimental-vm-modules scripts/measure-realm-memory.mjs --retention [iters]
//
// Four conditions, one fixture, the accounting §1 uses (two forced GCs plus a macrotask yield before
// each sample, heapUsed and rss side by side):
//
//   current    `import("path?v=stamp")` in this realm            — the leak #89 reports
//   worker     one `worker_threads` worker per evaluation        — §1-b's worker row
//   vm-script  `new vm.Script(src).runInContext(fresh context)`  — no ESM, so the JSON is INLINED
//   vm-module  `vm.SourceTextModule` in a fresh context          — the shape a policy module needs
//
// `vm-script` measures the same amount of code rather than the same shape, and the report has to say
// so — it cannot import, so it is not a policy module.
//
// `--retention` answers the follow-up question: is the growth this loop holding something, or the
// context, or the module? It drops one thing at a time (§4-b). Without that split, "vm leaks" is a
// claim about my harness as much as about `vm`.
//
// This is a measurement, not a regression test. It takes a fixture size and a flag, and #89 asks for
// the regression ("heap after N evaluations, by count rather than wall clock") to land WITH the
// implementation — so nothing here runs in CI.
import vm from "node:vm";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import { writeFileSync, mkdirSync, readFileSync, mkdtempSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { registerHooks } from "node:module";

// The fixture is generated, so it goes to a temp directory rather than beside this script. The first
// version wrote `scripts/fixture/` into the checkout, where it showed up as untracked and would have
// been committed along with the measurement.
//
// 🔴 `realpathSync`, and the reason is measured: ESM resolution realpaths module URLs, so a child
// specifier resolves to `/private/var/folders/…` on macOS while `mkdtempSync` hands back
// `/var/folders/…`. Without this the hook's root check never matched, the hook versioned **nothing**,
// and the hook-on row came out 0.008 MB from hook-off — a difference small enough to read as "the
// hook costs nothing" instead of "the hook never ran". A counter on the hook caught it.
const DIR = new URL(`file://${realpathSync(mkdtempSync(join(tmpdir(), "realm-fixture-")))}/`);
const SITE = new URL("./site.mjs", DIR).pathname;

if (!isMainThread) {
  const mod = await import(`${pathToFileURL(workerData.site).href}?v=${workerData.stamp}`);
  parentPort.postMessage({ entries: mod.site.entries.length });
} else {
  await main();
}

async function main() {
  const N = Number(process.argv[2] ?? 40);

  // Same fixture shape as the #89 measurements: a JSON file of ~0.19 MB and a module of ~0.13 MB
  // that imports it, so the numbers are comparable to what the design records.
  mkdirSync(DIR, { recursive: true });
  const rows = [];
  for (let i = 0; i < 540; i++) {
    rows.push({
      id: `POLICY-${String(i).padStart(4, "0")}`,
      desc: `synthetic rule ${i} standing in for a real policy entry with a comparable comment length`,
      proto: i % 2 ? "tcp" : "udp",
      ports: `${1000 + i}`,
      srcCidrs: ["10.0.0.0/8", "10.254.0.0/16"],
      tags: ["synthetic", "fixture", `group-${i % 7}`],
    });
  }
  const json = JSON.stringify({ groups: { synthetic: rows } }, null, 2);
  writeFileSync(new URL("./policies.json", DIR), json);

  let body = `import data from "./policies.json" with { type: "json" };\n\n`;
  for (let i = 0; i < 1080; i++) {
    body += `const entry${i} = { id: "E${i}", desc: "synthetic declaration ${i} kept live by the export below", ports: "${2000 + i}" };\n`;
  }
  body += `\nexport const site = {\n  cfg: { internalSupernet: "10.0.0.0/8" },\n  hosts: [{ id: "h-01.synthetic", stage: "canary", items: [] }],\n  data,\n  entries: [${Array.from({ length: 1080 }, (_, i) => `entry${i}`).join(", ")}],\n};\n`;
  writeFileSync(new URL("./site.mjs", DIR), body);

  // A plain-script variant: `vm.Script` cannot import, so the JSON is inlined instead. It measures a
  // different thing and the report has to say so.
  const scriptSrc =
    `const data = ${json};\n` + body.split("\n").slice(2).join("\n").replace(/^export const site =/m, "globalThis.site =");

  const settle = async () => {
    for (let i = 0; i < 2; i++) {
      globalThis.gc();
      await new Promise((r) => setTimeout(r, 0));
    }
    return process.memoryUsage();
  };

  // ## The child-version hook, because without it `current` is not today's renderer
  //
  // `bin/heliopause-policy-render.ts:499` versions every child specifier the entry module pulls in,
  // so each evaluation re-instantiates the children too. §1-b measures that as the difference between
  // "지금 (자식까지 버전 — #59·#63)" and "자식 버전 훅 OFF (#59 이전 동작)".
  //
  // 🔴 The first version of this script versioned only the entry URL and called the row `current`. It
  // was the hook-OFF condition, and §4-a compared `vm` against it while claiming to compare against
  // the renderer. A review measured that. `registerHooks` cannot be removed once installed, so the
  // flag below decides whether it does anything, and the two rows run in one process.
  // Counted, not assumed: "the hook is installed" and "the hook versioned something" are different
  // claims, and the row is worthless without the second. The first corrected run of this script put
  // hook-on and hook-off within 0.008 MB of each other, which is what a hook that never fires looks
  // like — so the count is printed beside the row.
  let versioned = 0;
  let hookOn = false;
  registerHooks({
    resolve(specifier, context, nextResolve) {
      const result = nextResolve(specifier, context);
      if (!hookOn || !context.parentURL) return result;
      const v = new URL(context.parentURL).searchParams.get("v");
      if (v === null) return result;
      const url = new URL(result.url);
      if (url.protocol !== "file:" || url.searchParams.has("v")) return result;
      if (url.pathname.includes("/node_modules/")) return result;
      if (!url.pathname.startsWith(DIR.pathname)) return result;
      url.searchParams.set("v", v);
      versioned += 1;
      return { ...result, url: url.href };
    },
  });

  // Each runner returns the value a caller would hold on to. The table reads a count off it and drops
  // it; `--retention` keeps it. Returning the count itself — which this script did at first — makes
  // the "holds the namespace" control hold a number instead, so both controls hold nothing and the
  // split §4-b claims to measure does not happen. A review measured that too.
  const runners = {
    async "current-hook-on"(stamp) {
      hookOn = true;
      try {
        return await import(`${pathToFileURL(SITE).href}?v=${stamp}`);
      } finally {
        hookOn = false;
      }
    },
    async "current-hook-off"(stamp) {
      return await import(`${pathToFileURL(SITE).href}?v=${stamp}`);
    },
    worker(stamp) {
      return new Promise((ok, fail) => {
        const w = new Worker(new URL(import.meta.url), { workerData: { site: SITE, stamp } });
        w.once("message", (m) => w.terminate().then(() => ok(m), fail));
        w.once("error", fail);
      });
    },
    async "vm-script"(stamp) {
      const ctx = vm.createContext({});
      new vm.Script(`${scriptSrc}\nglobalThis.__stamp = ${JSON.stringify(stamp)};`).runInContext(ctx, { timeout: 30_000 });
      return ctx;
    },
    async "vm-module"(stamp) {
      const ctx = vm.createContext({});
      const src = readFileSync(SITE, "utf8");
      const m = new vm.SourceTextModule(src, { context: ctx, identifier: `site-${stamp}` });
      await m.link(async (spec) => {
        // The JSON import. A real linker would resolve relative to the module; this one answers the
        // single specifier the fixture uses.
        if (!spec.endsWith("policies.json")) throw new Error(`unexpected specifier ${spec}`);
        const j = new vm.SyntheticModule(["default"], function () {
          this.setExport("default", vm.runInContext(`(${json})`, ctx));
        }, { context: ctx, identifier: `json-${stamp}` });
        return j;
      });
      await m.evaluate({ timeout: 30_000 });
      return m.namespace;
    },
  };

  // How many entries the held value exposes — proof the evaluation ran, printed beside each row. It
  // reads through whichever shape that condition returns rather than assuming one.
  const countOf = (held) =>
    held?.site?.entries?.length ?? held?.entries ?? "?";

  const MB = (b) => (b / 1024 / 1024).toFixed(2);

  // §4-b: three controls over the same evaluation, each keeping less than the one before. If
  // `dropped` still grows, this loop holding a reference is not the cause.
  //
  // ⚠️ What it does NOT establish is what the retained bytes are. A flat `ctx-only` says an empty
  // context is collected; it does not rule out the module evaluation path retaining its context too.
  // This comment said "what is retained is the module graph" — the same inference §4-b retracted,
  // left behind here when the document was narrowed. Measuring the kind needs heap-snapshot
  // retainers, which this script does not take.
  if (process.argv.includes("--retention")) {
    const iters = Number(process.argv[process.argv.indexOf("--retention") + 1] ?? 60);
    for (const mode of ["held", "dropped", "ctx-only"]) {
      let keep = null;
      const base = (await settle()).heapUsed;
      for (let i = 1; i <= iters; i++) {
        if (mode === "ctx-only") {
          vm.runInContext("1 + 1", vm.createContext({}));
        } else {
          const got = await runners["vm-module"](`${mode}-${i}`);
          keep = mode === "held" ? got : null;
        }
      }
      const end = (await settle()).heapUsed;
      console.log(
        `${mode.padEnd(9)} ${String(iters).padStart(3)} iters  heap +${MB(end - base).padStart(7)} MB` +
        `   ${((end - base) / iters / 1024 / 1024).toFixed(3)} MB/iter   (keep ${keep === null ? "null" : "namespace"})`,
      );
    }
    return;
  }

  const which = process.argv[3] ? [process.argv[3]] : Object.keys(runners);

  for (const name of which) {
    let held = null;
    const base = await settle();
    let ok = 0;
    let failure = "";
    for (let i = 1; i <= N; i++) {
      try {
        held = await runners[name](`stamp-${name}-${i}`);
        ok += 1;
      } catch (e) {
        failure = `${e.constructor.name}: ${String(e.message).slice(0, 90)}`;
        break;
      }
    }
    const end = await settle();
    const per = (k) => ((end[k] - base[k]) / ok / 1024 / 1024).toFixed(3);
    if (!ok) {
      console.log(`${name.padEnd(10)} FAILED on the first evaluation — ${failure}`);
      continue;
    }
    console.log(
      `${name.padEnd(17)} ${String(ok).padStart(3)} evals  heapUsed ${per("heapUsed").padStart(7)} MB/eval` +
      `   rss ${per("rss").padStart(7)} MB/eval   total heap ${MB(end.heapUsed - base.heapUsed).padStart(7)} MB` +
      (failure ? `   stopped: ${failure}` : "") +
      `   (entries ${countOf(held)}` +
      (name === "current-hook-on" ? `, child specifiers versioned ${versioned}` : "") +
      `)`,
    );
  }
}
