// Render a fixture site into `manifest.json` and `hosts/*.nft`, before anything is signed.
//
// ## Why the harnesses cannot just call heliopause-publish
//
// They need to publish something *wrong* — a generation whose manifest asks for a rule the ruleset
// does not contain, so the agent must refuse and roll back. They used to get that by publishing
// normally and then editing `manifest.json`.
//
// Editing a manifest after publication stopped working twice over. `heliopause-publish` now writes
// only `authorized-bundle.json` (there is no `manifest.json` left to edit), and even if there were,
// an edit after signing is exactly what the signature exists to catch. So the order changes: render
// here, edit, then sign with `e2e-authorize.mjs`. **The wrongness is authorized on purpose**, which
// is the only way to test what an agent does with a validly signed generation it cannot satisfy.
//
// This writes what `writePublish` writes and nothing else — no signing, no target, no expiry. Those
// belong to the authorization step, and keeping them apart is what lets a harness put something in
// between.
import { planPublish, writePublish } from "../src/publish.ts";

const [sitePath, outDir, generation] = process.argv.slice(2);
if (!sitePath || !outDir || !generation) {
  console.error("usage: e2e-render.mjs <site-module> <artifact-dir> <generation>");
  process.exit(64);
}

const mod = await import(sitePath);
if (!mod.site) {
  console.error(`${sitePath} does not export \`site\``);
  process.exit(65);
}
const site = mod.site;

const plan = planPublish({
  cfg: site.cfg,
  generation,
  // Fixed, not `new Date()`. A harness that stamped the current time would produce a different
  // artifact on every run, and the digests these tests compare are the point.
  issuedAt: "2026-01-01T00:00:00.000Z",
  hosts: site.hosts,
  ...(site.workload ? { workload: site.workload } : {}),
  ...(site.resolveService ? { resolveService: site.resolveService } : {}),
});
await writePublish(outDir, plan);
console.log(`rendered ${Object.keys(plan.manifest.hosts).length} host(s) as ${generation}`);
