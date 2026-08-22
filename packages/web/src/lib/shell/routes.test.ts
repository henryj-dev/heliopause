import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(path));
    else if (entry.name.endsWith("+page.svelte")) out.push(path);
  }
  return out;
}

describe("the route wrappers", () => {
  it("do not paint an English screen name above the console", () => {
    const root = fileURLToPath(new URL("../../routes", import.meta.url));
    const pages = walk(root);
    assert.ok(pages.length >= 7, "the walk missed the console screens");
    for (const file of pages) {
      const text = readFileSync(file, "utf8");
      assert.doesNotMatch(text, /<h1>/, file);
    }
  });
});
