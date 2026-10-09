// A throwaway copy of a site's policy directory with one data file replaced, for the render-diff
// preview. The renderer evaluates the copy in a worker and deletes it.
//
// What is copied: the regular files directly in the site module's directory, except dot files.
// Subdirectories are not copied — a site module that imports from one would fail to evaluate in the
// copy, which the preview reports as a failure rather than guessing. `../src` and `../bin` are
// symlinks to the renderer's own, so the copy imports the code this process runs.
// @see src/policy-preview.test.ts

import {
  copyFileSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { MAX_PREVIEW_BYTES } from "./preview-limits.ts";

export { MAX_PREVIEW_BYTES };

export class PreviewRefused extends Error {}

export interface PreviewCopy {
  /** The site module's path inside the copy. */
  sitePath: string;
  files: number;
  bytes: number;
  ms: number;
  /** Removes the whole copy. Safe to call more than once. */
  remove(): void;
}

/**
 * Refuses anything but a JSON object or array in a file the console may edit.
 *
 * `allowPaths` is the renderer's list; `path` must be one of its entries exactly, end in `.json`,
 * and name a file directly beside the site module.
 */
export function checkEdit(path: string, content: string, allowPaths: readonly string[]): void {
  if (!allowPaths.includes(path)) throw new PreviewRefused(`not an editable file: ${JSON.stringify(path)}`);
  if (!path.endsWith(".json")) throw new PreviewRefused("only JSON data can be previewed");
  if (basename(path) !== path || path.startsWith(".")) throw new PreviewRefused("the path must name a file beside the site module");
  if (Buffer.byteLength(content, "utf8") > MAX_PREVIEW_BYTES) {
    throw new PreviewRefused(`the edited file exceeds ${MAX_PREVIEW_BYTES} bytes`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new PreviewRefused("the edited file is not JSON");
  }
  if (typeof parsed !== "object" || parsed === null) throw new PreviewRefused("the edited file must be a JSON object or array");
}

/**
 * Copy `sitePath`'s directory into a fresh temporary directory, replace `path` with `content`, and
 * link `src` and `bin` from `codeRoot`.
 *
 * `codeRoot` is the directory holding the renderer's `src` and `bin`. Throws `PreviewRefused` from
 * `checkEdit` before touching the disk.
 */
export function makePreviewCopy(input: {
  sitePath: string;
  path: string;
  content: string;
  allowPaths: readonly string[];
  codeRoot: string;
}): PreviewCopy {
  checkEdit(input.path, input.content, input.allowPaths);
  const started = performance.now();
  const from = dirname(resolve(input.sitePath));
  const root = mkdtempSync(join(tmpdir(), "hp-preview-"));
  let removed = false;
  const remove = (): void => {
    if (removed) return;
    removed = true;
    rmSync(root, { recursive: true, force: true });
  };
  try {
    const to = join(root, "policy");
    mkdirSync(to);
    let files = 0;
    let bytes = 0;
    for (const name of readdirSync(from)) {
      if (name.startsWith(".")) continue;
      const src = join(from, name);
      const st = statSync(src);
      if (!st.isFile()) continue;
      copyFileSync(src, join(to, name));
      files += 1;
      bytes += st.size;
    }
    writeFileSync(join(to, input.path), input.content);
    symlinkSync(resolve(input.codeRoot, "src"), join(root, "src"));
    symlinkSync(resolve(input.codeRoot, "bin"), join(root, "bin"));
    const sitePath = join(to, basename(input.sitePath));
    if (!sitePath.startsWith(root + sep)) throw new PreviewRefused("the site module is outside the copy");
    return { sitePath, files, bytes, ms: performance.now() - started, remove };
  } catch (e) {
    remove();
    throw e;
  }
}
