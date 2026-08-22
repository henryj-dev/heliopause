import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { BASE_CSS, TOKENS_CSS } from "../../../../../src/design-tokens.ts";
import { SHELL_CSS } from "../../../../../src/app-shell.ts";

const dir = new URL("./", import.meta.url);

describe("web shell CSS is the same system the classic console paints", () => {
  it("keeps the token values, including the chrome sizes stardust uses", () => {
    const tokens = readFileSync(new URL("./tokens.css", dir), "utf8");
    assert.ok(tokens.includes(TOKENS_CSS), "tokens.css drifted from src/design-tokens.ts");
    assert.match(tokens, /--topbar-h:42px/);
    assert.match(tokens, /--sb-expanded:184px/);
  });

  it("keeps the table/button layer and the viewport shell", () => {
    const base = readFileSync(new URL("./base.css", dir), "utf8");
    const shell = readFileSync(new URL("./shell.css", dir), "utf8");
    assert.ok(base.includes(BASE_CSS), "base.css drifted from src/design-tokens.ts");
    assert.ok(shell.includes(SHELL_CSS), "shell.css drifted from src/app-shell.ts");
    assert.match(shell, /\.app-edge/);
    assert.match(shell, /grid-template-columns: var\(--sb-expanded\)/);
  });
});
