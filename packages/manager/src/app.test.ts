import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { app } from "./app.ts";

describe("manager Hono scaffold", () => {
  it("answers /healthz without authentication", async () => {
    const res = await app.request("https://127.0.0.1/healthz");
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
  });

  it("does not serve the live manager surface", async () => {
    const res = await app.request("https://127.0.0.1/site");
    assert.equal(res.status, 404);
  });
});
