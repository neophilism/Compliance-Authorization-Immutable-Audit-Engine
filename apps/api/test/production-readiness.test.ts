import assert from "node:assert/strict";
import test from "node:test";
import { buildApp } from "../src/app.js";

test("health and readiness expose distinct public probes", async () => {
  if (!process.env.DATABASE_URL) return;

  const app = await buildApp({
    securityMode: "enforce",
    runMigrations: false,
    corsOrigins: false,
    releaseSha: "test-release",
  });

  try {
    const health =
      await app.inject({
        method: "GET",
        url: "/health",
      });
    assert.equal(
      health.statusCode,
      200,
    );
    assert.equal(
      health.json().status,
      "ok",
    );
    assert.equal(
      health.json().release,
      "test-release",
    );

    const ready =
      await app.inject({
        method: "GET",
        url: "/ready",
      });
    assert.equal(
      ready.statusCode,
      200,
    );
    assert.equal(
      ready.json().status,
      "ready",
    );

    const openapi =
      await app.inject({
        method: "GET",
        url: "/openapi.json",
      });
    assert.equal(
      openapi.statusCode,
      200,
    );
    assert.ok(
      openapi.json()
        .paths["/ready"],
    );

    const origin =
      await app.inject({
        method: "GET",
        url: "/health",
        headers: {
          origin:
            "https://untrusted.example",
        },
      });
    assert.equal(
      origin.headers[
        "access-control-allow-origin"
      ],
      undefined,
    );
  } finally {
    await app.close();
  }
});
