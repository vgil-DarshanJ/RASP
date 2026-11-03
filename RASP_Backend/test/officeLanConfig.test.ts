import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/app";
import { allowedOrigins, isAllowedOrigin } from "../src/security/origins";

test("the office dashboard is allowed by the default CORS policy", () => {
  const previous = process.env.CORS_ORIGINS;
  delete process.env.CORS_ORIGINS;
  try {
    assert.deepEqual(allowedOrigins(), [
      "http://192.168.2.208:5050",
      "http://192.168.2.208:6050",
      "http://localhost:5050",
      "http://localhost:6050",
    ]);
    assert.equal(isAllowedOrigin("http://192.168.2.208:5050"), true);
    assert.equal(isAllowedOrigin("http://192.168.2.208:3000"), false);
  } finally {
    if (previous === undefined) delete process.env.CORS_ORIGINS;
    else process.env.CORS_ORIGINS = previous;
  }
});

test("the API returns credentialed CORS headers to the office dashboard", async () => {
  const previous = process.env.CORS_ORIGINS;
  delete process.env.CORS_ORIGINS;
  const server = createApp().listen(0, "127.0.0.1");
  try {
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const response = await fetch(`http://127.0.0.1:${address.port}/healthz`, {
      method: "OPTIONS",
      headers: {
        Origin: "http://192.168.2.208:5050",
        "Access-Control-Request-Method": "GET",
      },
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("access-control-allow-origin"), "http://192.168.2.208:5050");
    assert.equal(response.headers.get("access-control-allow-credentials"), "true");
  } finally {
    if (previous === undefined) delete process.env.CORS_ORIGINS;
    else process.env.CORS_ORIGINS = previous;
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
