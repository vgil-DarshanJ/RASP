// F-18: the server refuses to start with missing or malformed secrets.
// Real: configurationProblems and configurationWarnings (pure).
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { configurationProblems, configurationWarnings } from "../src/startupChecks";

const good = {
  DATABASE_URL: "postgresql://x", REDIS_URL: "redis://x",
  JWT_SECRET: "j".repeat(48), CREDENTIAL_ENCRYPTION_KEY: "ab".repeat(32),
};

test("a complete configuration passes, in development and production", () => {
  assert.deepEqual(configurationProblems(good), []);
  assert.deepEqual(configurationProblems({ ...good, NODE_ENV: "production" }), []);
});

test("missing values and a malformed encryption key are reported without their values", () => {
  const problems = configurationProblems({ ...good, REDIS_URL: "", CREDENTIAL_ENCRYPTION_KEY: "abc123" });
  assert.deepEqual(problems, ["REDIS_URL is not set", "CREDENTIAL_ENCRYPTION_KEY must be exactly 64 hex characters (openssl rand -hex 32)"]);
  assert.ok(!problems.join(" ").includes("abc123"));
});

test("production: short or placeholder secrets are refused", () => {
  assert.deepEqual(configurationProblems({ ...good, NODE_ENV: "production", JWT_SECRET: "short" }), ["JWT_SECRET must have at least 32 characters in production"]);
  assert.deepEqual(
    configurationProblems({ ...good, NODE_ENV: "production", JWT_SECRET: "replace-me-with-a-long-random-value-0123456789" }),
    ["JWT_SECRET still holds a placeholder value"],
  );
  assert.deepEqual(configurationProblems({ ...good, JWT_SECRET: "short" }), [], "development accepts a short dev secret");
});

test("CONFIG_SIGNING_KEY missing or malformed is a warning (remote config off), never its value", () => {
  assert.deepEqual(configurationWarnings({}), ["CONFIG_SIGNING_KEY is not set: remote configuration is off (npm run config:keygen)"]);
  const ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
  const warnings = configurationWarnings({ CONFIG_SIGNING_KEY: ec });
  assert.deepEqual(warnings, ["CONFIG_SIGNING_KEY is not a Base64 Ed25519 PKCS#8 key: remote configuration is off (npm run config:keygen)"]);
  assert.ok(!warnings.join(" ").includes(ec.slice(0, 20)));
  const ed = (crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64");
  assert.deepEqual(configurationWarnings({ CONFIG_SIGNING_KEY: ed }), []);
  assert.deepEqual(configurationProblems({ ...good }), [], "the server still starts without it");
});
