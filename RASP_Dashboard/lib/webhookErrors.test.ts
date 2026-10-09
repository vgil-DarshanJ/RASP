// Real: webhookErrorMessage (pure function).
import { test } from "node:test";
import assert from "node:assert/strict";

type Module = typeof import("./webhookErrors");
const { webhookErrorMessage }: Module = await import(new URL("./webhookErrors.ts", import.meta.url).href);

test("known codes get a sentence; anything else the fallback", () => {
  assert.match(webhookErrorMessage("WEBHOOK_URL_NOT_HTTPS", "x"), /https:\/\//);
  assert.match(webhookErrorMessage("WEBHOOK_URL_PRIVATE_ADDRESS", "x"), /private/);
  assert.match(webhookErrorMessage("FORBIDDEN_ROLE", "x"), /owner or admin/);
  assert.equal(webhookErrorMessage("SOMETHING_ELSE", "fallback"), "fallback");
  assert.equal(webhookErrorMessage(undefined, "fallback"), "fallback");
});
