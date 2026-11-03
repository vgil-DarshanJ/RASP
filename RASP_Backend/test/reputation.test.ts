// Signed malware reputation list for the SDK (GET /v1/reputation/list).
// Real: payload validation, Ed25519 signing (node:crypto), the file cache,
// the public key put into credentials. The route itself is covered by the
// leak scan (test/secretExposure.test.ts).
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { currentList, payloadText, reputationPublicKey, resetReputationCacheForTests } from "../src/reputation/reputationList";

const saved: Record<string, string | undefined> = {};
let dir = "";
let file = "";
const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const PRIVATE_B64 = (privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64");
const PUBLIC_B64 = (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");

before(() => {
  for (const k of ["REPUTATION_LIST_PATH", "REPUTATION_SIGNING_KEY"]) saved[k] = process.env[k];
  dir = mkdtempSync(path.join(os.tmpdir(), "rasp-reputation-"));
  file = path.join(dir, "list.json");
});
after(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  rmSync(dir, { recursive: true, force: true });
});
beforeEach(() => {
  resetReputationCacheForTests();
  process.env.REPUTATION_LIST_PATH = file;
  process.env.REPUTATION_SIGNING_KEY = PRIVATE_B64;
});

const write = (value: unknown, mtime?: Date) => {
  writeFileSync(file, JSON.stringify(value));
  if (mtime) utimesSync(file, mtime, mtime);
};

test("the served list verifies with the public key, exactly as the SDK checks it", () => {
  write({ version: 4, entries: [{ package: "com.bad.trojan", category: "banking_trojan", severity: "critical" }] });
  const r = currentList();
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(r.version, 4);
  assert.equal(r.entries, 1);
  assert.equal(JSON.parse(r.list.payload).entries[0].package, "com.bad.trojan");
  assert.ok(crypto.verify(null, Buffer.from(r.list.payload, "utf8"), crypto.createPublicKey({ key: Buffer.from(PUBLIC_B64, "base64"), format: "der", type: "spki" }), Buffer.from(r.list.signature, "base64")));
  assert.equal(reputationPublicKey(), PUBLIC_B64, "the key credentials carry");
});

test("a changed file is re-read and re-signed", () => {
  write({ version: 1, entries: [] }, new Date("2026-10-01T00:00:00Z"));
  assert.equal((currentList() as { version: number }).version, 1);
  write({ version: 2, entries: [] }, new Date("2026-10-02T00:00:00Z"));
  assert.equal((currentList() as { version: number }).version, 2);
});

test("not configured → REPUTATION_LIST_NOT_CONFIGURED; unusable file → REPUTATION_LIST_INVALID", () => {
  delete process.env.REPUTATION_SIGNING_KEY;
  assert.deepEqual(currentList(), { ok: false, error: "REPUTATION_LIST_NOT_CONFIGURED" });
  assert.equal(reputationPublicKey(), null);
  process.env.REPUTATION_SIGNING_KEY = PRIVATE_B64;
  process.env.REPUTATION_LIST_PATH = path.join(dir, "missing.json");
  assert.deepEqual(currentList(), { ok: false, error: "REPUTATION_LIST_NOT_CONFIGURED" });
  process.env.REPUTATION_LIST_PATH = file;
  write({ version: "1", entries: [] });
  resetReputationCacheForTests();
  assert.deepEqual(currentList(), { ok: false, error: "REPUTATION_LIST_INVALID" });
  process.env.REPUTATION_SIGNING_KEY = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
  assert.deepEqual(currentList(), { ok: false, error: "REPUTATION_LIST_NOT_CONFIGURED" }, "only an Ed25519 key is used");
});

test("payload rules: integer version, entries with real package names; extra fields dropped", () => {
  assert.equal(payloadText({ version: 1, entries: [{ package: "com.a.b", category: "x", note: "dropped" }] }), '{"version":1,"entries":[{"package":"com.a.b","category":"x"}]}');
  assert.equal(payloadText({ version: 1.5, entries: [] }), null);
  assert.equal(payloadText({ version: 1, entries: [{ package: "not a package" }] }), null);
  assert.equal(payloadText({ version: 1, entries: [{ package: "nodots" }] }), null);
  assert.equal(payloadText({ version: 1 }), null);
});
