// Webhook destinations, signing and retries (F-08).
// Real: destination.ts (address policy, URL check, the guarded DNS lookup),
// deliver() over real HTTP to a local receiver, the HMAC signature.
// Doubles: DNS answers for checkDestination (destinationDns.resolve), the
// webhook config row (prisma.webhookConfig.update), the retry sleep.
import { test, describe, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { prisma } from "../src/db/prisma";
import { encryptSecret } from "../src/crypto/secretBox";
import { checkDestination, destinationDns, isBlockedAddress } from "../src/webhooks/destination";
import { deliver, signDelivery, webhookRetry, WebhookEventPayload } from "../src/webhooks/dispatch";

const ENV_KEYS = ["WEBHOOK_ALLOW_PRIVATE_DESTINATIONS", "NODE_ENV", "CREDENTIAL_ENCRYPTION_KEY"];
const saved: Record<string, string | undefined> = {};
before(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString("hex"); // throwaway test key
});
after(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});
beforeEach(() => {
  delete process.env.WEBHOOK_ALLOW_PRIVATE_DESTINATIONS;
  delete process.env.NODE_ENV;
});

describe("address policy", () => {
  test("private, loopback, link-local, metadata, CGNAT, documentation and multicast addresses are blocked", () => {
    for (const a of [
      "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.2.208", "169.254.169.254", "100.64.0.1",
      "0.0.0.0", "198.18.0.1", "203.0.113.9", "224.0.0.1", "255.255.255.255",
      "::1", "::", "fe80::1", "fd00::1", "fc12::3", "ff02::1", "2001:db8::1",
      "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:a9fe:a9fe", "64:ff9b::10.0.0.1", "not-an-ip",
    ]) assert.equal(isBlockedAddress(a), true, a);
  });

  test("public addresses are allowed", () => {
    for (const a of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]) {
      assert.equal(isBlockedAddress(a), false, a);
    }
  });
});

describe("checkDestination", () => {
  const originalResolve = destinationDns.resolve;
  after(() => {
    destinationDns.resolve = originalResolve;
  });
  const answers = (map: Record<string, string[]>) => {
    destinationDns.resolve = async (host) => {
      if (!(host in map)) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      return map[host].map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));
    };
  };

  test("a public https URL passes; http, user:password, private literals and private DNS answers do not", async () => {
    answers({ "hooks.bank.example": ["93.184.216.34"], "internal.bank.example": ["10.0.0.5"], "mixed.bank.example": ["93.184.216.34", "127.0.0.1"] });
    assert.equal(await checkDestination("https://hooks.bank.example/rasp"), null);
    assert.equal(await checkDestination("https://93.184.216.34/rasp"), null);
    assert.equal(await checkDestination("http://hooks.bank.example/rasp"), "WEBHOOK_URL_NOT_HTTPS");
    assert.equal(await checkDestination("ftp://hooks.bank.example/rasp"), "WEBHOOK_URL_NOT_HTTPS");
    assert.equal(await checkDestination("https://user:pw@hooks.bank.example/"), "WEBHOOK_URL_HAS_CREDENTIALS");
    assert.equal(await checkDestination("https://169.254.169.254/latest/meta-data"), "WEBHOOK_URL_PRIVATE_ADDRESS");
    assert.equal(await checkDestination("https://[::1]:8443/x"), "WEBHOOK_URL_PRIVATE_ADDRESS");
    assert.equal(await checkDestination("https://internal.bank.example/"), "WEBHOOK_URL_PRIVATE_ADDRESS");
    assert.equal(await checkDestination("https://mixed.bank.example/"), "WEBHOOK_URL_PRIVATE_ADDRESS", "any private answer blocks");
    assert.equal(await checkDestination("https://nowhere.bank.example/"), "WEBHOOK_URL_UNRESOLVABLE");
    assert.equal(await checkDestination("not a url"), "WEBHOOK_URL_INVALID");
  });

  test("the development override allows http and private addresses, but never with NODE_ENV=production", async () => {
    process.env.WEBHOOK_ALLOW_PRIVATE_DESTINATIONS = "1";
    assert.equal(await checkDestination("http://127.0.0.1:9000/hook"), null);
    process.env.NODE_ENV = "production";
    assert.equal(await checkDestination("http://127.0.0.1:9000/hook"), "WEBHOOK_URL_NOT_HTTPS");
    assert.equal(await checkDestination("https://127.0.0.1:9000/hook"), "WEBHOOK_URL_PRIVATE_ADDRESS");
  });
});

describe("deliver", () => {
  type Hit = { headers: http.IncomingHttpHeaders; body: string };
  let server: http.Server;
  let port = 0;
  let hits: Hit[] = [];
  let statuses: number[] = [];
  let updates: Array<Record<string, unknown>> = [];
  const webhookConfig = prisma.webhookConfig as unknown as Record<string, unknown>;
  const originalUpdate = webhookConfig.update;
  const originalSleep = webhookRetry.sleep;
  const slept: number[] = [];

  before(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        hits.push({ headers: req.headers, body });
        res.statusCode = statuses.shift() ?? 200;
        res.end("ok");
      });
    });
    server.listen(0, "127.0.0.1");
    await new Promise<void>((r) => server.once("listening", () => r()));
    port = (server.address() as AddressInfo).port;
    webhookConfig.update = async (args: { data: Record<string, unknown> }) => {
      updates.push(args.data);
      return {};
    };
    webhookRetry.sleep = async (ms) => {
      slept.push(ms);
    };
  });
  after(async () => {
    webhookConfig.update = originalUpdate;
    webhookRetry.sleep = originalSleep;
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  });
  beforeEach(() => {
    hits = [];
    statuses = [];
    updates = [];
    slept.length = 0;
  });

  const payload: WebhookEventPayload = {
    applicationId: "app-1", applicationName: "Bank App", detectorId: "root_jailbreak", severity: "critical", status: "DETECTED",
    deviceId: "d1", deviceModel: "Pixel", osPlatform: "android", receivedAt: new Date(0).toISOString(), evidence: [],
  };
  const url = () => `http://127.0.0.1:${port}/hook`;

  test("signs timestamp and body: v1=HMAC(secret, '<ts>.<body>'), with a delivery id", async () => {
    process.env.WEBHOOK_ALLOW_PRIVATE_DESTINATIONS = "1";
    const before = Math.floor(Date.now() / 1000);
    await deliver("wh-1", url(), encryptSecret("hook-secret"), payload);
    assert.equal(hits.length, 1);
    const h = hits[0].headers;
    const ts = Number(h["x-webhook-timestamp"]);
    assert.ok(ts >= before && ts <= before + 5);
    const expected = `v1=${crypto.createHmac("sha256", "hook-secret").update(`${ts}.${hits[0].body}`).digest("hex")}`;
    assert.equal(h["x-webhook-signature"], expected);
    assert.equal(signDelivery("hook-secret", Buffer.from(hits[0].body), ts), expected);
    assert.match(String(h["x-webhook-id"]), /^[0-9a-f-]{36}$/);
    assert.deepEqual(JSON.parse(hits[0].body), payload);
    assert.equal(updates[0].lastStatusCode, 200);
    assert.equal(updates[0].lastError, null);
  });

  test("5xx and 429 are retried (1 s, then 4 s) with the same delivery id and a fresh signature; 4xx is not", async () => {
    process.env.WEBHOOK_ALLOW_PRIVATE_DESTINATIONS = "1";
    statuses = [503, 429, 200];
    await deliver("wh-1", url(), encryptSecret("hook-secret"), payload);
    assert.equal(hits.length, 3);
    assert.deepEqual(slept, [1000, 4000]);
    assert.equal(new Set(hits.map((x) => x.headers["x-webhook-id"])).size, 1);
    assert.equal(updates[0].lastStatusCode, 200);

    hits = []; updates = []; slept.length = 0;
    statuses = [500, 500, 500];
    await deliver("wh-1", url(), encryptSecret("hook-secret"), payload);
    assert.equal(hits.length, 3);
    assert.equal(updates[0].lastError, "Non-2xx response: 500 (after 3 attempts)");

    hits = []; updates = []; slept.length = 0;
    statuses = [400];
    await deliver("wh-1", url(), encryptSecret("hook-secret"), payload);
    assert.equal(hits.length, 1, "a 4xx is the receiver's answer, not a transient failure");
    assert.equal(updates[0].lastStatusCode, 400);
  });

  test("without the override, a private or http destination is never contacted", async () => {
    await deliver("wh-1", url(), encryptSecret("hook-secret"), payload);
    assert.equal(hits.length, 0);
    assert.equal(updates[0].lastError, "Webhook URL must use https://");

    await deliver("wh-1", `https://127.0.0.1:${port}/hook`, encryptSecret("hook-secret"), payload);
    assert.equal(hits.length, 0);
    assert.equal(updates[1].lastError, "Destination is a private or reserved address");

    await deliver("wh-1", `https://localhost:${port}/hook`, encryptSecret("hook-secret"), payload);
    assert.equal(hits.length, 0);
    assert.match(String(updates[2].lastError), /private or reserved address/, "a name resolving to loopback is blocked at connect time");
    assert.deepEqual(slept, [], "a blocked destination is not retried");
  });
});
