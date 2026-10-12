// Ingestion URL in issued credentials and the credentials list (Task 4.10
// item 4). Real: publicIngestionUrl and the source of src/credentials/routes.ts.
// Not exercised: the Express routes themselves (they need Postgres).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DEFAULT_INGESTION_URL, publicIngestionUrl } from "../src/credentials/ingestionUrl";

describe("public ingestion URL", () => {
  test("PUBLIC_INGESTION_URL is used when set", () => {
    assert.equal(
      publicIngestionUrl({ PUBLIC_INGESTION_URL: "https://api.example.com/v1/events" }),
      "https://api.example.com/v1/events",
    );
  });

  test("unset or blank falls back to the office-LAN backend URL", () => {
    assert.equal(DEFAULT_INGESTION_URL, "http://192.168.2.208:4444/v1/events");
    assert.equal(publicIngestionUrl({}), DEFAULT_INGESTION_URL);
    assert.equal(publicIngestionUrl({ PUBLIC_INGESTION_URL: "  " }), DEFAULT_INGESTION_URL);
  });

  test("the credentials routes have no hard-coded address and both use the helper", () => {
    const source = fs.readFileSync(path.join(__dirname, "..", "src", "credentials", "routes.ts"), "utf8");
    assert.equal(/\b\d{1,3}(\.\d{1,3}){3}:\d+/.test(source), false, "no hard-coded IP:port");
    assert.equal(source.includes("process.env.PUBLIC_INGESTION_URL"), false);
    assert.equal(source.match(/publicIngestionUrl\(\)/g)?.length, 2);
  });
});
