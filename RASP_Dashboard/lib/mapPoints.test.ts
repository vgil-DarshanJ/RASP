// Device Map helpers (Task 9.3). Runs with Node's own test runner and type
// stripping, no extra packages:  node --test lib/mapPoints.test.ts
// Real: lib/mapPoints.ts. Not covered: the Leaflet rendering (needs a browser).
import { test } from "node:test";
import assert from "node:assert/strict";

type MapPointsModule = typeof import("./mapPoints");
const { emptyMapMessage, markerColor, SEVERITY_COLOR, STALE_COLOR, timeAgo }: MapPointsModule = await import(
  new URL("./mapPoints.ts", import.meta.url).href
);

test("marker colour: green without threats, by severity otherwise, grey when stale", () => {
  assert.equal(markerColor({ severity: "none", stale: false }), SEVERITY_COLOR.none);
  assert.equal(SEVERITY_COLOR.none, "#16a34a");
  assert.equal(markerColor({ severity: "high", stale: false }), SEVERITY_COLOR.high);
  assert.equal(markerColor({ severity: "high", stale: true }), STALE_COLOR);
  assert.equal(markerColor({ severity: "none", stale: true }), STALE_COLOR);
  assert.equal(new Set(Object.values(SEVERITY_COLOR)).has(STALE_COLOR), false);
});

test("last seen as relative time", () => {
  const now = Date.UTC(2026, 9, 7, 12, 0, 0);
  const ago = (ms: number) => new Date(now - ms).toISOString();
  assert.equal(timeAgo(ago(20_000), now), "just now");
  assert.equal(timeAgo(ago(4 * 60_000), now), "4 min ago");
  assert.equal(timeAgo(ago(3 * 3_600_000), now), "3 h ago");
  assert.equal(timeAgo(ago(3 * 86_400_000), now), "3 d ago");
  assert.equal(timeAgo(ago(-5_000), now), "just now", "a clock slightly ahead is not 'in the future'");
});

test("empty state says whether devices exist without a shared location", () => {
  const period = "last 24 hours";
  assert.match(emptyMapMessage({ devicesReporting: 0, devicesWithLocation: 0 }, period, false), /^No device reported in the last 24 hours\./);
  assert.match(emptyMapMessage(null, period, false), /^No device reported/);
  assert.equal(
    emptyMapMessage({ devicesReporting: 2, devicesWithLocation: 0 }, period, false),
    "2 devices reported in the last 24 hours, but none shared its location. Location appears here only after the app user turns on Share location.",
  );
  assert.match(emptyMapMessage({ devicesReporting: 1, devicesWithLocation: 0 }, period, false), /^1 device reported/);
  assert.match(emptyMapMessage({ devicesReporting: 3, devicesWithLocation: 1 }, period, true), /^1 device shared a location .* none matches this severity\.$/);
});
