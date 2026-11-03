// The exported severities JSON is exactly the canonical table (F-26).
import { test } from "node:test";
import assert from "node:assert/strict";
import { severitiesJson } from "../scripts/export-severities";
import { DETECTOR_SEVERITY } from "../src/detectors/severity";

test("export contains every detector with its canonical severity", () => {
  const out = JSON.parse(severitiesJson()) as { severities: Record<string, string> };
  assert.deepEqual(out.severities, DETECTOR_SEVERITY);
  assert.equal(out.severities.tamper_signing_mismatch, "high");
});
