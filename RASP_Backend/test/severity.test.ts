// Severity table entries for detectors added in Tasks 3a-3c.
// Real: src/detectors/severity.ts (pure functions, no I/O).
import { test } from "node:test";
import assert from "node:assert/strict";
import { DETECTOR_SEVERITY, severityOf, weightOf } from "../src/detectors/severity";

const NEW_DETECTORS: Record<string, string> = {
  mock_location: "high",
  time_spoofing: "medium",
  unsafe_wifi: "medium",
  screen_recording: "high",
  vishing_call: "high",
  sim_change: "high",
  third_party_keyboard: "medium",
  task_hijack: "high",
  device_state_attestation: "high",
  malware_reputation: "critical",
};

test("new detector ids have an explicit severity (not the 'low' fallback)", () => {
  for (const [id, severity] of Object.entries(NEW_DETECTORS)) {
    assert.equal(DETECTOR_SEVERITY[id], severity, id);
    assert.equal(severityOf(id), severity, id);
  }
  assert.equal(weightOf("mock_location"), 25);
  assert.equal(weightOf("time_spoofing"), 12);
});
