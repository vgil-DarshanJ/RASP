/**
 * Writes the canonical detector severities (src/detectors/severity.ts) as
 * JSON, for the copies the dashboard and the Flutter plugin test against
 * (F-26: one source, checked copies).
 *
 *   npm run export:severities -- <file> [<file> ...]
 *
 * Typical targets: ../FE/lib/detectorSeverities.json and
 * ../../sdk_rasp/flutter/rasp_shield_sdk/test/fixtures/detector_severities.json
 */
import { writeFileSync } from "node:fs";
import { DETECTOR_SEVERITY } from "../src/detectors/severity";

export function severitiesJson(): string {
  const sorted = Object.fromEntries(Object.entries(DETECTOR_SEVERITY).sort(([a], [b]) => a.localeCompare(b)));
  return `${JSON.stringify({ source: "BE/src/detectors/severity.ts", severities: sorted }, null, 2)}\n`;
}

if (require.main === module) {
  const targets = process.argv.slice(2);
  if (targets.length === 0) {
    process.stdout.write(severitiesJson());
  } else {
    for (const target of targets) {
      writeFileSync(target, severitiesJson());
      console.log(`wrote ${target}`);
    }
  }
}
