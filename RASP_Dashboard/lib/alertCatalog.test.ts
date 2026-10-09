// F-26: the catalog's severities equal the canonical backend table.
// Real: ALERT_CATALOG and the exported copy lib/detectorSeverities.json
// (BE: npm run export:severities). When the backend checkout sits next to
// this one (../BE), the copy is also compared with BE/src/detectors/severity.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

type CatalogModule = typeof import("./alertCatalog");
const { ALERT_CATALOG }: CatalogModule = await import(new URL("./alertCatalog.ts", import.meta.url).href);
const copy = JSON.parse(readFileSync(new URL("./detectorSeverities.json", import.meta.url), "utf8")) as { severities: Record<string, string> };

test("every detector of the backend table has a catalog entry with the same severity", () => {
  for (const [id, severity] of Object.entries(copy.severities)) {
    assert.ok(ALERT_CATALOG[id], `catalog has no entry for ${id}`);
    assert.equal(ALERT_CATALOG[id].severity, severity, id);
  }
  for (const id of Object.keys(ALERT_CATALOG)) assert.ok(copy.severities[id], `${id} is not in the backend table`);
});

const backendTable = new URL("../../BE/src/detectors/severity.ts", import.meta.url);
test("the copy matches the backend table", { skip: !existsSync(backendTable) && "backend checkout not next to this one" }, () => {
  // Read as text: the backend is a CommonJS TypeScript project.
  const source = readFileSync(backendTable, "utf8");
  const start = source.indexOf("DETECTOR_SEVERITY");
  const table = source.slice(start, source.indexOf("};", start));
  const be: Record<string, string> = {};
  for (const m of table.matchAll(/^\s+([a-z_]+): "(critical|high|medium|low)",/gm)) be[m[1]] = m[2];
  assert.ok(Object.keys(be).length > 40, "parsed the backend table");
  assert.deepEqual(copy.severities, Object.fromEntries(Object.entries(be).sort(([a], [b]) => a.localeCompare(b))));
});
