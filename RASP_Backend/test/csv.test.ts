// Real: csvField, the cell encoder of the dashboard CSV export.
import { test } from "node:test";
import assert from "node:assert/strict";
import { csvField } from "../src/dashboard/csv";

test("cells are quoted with inner quotes doubled; empty for null", () => {
  assert.equal(csvField("Pixel 9"), '"Pixel 9"');
  assert.equal(csvField('say "hi"'), '"say ""hi"""');
  assert.equal(csvField(null), "");
  assert.equal(csvField(undefined), "");
  assert.equal(csvField({ a: 1 }), '"{""a"":1}"');
});

test("formula starters get a leading apostrophe (F-07)", () => {
  for (const s of ["=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd"]) {
    assert.equal(csvField(s), `"'${s.replace(/"/g, '""')}"`, JSON.stringify(s));
  }
  assert.equal(csvField("a=b"), '"a=b"', "only a leading character matters");
});
