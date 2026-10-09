/**
 * One CSV cell: always quoted, inner quotes doubled.
 *
 * A text cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return
 * gets a leading `'`, so a spreadsheet opening the export shows it as text
 * instead of running it as a formula (F-07). Values come from devices and
 * from the SDK (device model, evidence), so they are untrusted.
 */
export function csvField(value: unknown): string {
  if (value === null || value === undefined) return "";
  let str = typeof value === "string" ? value : JSON.stringify(value);
  if (/^[=+\-@\t\r]/.test(str)) str = `'${str}`;
  return `"${str.replace(/"/g, '""')}"`;
}
