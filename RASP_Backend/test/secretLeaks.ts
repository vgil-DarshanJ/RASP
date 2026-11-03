// Finds secrets in an HTTP response body, two ways:
// 1. a field whose NAME is a secret field (api_secret, apiSecretEncrypted,
//    account_hash_salt, accountHashSalt, secret, secretEncrypted, password,
//    passwordHash, …) with a non-null value — unless the endpoint is allowed
//    to return it;
// 2. any known secret VALUE anywhere in the raw text (nested, renamed, in
//    an error message, in a CSV) — this also catches a leak under an
//    innocent-looking name.
// Fields named `…Masked` must hold a masked prefix ("abcd…") or null.
// Messages name the secret by label only, never by value.
import { isSecretFieldName } from "../src/security/secretFields";

export interface KnownSecret {
  label: string;
  value: string;
}

const SECRET_NAME_PATTERN = /^(api_?secret(_?encrypted)?|secret(_?encrypted)?|account_?hash_?salt|password(_?hash)?)$/i;
const MASKED_VALUE = /^[^…]{0,4}…$/;

export function isSecretFieldNameForTests(name: string): boolean {
  return SECRET_NAME_PATTERN.test(name) || isSecretFieldName(name);
}

export function findSecretLeaks(
  text: string,
  known: KnownSecret[],
  options: { allowedFields?: string[] } = {},
): string[] {
  const leaks: string[] = [];
  for (const secret of known) {
    if (secret.value.length > 0 && text.includes(secret.value)) leaks.push(`contains the ${secret.label}`);
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return leaks; // not JSON (CSV, HTML 404 page): only the value scan applies
  }
  const allowed = new Set(options.allowedFields ?? []);
  const walk = (value: unknown, path: string, inFieldErrors: boolean) => {
    if (Array.isArray(value)) {
      value.forEach((item, i) => walk(item, `${path}[${i}]`, inFieldErrors));
      return;
    }
    if (value === null || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      const childPath = `${path}.${key}`;
      // zod's `fieldErrors` maps a field name to its error MESSAGES.
      if (!inFieldErrors && isSecretFieldNameForTests(key) && !allowed.has(key) && child !== null && child !== undefined) {
        leaks.push(`${childPath} is a secret field`);
      }
      if (/masked$/i.test(key) && child !== null && !(typeof child === "string" && MASKED_VALUE.test(child))) {
        leaks.push(`${childPath} is not a masked prefix`);
      }
      walk(child, childPath, key === "fieldErrors");
    }
  };
  walk(body, "$", false);
  return leaks;
}
