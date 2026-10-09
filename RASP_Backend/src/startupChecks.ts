/**
 * Configuration checks before the server starts (F-18). Returns the
 * problems; the caller refuses to start when there are any. Never includes
 * a secret's value in a message.
 *
 * - DATABASE_URL, REDIS_URL, JWT_SECRET, CREDENTIAL_ENCRYPTION_KEY are set.
 * - CREDENTIAL_ENCRYPTION_KEY is exactly 64 hex characters (32 bytes);
 *   before, a wrong key surfaced only on the first credential request.
 * - With NODE_ENV=production: JWT_SECRET has at least 32 characters, and
 *   neither secret is a placeholder from the example files.
 */
export function configurationProblems(env: NodeJS.ProcessEnv = process.env): string[] {
  const problems: string[] = [];
  for (const key of ["DATABASE_URL", "REDIS_URL", "JWT_SECRET", "CREDENTIAL_ENCRYPTION_KEY"]) {
    if (!env[key]) problems.push(`${key} is not set`);
  }
  const key = env.CREDENTIAL_ENCRYPTION_KEY;
  if (key && !/^[0-9a-fA-F]{64}$/.test(key)) {
    problems.push("CREDENTIAL_ENCRYPTION_KEY must be exactly 64 hex characters (openssl rand -hex 32)");
  }
  if (env.NODE_ENV === "production") {
    const jwt = env.JWT_SECRET ?? "";
    if (jwt && jwt.length < 32) problems.push("JWT_SECRET must have at least 32 characters in production");
    for (const name of ["JWT_SECRET", "CREDENTIAL_ENCRYPTION_KEY"]) {
      if (/replace|change[-_ ]?me|example|placeholder/i.test(env[name] ?? "")) {
        problems.push(`${name} still holds a placeholder value`);
      }
    }
  }
  return problems;
}
