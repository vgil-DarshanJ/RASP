/**
 * Browser origins allowed to call this API with credentials: CORS_ORIGINS,
 * comma-separated, each entry trimmed (a space after a comma used to make
 * that origin silently fail to match). Default: the local dashboard.
 */
export function allowedOrigins(): string[] {
  return (process.env.CORS_ORIGINS || "http://localhost:3000")
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
}

/** `true` when [origin] is one of [allowedOrigins]. */
export function isAllowedOrigin(origin: string | undefined): boolean {
  return origin !== undefined && allowedOrigins().includes(origin);
}
