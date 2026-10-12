/**
 * Browser origins allowed to call this API with credentials: CORS_ORIGINS,
 * comma-separated, each entry trimmed (a space after a comma used to make
 * that origin silently fail to match). Defaults to this project's office
 * dashboard origin and localhost for same-machine development.
 */
export function allowedOrigins(): string[] {
  return (process.env.CORS_ORIGINS || "http://192.168.2.208:5555,http://localhost:5555")
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
}

/** `true` when [origin] is one of [allowedOrigins]. */
export function isAllowedOrigin(origin: string | undefined): boolean {
  return origin !== undefined && allowedOrigins().includes(origin);
}
