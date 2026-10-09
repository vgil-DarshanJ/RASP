import jwt from "jsonwebtoken";

export interface JwtPayload {
  userId: string;
  organizationId: string;
  role: string;
  /** `users.tokenVersion` when the token was issued; raising it revokes every older token. */
  tokenVersion: number;
}

/** Claims as read back from a verified token. `tv` is absent in tokens issued before revocation existed. */
export interface TokenClaims {
  userId: string;
  organizationId: string;
  role: string;
  tv?: number;
  exp?: number;
}

/** The only algorithm accepted (F-11): a token naming any other one, including `none`, is rejected. */
export const JWT_ALGORITHM = "HS256" as const;

/** Session length when JWT_EXPIRES_IN is unset — one working day, not a week. */
export const DEFAULT_JWT_EXPIRES_IN = "8h";

function secret(): string {
  const value = process.env.JWT_SECRET;
  if (!value) throw new Error("JWT_SECRET not configured");
  return value;
}

export function signJwt(payload: JwtPayload): string {
  const expiresIn = process.env.JWT_EXPIRES_IN || DEFAULT_JWT_EXPIRES_IN;
  const claims = { userId: payload.userId, organizationId: payload.organizationId, role: payload.role, tv: payload.tokenVersion };
  return jwt.sign(claims, secret(), { algorithm: JWT_ALGORITHM, expiresIn } as jwt.SignOptions);
}

/** Verifies signature, algorithm and expiry; throws on any failure. */
export function verifyJwt(token: string): TokenClaims {
  return jwt.verify(token, secret(), { algorithms: [JWT_ALGORITHM] }) as TokenClaims;
}

/** Seconds until the token expires (for the session cookie's Max-Age); 0 when it has no expiry. */
export function secondsUntilExpiry(token: string, nowMs = Date.now()): number {
  const decoded = jwt.decode(token) as { exp?: number } | null;
  if (!decoded?.exp) return 0;
  return Math.max(0, Math.floor(decoded.exp - nowMs / 1000));
}
