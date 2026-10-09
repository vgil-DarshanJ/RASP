import { NextFunction, Request, Response } from "express";
import { prisma } from "../db/prisma";
import { TokenClaims, verifyJwt } from "../auth/jwt";
import { readSessionCookie } from "../auth/sessionCookie";
import { isAllowedOrigin } from "../security/origins";

export interface AuthedRequest extends Request {
  user?: { userId: string; organizationId: string; role: string };
}

/**
 * The account a token names, as it is in the database now; `null` when the
 * user no longer exists. Tests replace `find`.
 */
export const authAccounts: {
  find: (claims: TokenClaims) => Promise<{ organizationId: string; role: string; tokenVersion?: number } | null>;
} = {
  find: (claims) =>
    prisma.user.findUnique({
      where: { id: claims.userId },
      select: { organizationId: true, role: true, tokenVersion: true },
    }),
};

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Authenticates a dashboard request by the JWT from `POST /v1/auth/login`,
 * taken from `Authorization: Bearer <jwt>` or, for the dashboard, from the
 * httpOnly session cookie. Never trusts a request's own claim of identity
 * without verifying the signature — a forged/expired/malformed token, or one
 * signed with any algorithm other than HS256, is rejected with 401.
 *
 * A validly signed token is also checked against the database: when its
 * user no longer exists, or is no longer in the token's organization (a
 * reset database, a token from another backend with the same JWT secret, a
 * deleted user), the answer is 401 ACCOUNT_NOT_FOUND and the dashboard
 * signs out — instead of every write failing later on a foreign key. The
 * role is taken from the database, so a role change applies at once.
 * A token issued before the user's last sign-out (`tokenVersion` raised by
 * `POST /v1/auth/logout`) is 401 TOKEN_REVOKED.
 *
 * Cookie-authenticated requests that change data must carry an `Origin`
 * from CORS_ORIGINS (403 ORIGIN_NOT_ALLOWED otherwise): browsers attach
 * cookies to requests other sites trigger, so the origin is what tells a
 * dashboard action from a forged one. Bearer requests need no such check —
 * no browser adds that header on its own.
 */
export async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  let token: string | null = null;
  let viaCookie = false;
  if (header?.startsWith("Bearer ")) {
    token = header.slice("Bearer ".length);
  } else {
    token = readSessionCookie(req);
    viaCookie = token !== null;
  }
  if (!token) {
    return res.status(401).json({ error: "MISSING_TOKEN" });
  }
  if (viaCookie && UNSAFE_METHODS.has(req.method) && !isAllowedOrigin(req.headers.origin)) {
    return res.status(403).json({ error: "ORIGIN_NOT_ALLOWED" });
  }

  let claims: TokenClaims;
  try {
    claims = verifyJwt(token);
  } catch {
    return res.status(401).json({ error: "INVALID_TOKEN" });
  }
  if (typeof claims.userId !== "string" || typeof claims.organizationId !== "string") {
    return res.status(401).json({ error: "INVALID_TOKEN" });
  }

  let account: { organizationId: string; role: string; tokenVersion?: number } | null;
  try {
    account = await authAccounts.find(claims);
  } catch {
    return res.status(503).json({ error: "AUTH_BACKEND_UNAVAILABLE" });
  }
  if (!account || account.organizationId !== claims.organizationId) {
    return res.status(401).json({ error: "ACCOUNT_NOT_FOUND" });
  }
  if ((claims.tv ?? 0) !== (account.tokenVersion ?? 0)) {
    return res.status(401).json({ error: "TOKEN_REVOKED" });
  }
  req.user = { userId: claims.userId, organizationId: account.organizationId, role: account.role };
  next();
}
