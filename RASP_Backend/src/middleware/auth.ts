import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { prisma } from "../db/prisma";

export interface AuthedRequest extends Request {
  user?: { userId: string; organizationId: string; role: string };
}

interface TokenClaims {
  userId: string;
  organizationId: string;
  role: string;
}

/**
 * The account a token names, as it is in the database now; `null` when the
 * user no longer exists. Tests replace `find`.
 */
export const authAccounts: {
  find: (claims: TokenClaims) => Promise<{ organizationId: string; role: string } | null>;
} = {
  find: (claims) =>
    prisma.user.findUnique({ where: { id: claims.userId }, select: { organizationId: true, role: true } }),
};

/**
 * Verifies the `Authorization: Bearer <jwt>` header issued by
 * `POST /v1/auth/login`. Never trusts a request's own claim of identity
 * without verifying the signature — a forged/expired/malformed token is
 * rejected with 401, never silently treated as anonymous-but-allowed.
 *
 * A validly signed token is also checked against the database: when its
 * user no longer exists, or is no longer in the token's organization (a
 * reset database, a token from another backend with the same JWT secret, a
 * deleted user), the answer is 401 ACCOUNT_NOT_FOUND and the dashboard
 * signs out — instead of every write failing later on a foreign key. The
 * role is taken from the database, so a role change applies at once.
 */
export async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "MISSING_TOKEN" });
  }
  const token = header.slice("Bearer ".length);
  let claims: TokenClaims;
  try {
    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error("JWT_SECRET not configured");
    claims = jwt.verify(token, secret) as TokenClaims;
  } catch {
    return res.status(401).json({ error: "INVALID_TOKEN" });
  }
  if (typeof claims.userId !== "string" || typeof claims.organizationId !== "string") {
    return res.status(401).json({ error: "INVALID_TOKEN" });
  }

  let account: { organizationId: string; role: string } | null;
  try {
    account = await authAccounts.find(claims);
  } catch {
    return res.status(503).json({ error: "AUTH_BACKEND_UNAVAILABLE" });
  }
  if (!account || account.organizationId !== claims.organizationId) {
    return res.status(401).json({ error: "ACCOUNT_NOT_FOUND" });
  }
  req.user = { userId: claims.userId, organizationId: account.organizationId, role: account.role };
  next();
}
