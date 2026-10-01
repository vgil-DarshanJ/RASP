import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

export interface AuthedRequest extends Request {
  user?: { userId: string; organizationId: string; role: string };
}

/**
 * Verifies the `Authorization: Bearer <jwt>` header issued by
 * `POST /v1/auth/login`. Never trusts a request's own claim of identity
 * without verifying the signature — a forged/expired/malformed token is
 * rejected with 401, never silently treated as anonymous-but-allowed.
 */
export function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "MISSING_TOKEN" });
  }
  const token = header.slice("Bearer ".length);
  try {
    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error("JWT_SECRET not configured");
    const payload = jwt.verify(token, secret) as {
      userId: string;
      organizationId: string;
      role: string;
    };
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "INVALID_TOKEN" });
  }
}
