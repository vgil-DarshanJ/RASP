import jwt from "jsonwebtoken";

export interface JwtPayload {
  userId: string;
  organizationId: string;
  role: string;
}

export function signJwt(payload: JwtPayload): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET not configured");
  const expiresIn = process.env.JWT_EXPIRES_IN || "7d";
  return jwt.sign(payload, secret, { expiresIn } as jwt.SignOptions);
}
