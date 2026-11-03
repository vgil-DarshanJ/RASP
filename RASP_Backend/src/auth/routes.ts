import { Response, Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { AuthedRequest, requireAuth } from "../middleware/auth";
import { secondsUntilExpiry, signJwt } from "./jwt";
import { clearedSessionCookie, sessionCookie } from "./sessionCookie";
import {
  Blocked,
  checkAccountLock,
  checkIpLimit,
  clearAccountLock,
  recordLoginFailure,
  recordLoginSuccess,
} from "./loginGuard";
import { consumeResetToken, issueResetLink, passwordReset } from "./passwordReset";
import { logError } from "../security/secretFields";

export const authRouter = Router();

/** bcrypt cost for new password hashes; tests lower it with BCRYPT_ROUNDS. */
function bcryptRounds(): number {
  const rounds = Number(process.env.BCRYPT_ROUNDS);
  return Number.isInteger(rounds) && rounds >= 4 && rounds <= 15 ? rounds : 12;
}

function sendBlocked(res: Response, blocked: Blocked) {
  res.setHeader("Retry-After", String(blocked.retryAfterSeconds));
  return res.status(429).json(blocked);
}

/** Signs the session token and sets it as the httpOnly cookie; the token is also returned for API clients. */
function startSession(res: Response, user: { id: string; organizationId: string; role: string; tokenVersion: number }): string {
  const token = signJwt({ userId: user.id, organizationId: user.organizationId, role: user.role, tokenVersion: user.tokenVersion });
  res.setHeader("Set-Cookie", sessionCookie(token, secondsUntilExpiry(token)));
  return token;
}

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, "Password must be at least 8 characters"),
  organizationName: z.string().min(2).max(120),
});

/**
 * Creates a User AND its Organization together, in one transaction — this
 * platform has no "join an existing org by invite" flow yet (deferred, see
 * the plan's "explicitly deferred" section), so every registration is
 * necessarily a brand-new organization with this user as its OWNER.
 * Limited per client IP (see loginGuard.ts).
 */
authRouter.post("/register", async (req, res) => {
  const ipBlocked = await checkIpLimit("register", req.ip ?? "unknown");
  if (ipBlocked) return sendBlocked(res, ipBlocked);

  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_INPUT", details: parsed.error.flatten() });
  }
  const { email, password, organizationName } = parsed.data;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return res.status(409).json({ error: "EMAIL_ALREADY_REGISTERED" });
  }

  const passwordHash = await bcrypt.hash(password, bcryptRounds());

  const { user, organization } = await prisma.$transaction(async (tx) => {
    const organization = await tx.organization.create({
      data: { name: organizationName },
    });
    const user = await tx.user.create({
      data: {
        email,
        passwordHash,
        role: "OWNER",
        organizationId: organization.id,
      },
    });
    return { user, organization };
  });

  const token = startSession(res, { ...user, tokenVersion: user.tokenVersion ?? 0 });

  res.status(201).json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
    organization: { id: organization.id, name: organization.name },
  });
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

/**
 * Limited per client IP; repeated failures lock the email for a while
 * (429 ACCOUNT_TEMPORARILY_LOCKED, with Retry-After) — see loginGuard.ts.
 */
authRouter.post("/login", async (req, res) => {
  const ipBlocked = await checkIpLimit("login", req.ip ?? "unknown");
  if (ipBlocked) return sendBlocked(res, ipBlocked);

  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }
  const { email, password } = parsed.data;

  const locked = await checkAccountLock(email);
  if (locked) return sendBlocked(res, locked);

  const user = await prisma.user.findUnique({
    where: { email },
    include: { organization: true },
  });

  // Same generic error whether the email doesn't exist or the password is
  // wrong — never leak which one it was to an unauthenticated caller.
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    await recordLoginFailure(email);
    return res.status(401).json({ error: "INVALID_CREDENTIALS" });
  }
  await recordLoginSuccess(email);

  const token = startSession(res, { ...user, tokenVersion: user.tokenVersion ?? 0 });

  res.json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
    organization: { id: user.organization.id, name: user.organization.name },
  });
});

const forgotSchema = z.object({ email: z.string().email().max(320) });

/**
 * POST /v1/auth/forgot-password { email } → always 202 { ok: true }, sent
 * before any lookup, so the answer never tells whether the email has an
 * account. The link is created and delivered afterwards (see
 * passwordReset.ts). Limited per client IP and per email.
 */
authRouter.post("/forgot-password", async (req, res) => {
  const ipBlocked = await checkIpLimit("forgot", req.ip ?? "unknown");
  if (ipBlocked) return sendBlocked(res, ipBlocked);
  const parsed = forgotSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "INVALID_INPUT" });
  res.status(202).json({ ok: true });
  passwordReset.lastJob = issueResetLink(parsed.data.email, req.ip).catch((err) => logError("[password-reset]", err));
});

const resetSchema = z.object({
  token: z.string().min(20).max(200),
  password: z.string().min(8, "Password must be at least 8 characters").max(200),
});

/**
 * POST /v1/auth/reset-password { token, password } → 200 { ok: true }: the
 * new password is set, every session of the account ends and a lockout is
 * cleared. 400 INVALID_OR_EXPIRED_TOKEN for an unknown, expired or used link.
 */
authRouter.post("/reset-password", async (req, res) => {
  const ipBlocked = await checkIpLimit("reset", req.ip ?? "unknown");
  if (ipBlocked) return sendBlocked(res, ipBlocked);
  const parsed = resetSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "INVALID_INPUT", details: parsed.error.flatten() });
  const passwordHash = await bcrypt.hash(parsed.data.password, bcryptRounds());
  const email = await consumeResetToken(parsed.data.token, passwordHash);
  if (!email) return res.status(400).json({ error: "INVALID_OR_EXPIRED_TOKEN" });
  await clearAccountLock(email);
  res.json({ ok: true });
});

/** The signed-in user and organization — how the dashboard checks its cookie session. */
authRouter.get("/me", requireAuth, async (req: AuthedRequest, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user!.userId },
    include: { organization: true },
  });
  if (!user) return res.status(401).json({ error: "ACCOUNT_NOT_FOUND" });
  res.json({
    user: { id: user.id, email: user.email, role: user.role },
    organization: { id: user.organization.id, name: user.organization.name },
  });
});

/**
 * Signs the user out everywhere: raises `tokenVersion`, so every token issued
 * so far (this browser, other browsers, API scripts) is rejected with 401
 * TOKEN_REVOKED, and removes the session cookie.
 */
authRouter.post("/logout", requireAuth, async (req: AuthedRequest, res) => {
  await prisma.user.update({ where: { id: req.user!.userId }, data: { tokenVersion: { increment: 1 } } });
  res.setHeader("Set-Cookie", clearedSessionCookie());
  res.status(204).end();
});
