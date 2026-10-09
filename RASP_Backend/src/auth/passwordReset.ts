import crypto from "node:crypto";
import nodemailer from "nodemailer";
import { prisma } from "../db/prisma";
import { allowResetRequest } from "./loginGuard";

/**
 * "Forgot password" (POST /v1/auth/forgot-password, /reset-password).
 *
 * - The answer to a request is the same whether or not the email has an
 *   account, and is sent before anything is looked up, so the endpoint does
 *   not tell who has an account.
 * - A link carries 32 random bytes; only their SHA-256 is stored. It expires
 *   after 30 minutes, works once, and a newer request replaces it.
 * - Using it sets the new password, signs the account out everywhere
 *   (tokenVersion) and clears a login lockout.
 * - Delivery: e-mail over SMTP when SMTP_HOST is set. Without SMTP outside
 *   production (a development PC), the link is printed in the backend's
 *   terminal instead. In production without SMTP nothing is sent and an
 *   error is logged.
 */
export const RESET_TOKEN_TTL_MS = 30 * 60 * 1000;

export function hashResetToken(token: string): string {
  return crypto.createHash("sha256").update(token, "utf8").digest("hex");
}

/** The dashboard origin the link points at (DASHBOARD_URL; never taken from the request). */
export function dashboardUrl(): string {
  return (process.env.DASHBOARD_URL || "http://localhost:3000").trim().replace(/\/+$/, "");
}

export function resetLink(token: string): string {
  return `${dashboardUrl()}/reset-password?token=${encodeURIComponent(token)}`;
}

export interface ResetMailer {
  send(to: string, link: string): Promise<void>;
}

function smtpMailer(): ResetMailer {
  const port = Number(process.env.SMTP_PORT) || 587;
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: process.env.SMTP_SECURE === "1" || port === 465,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
  return {
    async send(to, link) {
      await transport.sendMail({
        from: process.env.MAIL_FROM || process.env.SMTP_USER,
        to,
        subject: "Reset your RASP Shield password",
        text:
          `Someone asked to reset the password of this RASP Shield account.\n\n` +
          `Open this link within 30 minutes to choose a new password:\n${link}\n\n` +
          `If you did not ask for it, ignore this e-mail; your password stays as it is.`,
      });
    },
  };
}

/** Development without SMTP: the link goes to this terminal (the person running the backend). */
const consoleMailer: ResetMailer = {
  async send(to, link) {
    console.log(`[password-reset] SMTP_HOST is not set (development): reset link for ${to}:\n${link}`);
  },
};

const disabledMailer: ResetMailer = {
  async send() {
    console.error("[password-reset] SMTP_HOST is not set; no reset e-mail was sent (production)");
  },
};

export function defaultMailer(): ResetMailer {
  if (process.env.SMTP_HOST) return smtpMailer();
  return process.env.NODE_ENV === "production" ? disabledMailer : consoleMailer;
}

/** Tests replace `mailer`; `lastJob` is the most recent background request (tests await it). */
export const passwordReset: { mailer: () => ResetMailer; lastJob: Promise<void> } = {
  mailer: defaultMailer,
  lastJob: Promise.resolve(),
};

/** Creates and sends a link when [email] has an account and is under its request limit. */
export async function issueResetLink(email: string, requestIp: string | undefined, now = new Date()): Promise<void> {
  if (!(await allowResetRequest(email))) return;
  const user = await prisma.user.findUnique({ where: { email }, select: { id: true, email: true } });
  if (!user) return;
  const token = crypto.randomBytes(32).toString("base64url");
  await prisma.$transaction([
    prisma.passwordResetToken.deleteMany({ where: { userId: user.id } }),
    prisma.passwordResetToken.create({
      data: { userId: user.id, tokenHash: hashResetToken(token), expiresAt: new Date(now.getTime() + RESET_TOKEN_TTL_MS), requestIp: requestIp ?? null },
    }),
  ]);
  await passwordReset.mailer().send(user.email, resetLink(token));
}

/**
 * Uses a link: the email of the account whose password was set, or null
 * when the token is unknown, expired or already used.
 */
export async function consumeResetToken(token: string, passwordHash: string, now = new Date()): Promise<string | null> {
  const row = await prisma.passwordResetToken.findUnique({
    where: { tokenHash: hashResetToken(token) },
    select: { id: true, userId: true, expiresAt: true },
  });
  if (!row) return null;
  if (row.expiresAt.getTime() <= now.getTime()) {
    await prisma.passwordResetToken.deleteMany({ where: { id: row.id } });
    return null;
  }
  return prisma.$transaction(async (tx) => {
    // Claim it: of two requests with the same link, only one deletes the row.
    const claimed = await tx.passwordResetToken.deleteMany({ where: { id: row.id } });
    if (claimed.count !== 1) return null;
    await tx.passwordResetToken.deleteMany({ where: { userId: row.userId } });
    const user = await tx.user.update({
      where: { id: row.userId },
      data: { passwordHash, tokenVersion: { increment: 1 } },
      select: { email: true },
    });
    return user.email;
  });
}
