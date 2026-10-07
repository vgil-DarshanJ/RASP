import crypto from "node:crypto";
import { prisma } from "../db/prisma";

/**
 * Per-application salt for account / session / beneficiary hashes. The SDK
 * computes hex(HMAC-SHA256(key = salt bytes (from hex), msg = UTF-8 id)), so
 * the backend only ever receives hashes, and the same customer id hashes
 * differently in two applications. Never logged; returned only in an issued
 * credential's JSON and by the OWNER/ADMIN reveal endpoint.
 */
export function generateAccountHashSalt(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function isAccountHashSalt(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

/** The hash the SDK sends for [id] — for tests and the dev seed script. */
export function accountHash(saltHex: string, id: string): string {
  return crypto.createHmac("sha256", Buffer.from(saltHex, "hex")).update(id, "utf8").digest("hex");
}

/** An application row without its salt — for every response that is not the credential download. */
export function withoutAccountHashSalt<T extends Record<string, unknown>>(app: T): Omit<T, "accountHashSalt"> {
  const { accountHashSalt: _salt, ...rest } = app;
  return rest;
}

/**
 * The application's salt, generating it first for an application created
 * before salts existed. The write only happens while the column is still
 * null, so two concurrent callers end up with the same salt. Generation is
 * audited (without the value).
 */
export async function ensureAccountHashSalt(
  applicationId: string,
  actor: { userId: string; ipAddress?: string },
): Promise<string> {
  const current = await prisma.application.findUnique({ where: { id: applicationId }, select: { accountHashSalt: true } });
  if (isAccountHashSalt(current?.accountHashSalt)) return current!.accountHashSalt!;

  const salt = generateAccountHashSalt();
  const written = await prisma.$transaction(async (tx) => {
    const updated = await tx.application.updateMany({
      where: { id: applicationId, accountHashSalt: null },
      data: { accountHashSalt: salt },
    });
    if (updated.count === 1) {
      await tx.applicationSettingsAuditLog.create({
        data: {
          applicationId,
          action: "ACCOUNT_HASH_SALT_GENERATED",
          field: "accountHashSalt",
          performedByUserId: actor.userId,
          ipAddress: actor.ipAddress,
        },
      });
    }
    return updated.count === 1;
  });
  if (written) return salt;
  const reread = await prisma.application.findUnique({ where: { id: applicationId }, select: { accountHashSalt: true } });
  if (!isAccountHashSalt(reread?.accountHashSalt)) throw new Error("account hash salt unavailable");
  return reread!.accountHashSalt!;
}
