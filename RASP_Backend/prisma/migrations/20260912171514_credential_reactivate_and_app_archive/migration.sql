-- AlterEnum
ALTER TYPE "CredentialAuditAction" ADD VALUE 'REACTIVATED';

-- AlterTable
ALTER TABLE "applications" ADD COLUMN     "archivedAt" TIMESTAMP(3);
