-- AlterEnum
ALTER TYPE "CredentialAuditAction" ADD VALUE 'DELETED';

-- AlterTable
ALTER TABLE "api_credentials" ADD COLUMN     "deletedAt" TIMESTAMP(3),
ADD COLUMN     "label" TEXT;
