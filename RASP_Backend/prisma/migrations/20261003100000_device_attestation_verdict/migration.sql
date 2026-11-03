-- AlterTable
ALTER TABLE "device_registrations" ADD COLUMN     "attestationVerdict" TEXT NOT NULL DEFAULT 'unverified';

