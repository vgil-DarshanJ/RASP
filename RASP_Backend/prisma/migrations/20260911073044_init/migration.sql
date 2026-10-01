-- CreateEnum
CREATE TYPE "Role" AS ENUM ('OWNER', 'ADMIN', 'MEMBER');

-- CreateEnum
CREATE TYPE "Platform" AS ENUM ('ANDROID_NATIVE', 'FLUTTER', 'IOS', 'REACT_NATIVE');

-- CreateEnum
CREATE TYPE "CredentialStatus" AS ENUM ('ACTIVE', 'REVOKED');

-- CreateEnum
CREATE TYPE "CredentialAuditAction" AS ENUM ('ISSUED', 'REVOKED');

-- CreateTable
CREATE TABLE "organizations" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "organizations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'OWNER',
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "applications" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "platform" "Platform" NOT NULL,
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "applications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_credentials" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "apiKey" TEXT NOT NULL,
    "apiSecretEncrypted" TEXT NOT NULL,
    "status" "CredentialStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rotatedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "api_credentials_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential_audit_logs" (
    "id" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "action" "CredentialAuditAction" NOT NULL,
    "performedByUserId" TEXT NOT NULL,
    "performedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" TEXT,

    CONSTRAINT "credential_audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_events" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "detectorId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "evidence" JSONB,
    "reason" TEXT,
    "deviceId" TEXT,
    "deviceModel" TEXT,
    "manufacturer" TEXT,
    "osPlatform" TEXT,
    "osVersion" TEXT,
    "appVersion" TEXT,
    "sdkVersion" TEXT,
    "clientObservedAt" TIMESTAMP(3),
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" TEXT,

    CONSTRAINT "security_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "applications_organizationId_idx" ON "applications"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "api_credentials_apiKey_key" ON "api_credentials"("apiKey");

-- CreateIndex
CREATE INDEX "api_credentials_applicationId_idx" ON "api_credentials"("applicationId");

-- CreateIndex
CREATE INDEX "credential_audit_logs_credentialId_idx" ON "credential_audit_logs"("credentialId");

-- CreateIndex
CREATE INDEX "security_events_applicationId_receivedAt_idx" ON "security_events"("applicationId", "receivedAt");

-- CreateIndex
CREATE INDEX "security_events_applicationId_detectorId_idx" ON "security_events"("applicationId", "detectorId");

-- CreateIndex
CREATE INDEX "security_events_applicationId_status_idx" ON "security_events"("applicationId", "status");

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "users_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "applications" ADD CONSTRAINT "applications_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_credentials" ADD CONSTRAINT "api_credentials_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "credential_audit_logs" ADD CONSTRAINT "credential_audit_logs_credentialId_fkey" FOREIGN KEY ("credentialId") REFERENCES "api_credentials"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
