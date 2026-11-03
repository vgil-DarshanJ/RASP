-- Task 8.1: fraud-risk foundation — account-hash salt and per-app risk-rule
-- thresholds on applications, a separate risk-event counter per device key,
-- account/device bindings, session and transaction risk events (hashes only,
-- never an amount), and an application-settings audit log.
-- Generated with `prisma migrate diff` from the previous schema; NOT applied
-- automatically. Apply with:
--   npx prisma migrate deploy        (or: npx prisma migrate dev)

-- AlterTable
ALTER TABLE "applications" ADD COLUMN     "accountHashSalt" TEXT,
ADD COLUMN     "riskRules" JSONB;

-- AlterTable
ALTER TABLE "device_registrations" ADD COLUMN     "lastRiskCounter" BIGINT NOT NULL DEFAULT 0;

-- CreateTable
CREATE TABLE "account_device_bindings" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "accountHash" TEXT NOT NULL,
    "deviceKeyId" TEXT NOT NULL,
    "deviceRegistrationId" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "account_device_bindings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "session_events" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "deviceRegistrationId" TEXT NOT NULL,
    "deviceKeyId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "monotonicCounter" BIGINT NOT NULL,
    "sdkVersion" TEXT NOT NULL,
    "accountHash" TEXT NOT NULL,
    "sessionHash" TEXT NOT NULL,
    "sessionEvent" TEXT NOT NULL,
    "riskScore" INTEGER,
    "riskVerdict" TEXT NOT NULL,
    "latitude" DOUBLE PRECISION,
    "longitude" DOUBLE PRECISION,
    "locationCapturedAt" TIMESTAMP(3),
    "ipCountry" TEXT,
    "eventTime" TIMESTAMP(3) NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "signature" TEXT NOT NULL,
    "riskEvents" JSONB NOT NULL DEFAULT '[]',

    CONSTRAINT "session_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "transaction_events" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "deviceRegistrationId" TEXT NOT NULL,
    "deviceKeyId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "monotonicCounter" BIGINT NOT NULL,
    "sdkVersion" TEXT NOT NULL,
    "accountHash" TEXT NOT NULL,
    "sessionHash" TEXT NOT NULL,
    "beneficiaryHash" TEXT NOT NULL,
    "currency" TEXT NOT NULL,
    "channel" TEXT NOT NULL,
    "bindingSha256" TEXT NOT NULL,
    "riskScore" INTEGER,
    "riskVerdict" TEXT NOT NULL,
    "latitude" DOUBLE PRECISION,
    "longitude" DOUBLE PRECISION,
    "locationCapturedAt" TIMESTAMP(3),
    "ipCountry" TEXT,
    "eventTime" TIMESTAMP(3) NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "signature" TEXT NOT NULL,
    "riskEvents" JSONB NOT NULL DEFAULT '[]',

    CONSTRAINT "transaction_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "application_settings_audit_logs" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "field" TEXT,
    "oldValue" JSONB,
    "newValue" JSONB,
    "performedByUserId" TEXT,
    "performedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" TEXT,

    CONSTRAINT "application_settings_audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "account_device_bindings_applicationId_accountHash_firstSeen_idx" ON "account_device_bindings"("applicationId", "accountHash", "firstSeenAt");

-- CreateIndex
CREATE INDEX "account_device_bindings_applicationId_deviceKeyId_idx" ON "account_device_bindings"("applicationId", "deviceKeyId");

-- CreateIndex
CREATE UNIQUE INDEX "account_device_bindings_applicationId_accountHash_deviceKey_key" ON "account_device_bindings"("applicationId", "accountHash", "deviceKeyId");

-- CreateIndex
CREATE INDEX "session_events_applicationId_accountHash_eventTime_idx" ON "session_events"("applicationId", "accountHash", "eventTime");

-- CreateIndex
CREATE INDEX "session_events_applicationId_deviceKeyId_receivedAt_idx" ON "session_events"("applicationId", "deviceKeyId", "receivedAt");

-- CreateIndex
CREATE INDEX "session_events_applicationId_receivedAt_idx" ON "session_events"("applicationId", "receivedAt");

-- CreateIndex
CREATE UNIQUE INDEX "session_events_deviceRegistrationId_nonce_key" ON "session_events"("deviceRegistrationId", "nonce");

-- CreateIndex
CREATE UNIQUE INDEX "session_events_deviceRegistrationId_eventId_key" ON "session_events"("deviceRegistrationId", "eventId");

-- CreateIndex
CREATE INDEX "transaction_events_applicationId_accountHash_eventTime_idx" ON "transaction_events"("applicationId", "accountHash", "eventTime");

-- CreateIndex
CREATE INDEX "transaction_events_applicationId_accountHash_beneficiaryHas_idx" ON "transaction_events"("applicationId", "accountHash", "beneficiaryHash");

-- CreateIndex
CREATE INDEX "transaction_events_applicationId_deviceKeyId_receivedAt_idx" ON "transaction_events"("applicationId", "deviceKeyId", "receivedAt");

-- CreateIndex
CREATE INDEX "transaction_events_applicationId_receivedAt_idx" ON "transaction_events"("applicationId", "receivedAt");

-- CreateIndex
CREATE UNIQUE INDEX "transaction_events_deviceRegistrationId_nonce_key" ON "transaction_events"("deviceRegistrationId", "nonce");

-- CreateIndex
CREATE UNIQUE INDEX "transaction_events_deviceRegistrationId_eventId_key" ON "transaction_events"("deviceRegistrationId", "eventId");

-- CreateIndex
CREATE INDEX "application_settings_audit_logs_applicationId_performedAt_idx" ON "application_settings_audit_logs"("applicationId", "performedAt");

-- AddForeignKey
ALTER TABLE "account_device_bindings" ADD CONSTRAINT "account_device_bindings_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "session_events" ADD CONSTRAINT "session_events_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "session_events" ADD CONSTRAINT "session_events_deviceRegistrationId_fkey" FOREIGN KEY ("deviceRegistrationId") REFERENCES "device_registrations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transaction_events" ADD CONSTRAINT "transaction_events_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transaction_events" ADD CONSTRAINT "transaction_events_deviceRegistrationId_fkey" FOREIGN KEY ("deviceRegistrationId") REFERENCES "device_registrations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "application_settings_audit_logs" ADD CONSTRAINT "application_settings_audit_logs_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

