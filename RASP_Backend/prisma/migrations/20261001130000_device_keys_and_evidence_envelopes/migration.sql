-- AlterTable
ALTER TABLE "security_events" ADD COLUMN     "envelopeId" TEXT;

-- CreateTable
CREATE TABLE "device_registrations" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "deviceId" TEXT,
    "deviceKeyId" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "attestationChain" TEXT[],
    "attestationStatus" TEXT NOT NULL,
    "attestationDetails" JSONB NOT NULL,
    "sdkVersion" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastCounter" BIGINT NOT NULL DEFAULT 0,

    CONSTRAINT "device_registrations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "evidence_envelopes" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "deviceRegistrationId" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "monotonicCounter" BIGINT NOT NULL,
    "nonce" TEXT NOT NULL,
    "eventTime" TIMESTAMP(3) NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "signedPayload" TEXT NOT NULL,
    "signature" TEXT NOT NULL,

    CONSTRAINT "evidence_envelopes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "device_registrations_deviceKeyId_key" ON "device_registrations"("deviceKeyId");

-- CreateIndex
CREATE INDEX "device_registrations_applicationId_deviceId_idx" ON "device_registrations"("applicationId", "deviceId");

-- CreateIndex
CREATE UNIQUE INDEX "evidence_envelopes_eventId_key" ON "evidence_envelopes"("eventId");

-- CreateIndex
CREATE INDEX "evidence_envelopes_applicationId_receivedAt_idx" ON "evidence_envelopes"("applicationId", "receivedAt");

-- CreateIndex
CREATE UNIQUE INDEX "evidence_envelopes_deviceRegistrationId_nonce_key" ON "evidence_envelopes"("deviceRegistrationId", "nonce");

-- CreateIndex
CREATE UNIQUE INDEX "evidence_envelopes_deviceRegistrationId_monotonicCounter_key" ON "evidence_envelopes"("deviceRegistrationId", "monotonicCounter");

-- CreateIndex
CREATE INDEX "security_events_envelopeId_idx" ON "security_events"("envelopeId");

-- AddForeignKey
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_envelopeId_fkey" FOREIGN KEY ("envelopeId") REFERENCES "evidence_envelopes"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_registrations" ADD CONSTRAINT "device_registrations_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence_envelopes" ADD CONSTRAINT "evidence_envelopes_deviceRegistrationId_fkey" FOREIGN KEY ("deviceRegistrationId") REFERENCES "device_registrations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

