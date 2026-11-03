-- Task 6.0: opted-in location on events, signing-certificate tamper alerts,
-- per-application IP-risk policy, device registration country.
-- Written by hand; NOT applied automatically. Apply with:
--   npx prisma migrate deploy        (or: npx prisma migrate dev)

-- Applications: expected signing certificate and IP-risk country lists.
ALTER TABLE "applications" ADD COLUMN "expectedSigningCertSha256" TEXT;
ALTER TABLE "applications" ADD COLUMN "ipBlockedCountries" TEXT[] DEFAULT ARRAY[]::TEXT[];
ALTER TABLE "applications" ADD COLUMN "ipAllowedCountries" TEXT[] DEFAULT ARRAY[]::TEXT[];

-- Security events: location columns, filled only with location_opt_in = true.
ALTER TABLE "security_events" ADD COLUMN "latitude" DOUBLE PRECISION;
ALTER TABLE "security_events" ADD COLUMN "longitude" DOUBLE PRECISION;
ALTER TABLE "security_events" ADD COLUMN "locationAccuracyM" DOUBLE PRECISION;
ALTER TABLE "security_events" ADD COLUMN "locationCapturedAt" TIMESTAMP(3);
ALTER TABLE "security_events" ADD COLUMN "locationOptIn" BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX "security_events_applicationId_locationOptIn_receivedAt_idx"
  ON "security_events"("applicationId", "locationOptIn", "receivedAt");

-- Device registrations: reported signing certificate and registration country.
ALTER TABLE "device_registrations" ADD COLUMN "signingCertSha256" TEXT;
ALTER TABLE "device_registrations" ADD COLUMN "registrationCountry" TEXT;

-- Evidence envelopes: marks payloads whose location fields were removed.
ALTER TABLE "evidence_envelopes" ADD COLUMN "payloadRedacted" BOOLEAN NOT NULL DEFAULT false;
