-- Attested registration (F-13 / F-14).
CREATE TYPE "AttestationPolicy" AS ENUM ('RECORD', 'REQUIRE_HARDWARE');

ALTER TABLE "applications" ADD COLUMN "attestationPolicy" "AttestationPolicy" NOT NULL DEFAULT 'RECORD';

-- Existing applications keep accepting legacy HMAC event batches; applications
-- created from now on start with envelopes only.
ALTER TABLE "applications" ADD COLUMN "legacyIngestionEnabled" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "applications" ALTER COLUMN "legacyIngestionEnabled" SET DEFAULT false;

ALTER TABLE "device_registrations" ADD COLUMN "possessionVerified" BOOLEAN NOT NULL DEFAULT false;
