-- Signed remote configuration (Task 10.0): published versions and their audit trail.
-- The signature is not stored: GET /v1/config signs the payload with CONFIG_SIGNING_KEY.

-- CreateTable
CREATE TABLE "remote_configs" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "payload" JSONB NOT NULL,
    "createdByUserId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "copiedFromVersion" INTEGER,

    CONSTRAINT "remote_configs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remote_config_audits" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "remoteConfigId" TEXT,
    "action" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "fromVersion" INTEGER,
    "changes" JSONB,
    "performedByUserId" TEXT NOT NULL,
    "performedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" TEXT,

    CONSTRAINT "remote_config_audits_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "remote_configs_applicationId_active_idx" ON "remote_configs"("applicationId", "active");

-- CreateIndex
CREATE UNIQUE INDEX "remote_configs_applicationId_version_key" ON "remote_configs"("applicationId", "version");

-- CreateIndex
CREATE INDEX "remote_config_audits_applicationId_performedAt_idx" ON "remote_config_audits"("applicationId", "performedAt");

-- AddForeignKey
ALTER TABLE "remote_configs" ADD CONSTRAINT "remote_configs_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remote_config_audits" ADD CONSTRAINT "remote_config_audits_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remote_config_audits" ADD CONSTRAINT "remote_config_audits_remoteConfigId_fkey" FOREIGN KEY ("remoteConfigId") REFERENCES "remote_configs"("id") ON DELETE SET NULL ON UPDATE CASCADE;

