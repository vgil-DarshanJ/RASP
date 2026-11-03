-- CreateTable
CREATE TABLE "device_locations" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "latitude" DOUBLE PRECISION,
    "longitude" DOUBLE PRECISION,
    "accuracyM" DOUBLE PRECISION,
    "isMock" BOOLEAN,
    "capturedAt" TIMESTAMP(3),
    "receivedAt" TIMESTAMP(3) NOT NULL,
    "lastCounter" BIGINT NOT NULL DEFAULT 0,

    CONSTRAINT "device_locations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_location_points" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "latitude" DOUBLE PRECISION NOT NULL,
    "longitude" DOUBLE PRECISION NOT NULL,
    "accuracyM" DOUBLE PRECISION,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_location_points_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "device_locations_applicationId_receivedAt_idx" ON "device_locations"("applicationId", "receivedAt");

-- CreateIndex
CREATE UNIQUE INDEX "device_locations_applicationId_deviceId_key" ON "device_locations"("applicationId", "deviceId");

-- CreateIndex
CREATE INDEX "device_location_points_applicationId_deviceId_receivedAt_idx" ON "device_location_points"("applicationId", "deviceId", "receivedAt");

-- AddForeignKey
ALTER TABLE "device_locations" ADD CONSTRAINT "device_locations_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_location_points" ADD CONSTRAINT "device_location_points_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

