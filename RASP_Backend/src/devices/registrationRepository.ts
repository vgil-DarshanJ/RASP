import { Prisma } from "@prisma/client";
import { prisma } from "../db/prisma";
import { RegisteredKey, RegistrationRepository } from "./registration";

const selectKey = {
  id: true,
  applicationId: true,
  appId: true,
  deviceKeyId: true,
  attestationStatus: true,
} as const;

/** Postgres-backed [RegistrationRepository]; `deviceKeyId` is unique. */
export const prismaRegistrationRepository: RegistrationRepository = {
  async findByKeyId(deviceKeyId): Promise<RegisteredKey | null> {
    return prisma.deviceRegistration.findUnique({ where: { deviceKeyId }, select: selectKey });
  },

  async create(input): Promise<RegisteredKey | "exists"> {
    try {
      return await prisma.deviceRegistration.create({
        data: {
          applicationId: input.applicationId,
          appId: input.appId,
          deviceId: input.deviceId,
          deviceKeyId: input.deviceKeyId,
          publicKey: input.publicKey,
          attestationChain: input.attestationChain,
          attestationStatus: input.attestation.status,
          attestationDetails: input.attestation as unknown as Prisma.InputJsonValue,
          sdkVersion: input.sdkVersion,
          createdAt: input.now,
          lastSeenAt: input.now,
        },
        select: selectKey,
      });
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") return "exists";
      throw err;
    }
  },

  async touch(id, now) {
    await prisma.deviceRegistration.update({ where: { id }, data: { lastSeenAt: now } });
  },
};
