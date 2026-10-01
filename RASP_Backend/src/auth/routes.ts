import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { signJwt } from "./jwt";

export const authRouter = Router();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, "Password must be at least 8 characters"),
  organizationName: z.string().min(2).max(120),
});

/**
 * Creates a User AND its Organization together, in one transaction — this
 * platform has no "join an existing org by invite" flow yet (deferred, see
 * the plan's "explicitly deferred" section), so every registration is
 * necessarily a brand-new organization with this user as its OWNER.
 */
authRouter.post("/register", async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_INPUT", details: parsed.error.flatten() });
  }
  const { email, password, organizationName } = parsed.data;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return res.status(409).json({ error: "EMAIL_ALREADY_REGISTERED" });
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const { user, organization } = await prisma.$transaction(async (tx) => {
    const organization = await tx.organization.create({
      data: { name: organizationName },
    });
    const user = await tx.user.create({
      data: {
        email,
        passwordHash,
        role: "OWNER",
        organizationId: organization.id,
      },
    });
    return { user, organization };
  });

  const token = signJwt({ userId: user.id, organizationId: organization.id, role: user.role });

  res.status(201).json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
    organization: { id: organization.id, name: organization.name },
  });
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

authRouter.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }
  const { email, password } = parsed.data;

  const user = await prisma.user.findUnique({
    where: { email },
    include: { organization: true },
  });

  // Same generic error whether the email doesn't exist or the password is
  // wrong — never leak which one it was to an unauthenticated caller.
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "INVALID_CREDENTIALS" });
  }

  const token = signJwt({ userId: user.id, organizationId: user.organizationId, role: user.role });

  res.json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
    organization: { id: user.organization.id, name: user.organization.name },
  });
});
