-- Session revocation (F-11): POST /v1/auth/logout raises tokenVersion; tokens
-- carrying an older value are rejected. Existing users start at 0, which is
-- also what tokens issued before this change are treated as.
ALTER TABLE "users" ADD COLUMN "tokenVersion" INTEGER NOT NULL DEFAULT 0;
