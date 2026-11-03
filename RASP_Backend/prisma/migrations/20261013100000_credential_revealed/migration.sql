-- Credential audit action for POST /v1/credentials/.../:credentialId/reveal
-- (an administrator viewed an existing credential JSON again).
ALTER TYPE "CredentialAuditAction" ADD VALUE 'REVEALED';
