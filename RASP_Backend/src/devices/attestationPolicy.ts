/**
 * Whether a device key meets its application's attestation policy (F-13,
 * F-14). Used at registration and again on every envelope and risk event,
 * so switching an application to REQUIRE_HARDWARE applies to keys that
 * were registered before.
 *
 * REQUIRE_HARDWARE needs all of:
 * - `attestation_not_verified`: verdict `verified` (Google root, hardware
 *   level, valid and not revoked — see inspectAttestationChain);
 * - `revocation_not_checked`: the revocation list was checked (unless
 *   ATTESTATION_REVOCATION_CHECK=off);
 * - `possession_not_proven`: the device signed a one-time server challenge
 *   with the key;
 * - `package_mismatch`: the attested package (from the TEE, not from the
 *   app) is the registered appId;
 * - `signing_certificate_mismatch`: when the application has an expected
 *   signing certificate, the attested signing digests include it — a
 *   repackaged app on a genuine phone fails here.
 * RECORD accepts everything (the reasons are still reported).
 */
export type AttestationPolicyName = "RECORD" | "REQUIRE_HARDWARE";

export interface PolicyInput {
  policy: AttestationPolicyName;
  appId: string;
  expectedSigningCertSha256: string | null;
  verdict: string;
  possessionVerified: boolean;
  revocationChecked: boolean;
  revocationRequired: boolean;
  attestedPackages: string[];
  attestedSigningCertSha256: string[];
}

export type PolicyReason =
  | "attestation_not_verified"
  | "revocation_not_checked"
  | "possession_not_proven"
  | "package_mismatch"
  | "signing_certificate_mismatch";

/** Every reason the key falls short of REQUIRE_HARDWARE (empty = meets it). */
export function attestationShortfalls(input: PolicyInput): PolicyReason[] {
  const reasons: PolicyReason[] = [];
  if (input.verdict !== "verified") reasons.push("attestation_not_verified");
  if (input.revocationRequired && !input.revocationChecked) reasons.push("revocation_not_checked");
  if (!input.possessionVerified) reasons.push("possession_not_proven");
  if (!input.attestedPackages.includes(input.appId)) reasons.push("package_mismatch");
  if (input.expectedSigningCertSha256 && !input.attestedSigningCertSha256.includes(input.expectedSigningCertSha256.toUpperCase())) {
    reasons.push("signing_certificate_mismatch");
  }
  return reasons;
}

/** `true` when the key may register / deliver under its application's policy. */
export function meetsAttestationPolicy(input: PolicyInput): boolean {
  return input.policy !== "REQUIRE_HARDWARE" || attestationShortfalls(input).length === 0;
}

/** Reads the stored attestation details of a registration (JSON written by registerDevice). */
export function storedAttestation(details: unknown): {
  revocationChecked: boolean;
  attestedPackages: string[];
  attestedSigningCertSha256: string[];
} {
  const d = (details ?? {}) as Record<string, unknown>;
  const strings = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  return {
    revocationChecked: d.revocationChecked === true,
    attestedPackages: strings(d.attestedPackages),
    attestedSigningCertSha256: strings(d.attestedSigningCertSha256),
  };
}

/** The registration columns (and the application's policy) the ingestion paths read. */
export const POLICY_SELECT = {
  appId: true,
  attestationVerdict: true,
  possessionVerified: true,
  attestationDetails: true,
  application: { select: { attestationPolicy: true, expectedSigningCertSha256: true } },
} as const;

/** [meetsAttestationPolicy] for a registration row loaded with [POLICY_SELECT]. */
export function rowMeetsPolicy(row: {
  appId: string;
  attestationVerdict: string;
  possessionVerified: boolean;
  attestationDetails: unknown;
  application: { attestationPolicy: AttestationPolicyName; expectedSigningCertSha256: string | null };
}, revocationRequired: boolean): boolean {
  const stored = storedAttestation(row.attestationDetails);
  return meetsAttestationPolicy({
    policy: row.application.attestationPolicy,
    appId: row.appId,
    expectedSigningCertSha256: row.application.expectedSigningCertSha256,
    verdict: row.attestationVerdict,
    possessionVerified: row.possessionVerified,
    revocationChecked: stored.revocationChecked,
    revocationRequired,
    attestedPackages: stored.attestedPackages,
    attestedSigningCertSha256: stored.attestedSigningCertSha256,
  });
}
