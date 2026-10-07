/**
 * Location in detector results: stored ONLY when the user opted in.
 *
 * The SDK attaches `location_opt_in: true`, `latitude`, `longitude`,
 * `location_accuracy_m` and `location_captured_at_millis` to a result's
 * evidence while the user has opted in to sharing location. Older SDKs
 * attached `latitude`/`longitude` to DETECTED results without any opt-in
 * flag; those coordinates must not be stored anywhere, so they are removed
 * from the evidence before it is written.
 *
 * Evidence is normally a list of `{key, value, note}` entries; a plain
 * object (`{latitude: …}`) is handled the same way.
 */

/** Evidence keys that carry location. */
export const LOCATION_KEYS = new Set([
  "latitude",
  "longitude",
  "location_accuracy_m",
  "location_captured_at_millis",
  "location_opt_in",
  // Location heartbeat (Task 9.3) details: also removed without opt-in.
  "location_fix_age_seconds",
  "location_is_mock",
]);

export interface StoredLocation {
  latitude: number;
  longitude: number;
  accuracyM: number | null;
  capturedAt: Date | null;
}

export interface LocationExtraction {
  /** Evidence to store: unchanged with opt-in, location keys removed without. */
  evidence: unknown;
  /** Coordinates to store in the event's columns; null without opt-in or invalid values. */
  location: StoredLocation | null;
  /** `location_opt_in === true` was present. */
  optIn: boolean;
  /** Location keys were removed (coordinates sent without opt-in). */
  stripped: boolean;
}

function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function readFields(evidence: unknown): Map<string, unknown> {
  const fields = new Map<string, unknown>();
  if (Array.isArray(evidence)) {
    for (const item of evidence) {
      if (item && typeof item === "object" && typeof (item as { key?: unknown }).key === "string") {
        const { key, value } = item as { key: string; value?: unknown };
        if (LOCATION_KEYS.has(key) && !fields.has(key)) fields.set(key, value);
      }
    }
  } else if (evidence && typeof evidence === "object") {
    for (const [key, value] of Object.entries(evidence as Record<string, unknown>)) {
      if (LOCATION_KEYS.has(key)) fields.set(key, value);
    }
  }
  return fields;
}

function withoutLocationKeys(evidence: unknown): unknown {
  if (Array.isArray(evidence)) {
    return evidence.filter(
      (item) => !(item && typeof item === "object" && LOCATION_KEYS.has(String((item as { key?: unknown }).key))),
    );
  }
  if (evidence && typeof evidence === "object") {
    return Object.fromEntries(Object.entries(evidence as Record<string, unknown>).filter(([k]) => !LOCATION_KEYS.has(k)));
  }
  return evidence;
}

/** Decides what of a result's location may be stored. Pure. */
export function extractLocation(evidence: unknown): LocationExtraction {
  const fields = readFields(evidence);
  if (fields.size === 0) return { evidence, location: null, optIn: false, stripped: false };

  const optIn = fields.get("location_opt_in") === true;
  if (!optIn) {
    return { evidence: withoutLocationKeys(evidence), location: null, optIn: false, stripped: true };
  }

  const latitude = finite(fields.get("latitude"));
  const longitude = finite(fields.get("longitude"));
  const valid = latitude !== null && longitude !== null &&
    latitude >= -90 && latitude <= 90 && longitude >= -180 && longitude <= 180;
  if (!valid) {
    // Opted in but unusable coordinates: store neither the columns nor the bad values.
    return { evidence: withoutLocationKeys(evidence), location: null, optIn: true, stripped: true };
  }
  const accuracy = finite(fields.get("location_accuracy_m"));
  const capturedMillis = finite(fields.get("location_captured_at_millis"));
  return {
    evidence,
    location: {
      latitude: latitude!,
      longitude: longitude!,
      accuracyM: accuracy !== null && accuracy >= 0 ? accuracy : null,
      capturedAt: capturedMillis !== null && capturedMillis > 0 ? new Date(capturedMillis) : null,
    },
    optIn: true,
    stripped: false,
  };
}

/** Prisma `SecurityEvent` column values for an (opted-in) location, or all-empty for null. */
export function locationColumns(loc: StoredLocation | null) {
  return {
    latitude: loc?.latitude ?? null,
    longitude: loc?.longitude ?? null,
    locationAccuracyM: loc?.accuracyM ?? null,
    locationCapturedAt: loc?.capturedAt ?? null,
    locationOptIn: loc !== null,
  };
}

/**
 * Removes non-opted-in location from a signed envelope payload's
 * `detectorResults[].evidence`, re-serialized with [canonicalize]. Returns
 * the payload unchanged (and `redacted: false`) when nothing had to go.
 */
export function redactEnvelopePayload(
  signedPayload: string,
  canonicalize: (value: unknown) => string,
): { payload: string; redacted: boolean } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(signedPayload);
  } catch {
    return { payload: signedPayload, redacted: false };
  }
  const results = (parsed as { detectorResults?: unknown }).detectorResults;
  if (!Array.isArray(results)) return { payload: signedPayload, redacted: false };
  let redacted = false;
  const cleaned = results.map((r) => {
    if (!r || typeof r !== "object") return r;
    const extraction = extractLocation((r as { evidence?: unknown }).evidence);
    if (!extraction.stripped) return r;
    redacted = true;
    return { ...(r as Record<string, unknown>), evidence: extraction.evidence };
  });
  if (!redacted) return { payload: signedPayload, redacted: false };
  return { payload: canonicalize({ ...(parsed as Record<string, unknown>), detectorResults: cleaned }), redacted: true };
}
