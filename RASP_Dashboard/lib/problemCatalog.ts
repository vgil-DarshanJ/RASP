/**
 * Plain-English meaning and next step for the backend's `error` codes and
 * HTTP statuses, for the System Status page. Unknown codes fall back to the
 * HTTP status.
 */
export interface Explanation {
  meaning: string;
  fix: string;
}

const PHONE_CREDENTIAL_FIX =
  "Issue a fresh credential for this app on the dashboard (Applications → the app → Credentials), paste the whole JSON into the app again, and restart the app.";

const CODES: Record<string, Explanation> = {
  // Phone → backend (signed with the app credential)
  MISSING_API_KEY: { meaning: "A phone called the backend without an API key.", fix: PHONE_CREDENTIAL_FIX },
  INVALID_OR_REVOKED_API_KEY: { meaning: "The phone's API key is unknown here or was revoked. Often the credential came from a different backend.", fix: PHONE_CREDENTIAL_FIX },
  MISSING_SIGNATURE: { meaning: "A phone request had no signature.", fix: "Use the SDK's own sync. Requests must be signed with the credential." },
  INVALID_SIGNATURE_FORMAT: { meaning: "A phone request's signature is malformed.", fix: PHONE_CREDENTIAL_FIX },
  SIGNATURE_MISMATCH: { meaning: "The phone signed with a different secret than this backend has. The pasted credential is old, incomplete, or from another backend.", fix: PHONE_CREDENTIAL_FIX },
  MISSING_TIMESTAMP: { meaning: "A phone request had no timestamp.", fix: "Update the app to the current SDK." },
  INVALID_TIMESTAMP: { meaning: "A phone request's timestamp could not be read.", fix: "Update the app to the current SDK." },
  STALE_TIMESTAMP: { meaning: "The phone's clock is more than 5 minutes away from the server's.", fix: "On the phone: Settings → Date & time → turn on automatic time. Check the server clock too (timedatectl)." },
  REPLAYED_REQUEST: { meaning: "The same signed request arrived twice and the copy was refused (replay protection).", fix: "Usually harmless (a network retry). If it repeats, something may be replaying traffic." },
  REPLAY_CHECK_UNAVAILABLE: { meaning: "Redis is down, so the replay check could not run and the request was refused.", fix: "Start Redis: cd to the backend folder, then docker compose up -d redis." },
  RATE_LIMIT_EXCEEDED: { meaning: "Too many requests from one phone, app or IP in a short time.", fix: "Wait a minute. If it is a real load, raise the *_RATE_LIMIT_* values in the backend .env." },
  ATTESTATION_REQUIRED: { meaning: "This app requires hardware key attestation and the phone could not provide it.", fix: "Use a real phone with a hardware keystore, or set the app's attestation policy to RECORD." },
  DEVICE_KEY_REGISTERED_TO_OTHER_APPLICATION: { meaning: "This phone's device key is already registered to another application.", fix: "Clear the app's data on the phone (or reinstall) so it creates a new key." },
  DEVICE_KEY_REGISTERED_FOR_OTHER_APP_ID: { meaning: "This device key was registered for another app id.", fix: "Clear the app's data on the phone (or reinstall)." },
  REGISTRATION_FAILED: { meaning: "The phone could not register its device key.", fix: "Check the backend log for this request id." },
  INVALID_REGISTER_BODY: { meaning: "A device registration request was malformed.", fix: "Update the app to the current SDK." },
  INVALID_PUBLIC_KEY: { meaning: "The phone sent a device key the backend cannot read.", fix: "Update the app to the current SDK." },
  CHALLENGE_UNAVAILABLE: { meaning: "The device-key challenge could not be created (usually Redis is down).", fix: "Start Redis: docker compose up -d redis." },
  INVALID_EVENT_BATCH: { meaning: "A batch of detector results was malformed.", fix: "Update the app to the current SDK." },
  LEGACY_INGESTION_DISABLED: { meaning: "The phone sent unsigned (old-style) events, which this app no longer accepts.", fix: "Turn on signed evidence envelopes in the app (useEvidenceEnvelope: true)." },
  INVALID_DEVICE_ID: { meaning: "A request carried an invalid device id.", fix: "Update the app to the current SDK." },
  PAYLOAD_TOO_LARGE: { meaning: "A request body was larger than the backend accepts.", fix: "Send fewer events per batch." },
  APPLICATION_ARCHIVED: { meaning: "The application was archived, so its phones are refused.", fix: "Restore the app or create a new one and issue a credential for it." },
  REMOTE_CONFIG_NONE: { meaning: "No remote config is published for this app yet.", fix: "Not an error unless you expect one. Publish a config first." },
  REMOTE_CONFIG_EXPIRED: { meaning: "The published remote config has expired.", fix: "Publish a new remote config." },
  REMOTE_CONFIG_SIGNING_UNAVAILABLE: { meaning: "The backend has no config signing key, so remote config is off.", fix: "On the server: npm run config:keygen, put the key in .env as CONFIG_SIGNING_KEY, restart." },
  REPUTATION_LIST_NOT_CONFIGURED: { meaning: "The malware list is not set up on this backend.", fix: "See the backend's reputation/README.md (REPUTATION_SIGNING_KEY)." },

  // Dashboard (browser) → backend
  MISSING_TOKEN: { meaning: "Not signed in, or the session cookie was not sent.", fix: "Sign in again. If it keeps happening, open the portal at the URL in CORS_ORIGINS (not a different IP or port)." },
  INVALID_TOKEN: { meaning: "The session token is invalid (for example the backend's JWT_SECRET changed).", fix: "Sign in again." },
  INVALID_OR_EXPIRED_TOKEN: { meaning: "The link or token has expired.", fix: "Request a new one." },
  TOKEN_REVOKED: { meaning: "This session was signed out elsewhere.", fix: "Sign in again." },
  ACCOUNT_NOT_FOUND: { meaning: "The signed-in account no longer exists in this backend's database (database reset, or a token from another backend).", fix: "Register or sign in again on this portal." },
  AUTH_BACKEND_UNAVAILABLE: { meaning: "The database did not answer while checking the session.", fix: "Check the PostgreSQL row above. Start it with: docker compose up -d postgres." },
  ORIGIN_NOT_ALLOWED: { meaning: "The backend refused a change from this page's address (CSRF protection).", fix: "Add this page's origin to CORS_ORIGINS in the backend .env and restart the backend." },
  FORBIDDEN_ROLE: { meaning: "Your role (MEMBER) cannot do this.", fix: "Ask an OWNER or ADMIN." },
  INVALID_CREDENTIALS: { meaning: "Wrong e-mail or password.", fix: "Check them, or use Forgot password." },
  ACCOUNT_TEMPORARILY_LOCKED: { meaning: "Too many failed sign-ins, so the account is locked for a while.", fix: "Wait 15 minutes, then try again." },
  EMAIL_ALREADY_REGISTERED: { meaning: "That e-mail already has an account.", fix: "Sign in instead." },
  APPLICATION_NOT_FOUND: { meaning: "The application does not exist (deleted, or from another organization).", fix: "Pick another app in the app picker." },
  CREDENTIAL_NOT_FOUND: { meaning: "The credential does not exist.", fix: "Reload the page." },
  DEVICE_NOT_FOUND: { meaning: "The device does not exist.", fix: "Reload the page." },
  EVENT_NOT_FOUND: { meaning: "The event does not exist (maybe removed by retention).", fix: "Reload the page." },
  INVALID_INPUT: { meaning: "The request had invalid values.", fix: "Check the form fields." },
  INVALID_BODY: { meaning: "The request had invalid values.", fix: "Check the form fields." },
  INVALID_QUERY: { meaning: "A filter or search value was invalid.", fix: "Change the filter." },
  INVALID_JSON: { meaning: "The request body was not valid JSON.", fix: "Check what was pasted." },
  SDK_SOURCE_ROOT_NOT_CONFIGURED: { meaning: "SDK download is not set up on this backend.", fix: "Set SDK_SOURCE_ROOT in the backend .env to the sdk_rasp folder." },
  SDK_SOURCE_NOT_FOUND_ON_SERVER: { meaning: "SDK_SOURCE_ROOT points at a folder that does not exist.", fix: "Fix SDK_SOURCE_ROOT in the backend .env." },
  WEBHOOK_NOT_CONFIGURED: { meaning: "No webhook is set up for this app.", fix: "Add one under Alerting." },
  INTERNAL_SERVER_ERROR: { meaning: "The backend hit an unexpected error.", fix: "Look up this request id in the backend log (scripts/office-server.sh logs be)." },
};

export function explain(code: string | undefined, status: number | undefined): Explanation {
  if (code && CODES[code]) return CODES[code];
  if (status === 0) {
    return {
      meaning: "The browser got no answer from the backend: it is stopped, the address is wrong, a firewall blocks port 4444, or CORS refused this page.",
      fix: "Check the \"This browser → backend\" box at the top of this page.",
    };
  }
  if (status === undefined) return { meaning: "See the detail.", fix: "Check the backend log." };
  if (status >= 500) return { meaning: "The backend failed while handling the request.", fix: "Look up the request id in the backend log." };
  if (status === 404) return { meaning: "The backend has no such page or item.", fix: "Check the address, or that the backend and portal are the same version (git pull both)." };
  if (status === 401 || status === 403) return { meaning: "The request was not allowed.", fix: "Sign in again, or check the credential." };
  if (status === 429) return CODES.RATE_LIMIT_EXCEEDED;
  return { meaning: "The request was refused.", fix: "Check the values that were sent." };
}
