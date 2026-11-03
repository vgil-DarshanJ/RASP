# Play Integrity — setup guide (server-side verification)

What this turns on: the phone asks Google "is this the real app, installed
from Play, on a real Android device?" and gets a signed token. The token is
worthless until a server asks Google to decode it. After this setup, the
RASP backend does that at `POST /v1/integrity/verify` and answers
**PASS / FAIL + reasons**. The code is already in place
(`src/integrity/`, engine `RaspPlayIntegrityVerifier`); what is missing is
only the Google side, which only an account owner can do.

You need:
- a **Google Play Console** developer account that owns (or can add) the app;
- a **Google Cloud** account in the same Google organisation (or personal account);
- access to the backend server (`192.168.2.208`, `BE/` folder).

Time: about 30 minutes. Cost: free (10,000 checks per day by default).

---

## Step 1 — Create (or pick) a Google Cloud project

1. Open <https://console.cloud.google.com/>.
2. Top bar → project picker → **New project**.
   - Name: e.g. `rasp-shield-integrity`. Organisation: your company, if offered.
   - **Create**, then make sure the new project is selected in the top bar.
3. Home / **Dashboard** → card **Project info** → copy the **Project number**
   (digits only, e.g. `123456789012`; *not* the project ID).
   Keep it — the app needs it for sideloaded test builds (Step 8).

## Step 2 — Turn on the Play Integrity API in that project

1. Left menu → **APIs & Services → Library**.
2. Search **"Google Play Integrity API"** → open it → **Enable**.
3. Check: **APIs & Services → Enabled APIs & services** lists it.

## Step 3 — Put the app in Play Console and link the project

Play Integrity only works for an app that exists in Play Console.

1. Open <https://play.google.com/console/> → **Create app** (if it does not
   exist yet). The **package name** must be exactly the app's
   `applicationId` (for the trial app: `com.shieldsdk.rasp.trial`).
   The package name is fixed by the first upload.
2. Upload a first build to a test track: **Test and release → Testing →
   Internal testing → Create new release**, upload a **release** `.aab`, save,
   roll out to internal testers (add your own Google account as tester).
   This is needed to get `PLAY_RECOGNIZED` later.
3. **Test and release → App integrity** (older UI: **Release → Setup → App
   integrity**) → section **Play Integrity API** → **Link a Cloud project** →
   choose the project from Step 1 → **Link**.
4. On the same page, **Settings** of the Play Integrity API: leave the
   default responses. (Optional extras such as "app access risk" cost
   nothing but the backend does not use them yet.)

## Step 4 — Note the real signing certificate (very important)

With **Play App Signing** (default for new apps) Google re-signs the app with
*its* key. The certificate on users' phones is therefore **not** your upload
key's.

1. **Test and release → App integrity → App signing** tab.
2. Under **App signing key certificate**, copy **SHA-256 certificate fingerprint**.
3. Put it in the dashboard: **Security settings** page → expected signing certificate
   (it is stored without colons; the backend normalises it).
   The same value goes into the app's `expectedSigningCertSha256` RASP config.
   The backend then fails Play Integrity with `SIGNING_CERT_MISMATCH` and the
   on-device `tamper` / `repackage` checks fail if a build is signed by
   anyone else.

Builds you install yourself (Android Studio, `adb install`, the
`RASP_APK` file) are signed with the upload or debug key, so they will not
match this fingerprint — expected.

## Step 5 — Create the service account the backend uses

1. Cloud console (project from Step 1) → **IAM & Admin → Service accounts →
   Create service account**.
   - Name: `rasp-integrity-verifier`. **Create and continue**.
   - Role: none needed. **Continue → Done**.
2. Open the new account → tab **Keys → Add key → Create new key → JSON →
   Create**. A file like `rasp-shield-integrity-abc123.json` downloads.
   - If you see *"Service account key creation is disabled"*, an
     organisation policy (`iam.disableServiceAccountKeyCreation`) blocks it;
     an organisation admin must allow it for this project.
3. Treat that file like a password:
   - do **not** email it, paste it in chat, or put it in git;
   - you can always delete the key in the console and make a new one.

## Step 6 — Install the key on the backend server

On the server (`ssh block@192.168.2.208`, project in `/home/block/Darshan`):

```bash
cd /home/block/Darshan/BE
mkdir -p deploy/secrets
# copy the downloaded file there (scp from your laptop), then:
mv ~/rasp-shield-integrity-*.json deploy/secrets/play-integrity.json
chmod 600 deploy/secrets/play-integrity.json
```

(`deploy/secrets/` and `*play-integrity*.json` are in `.gitignore`.)

Add to the backend's environment file (`BE/.env` for `scripts/office-server.sh`,
or `deploy/production.env` for Docker):

```env
# office server (plain Node):
PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE=/home/block/Darshan/BE/deploy/secrets/play-integrity.json
# Docker deploy instead (the folder is mounted read-only at /secrets):
# PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE=/secrets/play-integrity.json

PLAY_INTEGRITY_ALLOWED_PACKAGES=com.shieldsdk.rasp.trial
PLAY_INTEGRITY_REQUIRE=PLAY_RECOGNIZED
PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS=300
```

Restart: `scripts/office-server.sh restart` (or `docker compose -f
deploy/docker-compose.prod.yml up -d backend`).

Quick check that the endpoint is now configured: without the env vars,
`/v1/integrity/challenge` answers `503 PLAY_INTEGRITY_NOT_CONFIGURED`; with
them, a signed SDK call gets `200 {"nonce": …}`.

## Step 7 — Call it from the app

Kotlin (native Android, any background thread):

```kotlin
val outcome = RaspShieldCore.verifyPlayIntegrityBlocking(context, credential)
when (outcome.verdict) {
    RaspPlayIntegrityVerifier.Verdict.PASS -> { /* genuine */ }
    RaspPlayIntegrityVerifier.Verdict.FAIL -> { /* outcome.reasons, e.g. DEVICE_INTEGRITY_FAILED */ }
    RaspPlayIntegrityVerifier.Verdict.UNAVAILABLE -> { /* outcome.error: no Play Store, offline, … */ }
}
```

`credential` is the same RASP credential the app already uses for events.
The Flutter / React Native plugins do not expose this call yet.

## Step 8 — Testing before the app is live on Play

| How the app was installed | What Google says | What to set |
|---|---|---|
| From the Play **internal testing** link | `PLAY_RECOGNIZED` | defaults — the real test |
| `adb install` / Android Studio / APK file | `UNRECOGNIZED_VERSION` or `UNEVALUATED` | pass the project number: `verifyPlayIntegrityBlocking(context, credential, cloudProjectNumber = 123456789012L)` and, on a **dev** backend only, `PLAY_INTEGRITY_REQUIRE=` (empty) |
| Emulator without Play Store | token request fails `PLAY_STORE_NOT_FOUND` | use a real phone or a "Google Play" emulator image |

Play Console also has **App integrity → Play Integrity API → Settings →
Testing responses**: for licence-tester accounts you can force a chosen
verdict (e.g. "device fails") to test the FAIL path without a rooted phone.

## Reason codes the backend returns

| Code | Meaning |
|---|---|
| `NONCE_MISMATCH` | token not made for this challenge (replay) |
| `PACKAGE_MISMATCH` / `APP_PACKAGE_MISMATCH` | token from another app |
| `TOKEN_TOO_OLD` / `NO_TIMESTAMP` | older than `PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS` |
| `APP_NOT_RECOGNIZED` | Google does not know this build: modified or re-signed |
| `APP_NOT_PLAY_RECOGNIZED` | not installed from Play (when `PLAY_RECOGNIZED` is required) |
| `SIGNING_CERT_MISMATCH` | signed with a key other than the dashboard's expected certificate |
| `DEVICE_INTEGRITY_FAILED` | rooted, emulator, unlocked bootloader or custom ROM |
| `STRONG_INTEGRITY_REQUIRED` | `STRONG` required, device only meets basic/device integrity |
| `NOT_LICENSED` | `LICENSED` required, user did not get the app from Play |
| `TOKEN_REJECTED_BY_GOOGLE` | Google refused to decode it (forged, or another project's) |

HTTP errors (`503`): `PLAY_INTEGRITY_NOT_CONFIGURED`, `GOOGLE_AUTH_FAILED`
(bad/deleted key file), `GOOGLE_UNAVAILABLE`, `SERVICE_ACCOUNT_UNREADABLE`.
`400`: `PACKAGE_NOT_ALLOWED`, `UNKNOWN_OR_USED_NONCE`, `INVALID_BODY`.

## Troubleshooting

- **`GOOGLE_AUTH_FAILED`** — wrong path, file not readable by the backend
  user, or the key was deleted in the console. Make a new key (Step 5).
- **`TOKEN_REJECTED_BY_GOOGLE` on every call** — the Cloud project that owns
  the service account is not the one linked in Play Console (Step 3), or the
  API is not enabled in it (Step 2).
- **App gets `CLOUD_PROJECT_NUMBER_IS_INVALID`** — the number passed in
  Step 8 is the project *ID* or a different project; use the digits from
  Step 1.
- **`TOO_MANY_REQUESTS`** — default quota is 10,000/day per app; request
  more in Play Console → App integrity → Play Integrity API → quota.
- **Clock** — `TOKEN_TOO_OLD` on fresh tokens means the server clock is off;
  enable NTP on the server.

## Rotating / revoking the key

Cloud console → service account → **Keys** → add a new JSON key → replace
`deploy/secrets/play-integrity.json` → restart → delete the old key in the
console. Do this immediately if the file may have leaked.
