/**
 * Creates the Ed25519 key pair that signs the remote configuration
 * (src/remoteConfig/signing.ts, Task 10.0).
 *
 *   npm run config:keygen
 *
 * Prints CONFIG_SIGNING_KEY (PRIVATE: put it only into the server's .env,
 * never into git, a chat, a ticket or the dashboard) and the public key,
 * which new credentials carry as `config_public_key`. Nothing is written to
 * disk. Run it once per environment; a new key means every app needs a newly
 * issued credential (see docs/REMOTE_CONFIG.md, key rotation).
 */
import crypto from "node:crypto";

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const privateB64 = (privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64");
const publicB64 = (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");

console.log("# Add to the backend .env (keep it secret; do not paste it anywhere else):");
console.log(`CONFIG_SIGNING_KEY=${privateB64}`);
console.log("");
console.log("# Public key (not secret) — sent in new credentials as config_public_key:");
console.log(publicB64);
