/**
 * Creates the Ed25519 key pair that signs the malware reputation list
 * (src/reputation/reputationList.ts).
 *
 *   npm run reputation:keygen
 *
 * Prints REPUTATION_SIGNING_KEY (PRIVATE: put it into the server's .env, never
 * into git or a chat) and the public key, which new credentials carry as
 * `reputation_public_key`. Nothing is written to disk.
 */
import crypto from "node:crypto";

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const privateB64 = (privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64");
const publicB64 = (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");

console.log("# Add to the backend .env (keep it secret):");
console.log(`REPUTATION_SIGNING_KEY=${privateB64}`);
console.log("");
console.log("# Public key (not secret) — sent in new credentials as reputation_public_key:");
console.log(publicB64);
