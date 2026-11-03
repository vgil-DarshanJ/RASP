// Builds X.509 certificates in DER for tests: a self-signed test root and
// leaf certificates carrying an Android KeyDescription (attestation
// extension) for a key the test holds. Signed with real ECDSA P-256 keys,
// so node:crypto verifies them like device chains. Test-only.
import crypto from "node:crypto";

const len = (n: number): Buffer => {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
};
const tlv = (tag: number, content: Buffer) => Buffer.concat([Buffer.from([tag]), len(content.length), content]);
export const seq = (...items: Buffer[]) => tlv(0x30, Buffer.concat(items));
export const set = (...items: Buffer[]) => tlv(0x31, Buffer.concat(items));
export const octet = (b: Buffer | string) => tlv(0x04, Buffer.isBuffer(b) ? b : Buffer.from(b, "utf8"));
export const bool = (v: boolean) => tlv(0x01, Buffer.from([v ? 0xff : 0]));
export const enumerated = (v: number) => tlv(0x0a, Buffer.from([v]));
export function int(v: number | bigint): Buffer {
  let hex = BigInt(v).toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let b = Buffer.from(hex, "hex");
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}
function oid(dotted: string): Buffer {
  const parts = dotted.split(".").map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const p of parts.slice(2)) {
    const chunk: number[] = [];
    let v = p;
    do {
      chunk.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80;
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}
/** [tag] EXPLICIT (context-specific, constructed), high tag numbers included. */
export function explicit(tag: number, content: Buffer): Buffer {
  if (tag < 31) return tlv(0xa0 | tag, content);
  const t: number[] = [];
  let v = tag;
  do {
    t.unshift(v & 0x7f);
    v = Math.floor(v / 128);
  } while (v > 0);
  for (let i = 0; i < t.length - 1; i++) t[i] |= 0x80;
  return Buffer.concat([Buffer.from([0xbf, ...t]), len(content.length), content]);
}
const name = (cn: string) => seq(set(seq(oid("2.5.4.3"), tlv(0x0c, Buffer.from(cn, "utf8")))));
const time = (d: Date) => tlv(0x18, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z", "ascii"));
const ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"));

export interface Issued {
  der: Buffer;
  base64: string;
  key: crypto.KeyObject;
  cert: crypto.X509Certificate;
}

function certificate(args: {
  serial: number;
  issuer: string;
  subject: string;
  subjectPublicKey: crypto.KeyObject;
  signingKey: crypto.KeyObject;
  notBefore: Date;
  notAfter: Date;
  extensions?: Buffer[];
  ca?: boolean;
}): Buffer {
  const spki = args.subjectPublicKey.export({ type: "spki", format: "der" }) as Buffer;
  const exts = [...(args.extensions ?? [])];
  if (args.ca) exts.push(seq(oid("2.5.29.19"), bool(true), octet(seq(bool(true)))));
  const tbs = seq(
    explicit(0, int(2)),
    int(args.serial),
    ECDSA_SHA256,
    name(args.issuer),
    seq(time(args.notBefore), time(args.notAfter)),
    name(args.subject),
    spki,
    ...(exts.length ? [explicit(3, seq(...exts))] : []),
  );
  const signature = crypto.sign("sha256", tbs, { key: args.signingKey, dsaEncoding: "der" });
  return seq(tbs, ECDSA_SHA256, tlv(0x03, Buffer.concat([Buffer.from([0]), signature])));
}

const wrap = (der: Buffer, key: crypto.KeyObject): Issued => ({ der, base64: der.toString("base64"), key, cert: new crypto.X509Certificate(der) });

export function testRoot(cn = "Attestation test root", serial = 1): Issued {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const der = certificate({
    serial, issuer: cn, subject: cn, subjectPublicKey: publicKey, signingKey: privateKey,
    notBefore: new Date("2025-01-01T00:00:00Z"), notAfter: new Date("2035-01-01T00:00:00Z"), ca: true,
  });
  return wrap(der, privateKey);
}

export interface KeyDescriptionSpec {
  securityLevel?: number;
  challenge?: Buffer;
  packages?: string[];
  signingDigestsHex?: string[];
  deviceLocked?: boolean;
  verifiedBootState?: number;
  osPatchLevel?: number;
}

export function keyDescription(spec: KeyDescriptionSpec = {}): Buffer {
  const level = spec.securityLevel ?? 1;
  const software: Buffer[] = [];
  if (spec.packages) {
    const appId = seq(
      set(...spec.packages.map((p) => seq(octet(p), int(1)))),
      set(...(spec.signingDigestsHex ?? []).map((d) => octet(Buffer.from(d, "hex")))),
    );
    software.push(explicit(709, octet(appId)));
  }
  const hardware: Buffer[] = [];
  if (spec.deviceLocked !== undefined || spec.verifiedBootState !== undefined) {
    hardware.push(explicit(704, seq(octet(Buffer.alloc(32, 1)), bool(spec.deviceLocked ?? true), enumerated(spec.verifiedBootState ?? 0), octet(Buffer.alloc(32, 2)))));
  }
  if (spec.osPatchLevel !== undefined) hardware.push(explicit(706, int(spec.osPatchLevel)));
  return seq(int(300), enumerated(level), int(300), enumerated(level), octet(spec.challenge ?? Buffer.from("local-challenge")), octet(Buffer.alloc(0)), seq(...software), seq(...hardware));
}

/** A device key and its leaf certificate (KeyDescription extension), signed by [issuer]. */
export function attestedLeaf(issuer: Issued, spec: KeyDescriptionSpec = {}, serial = 2): Issued & { publicKey: crypto.KeyObject } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const der = certificate({
    serial, issuer: issuer.cert.subject.replace(/^CN=/, ""), subject: "Android Keystore Key", subjectPublicKey: publicKey, signingKey: issuer.key,
    notBefore: new Date("1970-01-01T00:00:00Z"), notAfter: new Date("2048-01-01T00:00:00Z"),
    extensions: [seq(oid("1.3.6.1.4.1.11129.2.1.17"), octet(keyDescription(spec)))],
  });
  return { ...wrap(der, privateKey), publicKey };
}

/** Base64 SPKI of [key], as the SDK sends it. */
export const spkiBase64 = (key: crypto.KeyObject) => (key.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
