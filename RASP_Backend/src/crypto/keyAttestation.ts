/**
 * Reads the Android key attestation extension (OID 1.3.6.1.4.1.11129.2.1.17,
 * `KeyDescription`) from a DER X.509 certificate. Node's X509Certificate does
 * not expose extensions, so this walks the DER directly — only as far as the
 * attestation security level (KeyDescription field 1).
 */

interface Tlv {
  tagClass: number; // 0 universal, 2 context-specific
  constructed: boolean;
  tagNumber: number;
  content: Buffer;
}

function readTlv(buf: Buffer, offset: number): { tlv: Tlv; next: number } {
  let pos = offset;
  const need = (n: number) => {
    if (pos + n > buf.length) throw new Error("truncated DER");
  };
  need(1);
  const first = buf[pos++];
  let tagNumber = first & 0x1f;
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    let b: number;
    do {
      need(1);
      b = buf[pos++];
      tagNumber = (tagNumber << 7) | (b & 0x7f);
      if (tagNumber > 1 << 24) throw new Error("tag number too large");
    } while (b & 0x80);
  }
  need(1);
  let length = buf[pos++];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count < 1 || count > 4) throw new Error("unsupported DER length");
    need(count);
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buf[pos++];
  }
  need(length);
  return {
    tlv: { tagClass: first >> 6, constructed: (first & 0x20) !== 0, tagNumber, content: buf.subarray(pos, pos + length) },
    next: pos + length,
  };
}

function children(tlv: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let pos = 0;
  while (pos < tlv.content.length) {
    const { tlv: child, next } = readTlv(tlv.content, pos);
    out.push(child);
    pos = next;
  }
  return out;
}

const ATTESTATION_OID = Buffer.from([0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11]);

/** The raw extension value (KeyDescription DER), or `null` when the certificate has none. */
export function attestationExtension(certDer: Buffer): Buffer | null {
  const cert = readTlv(certDer, 0).tlv;
  const tbs = children(cert)[0];
  // Extensions: [3] EXPLICIT SEQUENCE OF Extension, in tbsCertificate.
  const extWrapper = children(tbs).find((t) => t.tagClass === 2 && t.tagNumber === 3);
  if (!extWrapper) return null;
  for (const ext of children(children(extWrapper)[0])) {
    const parts = children(ext); // OID, [critical BOOLEAN], OCTET STRING value
    if (parts[0]?.tagNumber === 6 && parts[0].content.equals(ATTESTATION_OID)) {
      return parts[parts.length - 1].content;
    }
  }
  return null;
}

/** Security level of an attestation: 0 Software, 1 TrustedEnvironment, 2 StrongBox. */
export function attestationSecurityLevel(keyDescription: Buffer): number {
  const fields = children(readTlv(keyDescription, 0).tlv);
  if (fields.length < 8) throw new Error(`KeyDescription has ${fields.length} fields, expected 8`);
  const level = fields[1];
  if (level.tagNumber !== 10 || level.content.length !== 1) throw new Error("attestationSecurityLevel is not an ENUMERATED");
  return level.content[0];
}
