#!/usr/bin/env bash
# Regenerates test/fixtures/attestation-certs.json (test-only keys and certificates).
#   bash test/fixtures/make-attestation-certs.sh
# Needs openssl and node. Chains (leaf first, then a test CA):
#   attested              KeyDescription at TrustedEnvironment level
#   attestedSoftware      KeyDescription at Software level
#   attestedBadExtension  attestation OID present, but an empty SEQUENCE
#   attestedWrongOrder    CA first, leaf second (does not link)
# Test-only: these imitate the structure, not a real Keystore attestation.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # keep "/CN=..." intact under Git Bash
out="$(cd "$(dirname "$0")" && pwd)/attestation-certs.json"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

b64() { base64 -w0 "$1"; }

# KeyDescription DER: version 4, the given security level (twice), empty
# challenge-adjacent fields and empty authorization lists.
key_description_hex() {
  node -e '
    const lvl = Number(process.argv[1]);
    const tlv = (t, c) => Buffer.concat([Buffer.from([t, c.length]), c]);
    const kd = tlv(0x30, Buffer.concat([
      tlv(0x02, Buffer.from([4])), tlv(0x0a, Buffer.from([lvl])),
      tlv(0x02, Buffer.from([41])), tlv(0x0a, Buffer.from([lvl])),
      tlv(0x04, Buffer.from("challenge")), tlv(0x04, Buffer.alloc(0)),
      tlv(0x30, Buffer.alloc(0)), tlv(0x30, Buffer.alloc(0)),
    ]));
    process.stdout.write(kd.toString("hex"));' "$1"
}

sign_leaf() { # <extension DER hex> <out.der>
  printf '1.3.6.1.4.1.11129.2.1.17=DER:%s\n' "$1" > ext.cnf
  openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.pem -CAcreateserial -days 36500 \
    -extfile ext.cnf -outform DER -out "$2" 2>/dev/null
}

openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl ec -in key.pem -pubout -outform DER -out key.spki.der 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out other.pem
openssl ec -in other.pem -pubout -outform DER -out other.spki.der 2>/dev/null

# Self-signed certificate for the device key (what Keystore gives without attestation).
openssl req -new -x509 -key key.pem -subj "/CN=fake" -days 36500 -outform DER -out selfsigned.der
openssl req -new -x509 -key other.pem -subj "/CN=fake" -days 36500 -outform DER -out other-selfsigned.der

# Test CA and leaves for the device key.
openssl ecparam -name prime256v1 -genkey -noout -out ca.pem
openssl req -new -x509 -key ca.pem -subj "/CN=Test Attestation CA" -days 36500 -out ca.crt
openssl x509 -in ca.crt -outform DER -out ca.der
openssl req -new -key key.pem -subj "/CN=Android Keystore Key" -out leaf.csr
sign_leaf "$(key_description_hex 1)" leaf.der
sign_leaf "$(key_description_hex 0)" leaf-software.der
sign_leaf "3000" leaf-badext.der

cat > "$out" <<EOF
{
  "publicKey": "$(b64 key.spki.der)",
  "otherPublicKey": "$(b64 other.spki.der)",
  "selfSigned": ["$(b64 selfsigned.der)"],
  "otherSelfSigned": ["$(b64 other-selfsigned.der)"],
  "attested": ["$(b64 leaf.der)", "$(b64 ca.der)"],
  "attestedSoftware": ["$(b64 leaf-software.der)", "$(b64 ca.der)"],
  "attestedBadExtension": ["$(b64 leaf-badext.der)", "$(b64 ca.der)"],
  "attestedWrongOrder": ["$(b64 ca.der)", "$(b64 leaf.der)"]
}
EOF
echo "wrote $out"
