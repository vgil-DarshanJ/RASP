#!/usr/bin/env bash
# Regenerates test/fixtures/attestation-certs.json (test-only keys and certificates).
#   bash test/fixtures/make-attestation-certs.sh
# Needs openssl. The "attested" chain is leaf -> test CA, with the Android key
# attestation extension OID (1.3.6.1.4.1.11129.2.1.17) present but empty: it
# exercises parsing, key matching and chain linking, not a real attestation.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # keep "/CN=..." intact under Git Bash
out="$(cd "$(dirname "$0")" && pwd)/attestation-certs.json"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

b64() { base64 -w0 "$1"; }

openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl ec -in key.pem -pubout -outform DER -out key.spki.der 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out other.pem
openssl ec -in other.pem -pubout -outform DER -out other.spki.der 2>/dev/null

# Self-signed certificate for the device key (what Keystore gives without attestation).
openssl req -new -x509 -key key.pem -subj "/CN=fake" -days 36500 -outform DER -out selfsigned.der
openssl req -new -x509 -key other.pem -subj "/CN=fake" -days 36500 -outform DER -out other-selfsigned.der

# Test CA and a leaf for the device key carrying the attestation extension OID.
openssl ecparam -name prime256v1 -genkey -noout -out ca.pem
openssl req -new -x509 -key ca.pem -subj "/CN=Test Attestation CA" -days 36500 -out ca.crt
openssl x509 -in ca.crt -outform DER -out ca.der
openssl req -new -key key.pem -subj "/CN=Android Keystore Key" -out leaf.csr
printf '1.3.6.1.4.1.11129.2.1.17=DER:3000\n' > ext.cnf
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.pem -CAcreateserial -days 36500 \
  -extfile ext.cnf -outform DER -out leaf.der 2>/dev/null

cat > "$out" <<EOF
{
  "publicKey": "$(b64 key.spki.der)",
  "otherPublicKey": "$(b64 other.spki.der)",
  "selfSigned": ["$(b64 selfsigned.der)"],
  "otherSelfSigned": ["$(b64 other-selfsigned.der)"],
  "attested": ["$(b64 leaf.der)", "$(b64 ca.der)"]
}
EOF
echo "wrote $out"
