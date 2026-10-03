# OTA signing keys — public halves only

These are the **public** halves of the OTA signing keys referenced by
`../ota_trust_anchors.json`. The private halves were generated outside this repository
and are not committed here, and `tools/xrom_preflight.py` fails the build if a private
key is ever found anywhere under `security/`.

Generating a replacement pair:

```sh
openssl genpkey -algorithm ed25519 -out ota-ed25519.pem
openssl pkey -in ota-ed25519.pem -pubout -out keys/xrom-ota-NN-ed25519.pub.pem

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ota-rsa4096.pem
openssl pkey -in ota-rsa4096.pem -pubout -out keys/xrom-ota-NN-rsa4096.pub.pem
```

The RSA modulus size is checked at load time and not trusted from the filename: an
anchor claiming `RSA4096_SHA256` while holding a 2048-bit key is rejected, because
2048-bit RSA is what `openssl genpkey` produces by default and it is exactly the
mistake that check exists to catch.

Rotation means adding the new entry, keeping the old one `enabled: true` until every
manifest in the field has been re-signed, and then setting the old one to
`enabled: false`. A disabled anchor is kept in the file rather than deleted, so that a
signature once verified under it can still be explained from the log.
