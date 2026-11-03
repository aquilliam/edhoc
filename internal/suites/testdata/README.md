- `ecdsa_secp256r1_sha256_p1363_test.json`: from [Project Wycheproof](https://github.com/C2SP/wycheproof)
  (`testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json`), Apache 2.0.
- `ecdsa_secp384r1_sha384_p1363_test.json`: from [Project Wycheproof](https://github.com/C2SP/wycheproof)
  (`testvectors_v1/ecdsa_secp384r1_sha384_p1363_test.json`), Apache 2.0.
- `kmac256.txt`: KMAC256 outputs with an empty customization string from
  OpenSSL 3.6.3. Each line is the key length, data length and output length in
  bytes, then the output. Key byte i is 1+7i and data byte i is 2+7i, mod 256.
