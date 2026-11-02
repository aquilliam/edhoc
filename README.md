# edhoc

A Go implementation of EDHOC, the Ephemeral Diffie-Hellman Over COSE key
exchange defined in [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528).

EDHOC is a lightweight authenticated key exchange for constrained devices. It
is most often used to set up an [OSCORE](https://www.rfc-editor.org/rfc/rfc8613)
security context, but the library does not depend on CoAP or OSCORE. It takes
EDHOC messages as bytes and returns bytes to send.

## Status

Early. Methods 0–3 with cipher suites 0 to 6 and 24 work, and both RFC 9529 traces
are reproduced byte for byte; the rest of the RFC is still to come. Expect
breaking changes until v1.0.

## Goals

- Pure Go. No cgo, no `unsafe`, no assembly.
- Dependencies limited to the standard library and `golang.org/x/crypto`.
- Byte-for-byte agreement with the [RFC 9529](https://www.rfc-editor.org/rfc/rfc9529)
  traces, and interoperability with other EDHOC implementations.
- Code that can be read next to the RFC: names, files and comments follow
  RFC 9528.

## Supported

| | Status |
|---|---|
| Cipher suite 0 (AES-CCM-16-64-128, SHA-256, X25519, EdDSA) | yes |
| Cipher suite 1 (AES-CCM-16-128-128, SHA-256, X25519, EdDSA) | yes |
| Cipher suite 2 (AES-CCM-16-64-128, SHA-256, P-256, ES256) | yes |
| Cipher suite 3 (AES-CCM-16-128-128, SHA-256, P-256, ES256) | yes |
| Cipher suite 4 (ChaCha20/Poly1305, SHA-256, X25519, EdDSA) | yes |
| Cipher suite 5 (ChaCha20/Poly1305, SHA-256, P-256, ES256) | yes |
| Cipher suite 6 (A128GCM, SHA-256, X25519, ES256) | yes |
| Cipher suite 24 (A256GCM, SHA-384, P-384, ES384) | yes |
| Cipher suite 25 (X448, SHAKE256) | not planned until Go has X448 and Ed448 |
| Methods 0–3 (signature and static DH keys, in any combination) | yes |
| message_4, EAD, error messages, cipher suite negotiation | yes |
| EDHOC_Exporter, EDHOC_KeyUpdate, OSCORE parameters | yes |
| Raw public keys (CCS) identified by `kid` | yes |
| X.509 certificates identified by `x5t` | yes |
| Credentials sent by value in `x5chain` or `kccs` | yes |
| Other ID_CRED forms | through `ParseIDCred` |

## Example

See [example_test.go](example_test.go) for a complete handshake. In short:

```go
initiator, err := edhoc.NewInitiator(&edhoc.Config{
	Method:         edhoc.MethodStaticStatic,
	Suites:         []edhoc.Suite{edhoc.Suite2},
	ConnID:         []byte{0x37},
	Credential:     myCredential,
	Key:            myKey,
	PeerCredential: lookUpPeer,
})
msg1, err := initiator.WriteMessage1()
// send msg1, receive msg2
err = initiator.ReadMessage2(msg2)
msg3, err := initiator.WriteMessage3()
// send msg3
session, err := initiator.Session()
oscore, err := session.OSCORE()
```

## Go versions

The two most recent Go releases, the same ones the Go team supports.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Copyright 2026 Last Lock Inc. Licensed under the Apache License, Version 2.0;
see [LICENSE](LICENSE) and [NOTICE](NOTICE). You may use, modify and
redistribute it, including in commercial and closed-source products.
