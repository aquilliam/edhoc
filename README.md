# edhoc

A Go implementation of EDHOC, the Ephemeral Diffie-Hellman Over COSE key
exchange defined in [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528).

EDHOC is a lightweight authenticated key exchange for constrained devices. It
is most often used to set up an [OSCORE](https://www.rfc-editor.org/rfc/rfc8613)
security context, but the library does not depend on CoAP or OSCORE. It takes
EDHOC messages as bytes and returns bytes to send.

## Status

Early. Method 3 with cipher suite 2 works and reproduces the RFC 9529 trace
byte for byte; the rest of the RFC is still to come. Expect breaking changes
until v1.0.

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
| Cipher suite 2 (AES-CCM-16-64-128, SHA-256, P-256, ES256) | yes |
| Other cipher suites | planned |
| Method 3 (static DH keys on both sides) | yes |
| Methods 0–2 (signature keys) | planned |
| message_4, EAD, error messages, cipher suite negotiation | yes |
| EDHOC_Exporter, EDHOC_KeyUpdate, OSCORE parameters | yes |
| Raw public keys (CCS) identified by `kid` | yes |
| Other credential types and ID_CRED forms | planned |

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

Apache 2.0. See [LICENSE](LICENSE).
