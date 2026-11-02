# edhoc

A Go implementation of EDHOC, the Ephemeral Diffie-Hellman Over COSE key
exchange defined in [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528).

EDHOC is a lightweight authenticated key exchange for constrained devices. It
is most often used to set up an [OSCORE](https://www.rfc-editor.org/rfc/rfc8613)
security context, but the library does not depend on CoAP or OSCORE. It takes
EDHOC messages as bytes and returns bytes to send.

## Status

Not ready for use. The handshake API does not exist yet; what is here are the
building blocks (CBOR, AES-CCM, key derivation) and their tests. Expect breaking
changes until v1.0.

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
| Cipher suite 2 (AES-CCM-16-64-128, SHA-256, P-256, ES256) | building blocks only |
| Other cipher suites | planned |
| Methods 0–3 | planned |
| message_4, EAD, error messages | planned |
| EDHOC_Exporter, EDHOC_KeyUpdate, OSCORE parameters | planned |

## Go versions

The two most recent Go releases, the same ones the Go team supports.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Apache 2.0. See [LICENSE](LICENSE).
