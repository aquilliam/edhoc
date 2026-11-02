# Changelog

All notable changes to this project are listed here. Versions follow
[semantic versioning](https://semver.org/). Until v1.0.0, minor versions may
include breaking changes.

## v0.1.0 (2026-11-02)

First release.

- The Initiator and Responder for EDHOC (RFC 9528), with all four
  authentication methods, signature and static DH keys in any combination.
- Cipher suites 0, 1, 2, 3, 4, 5, 6 and 24.
- Raw public keys in CWT Claims Sets (`NewCCS`, `ParseCCS`) and X.509
  certificates (`NewX509`). Credentials can be identified by `kid` or `x5t`,
  or sent by value in `x5chain` or `kccs`.
- message_4, EAD items, error messages and cipher suite negotiation.
- `Session.Exporter`, `Session.KeyUpdate` and `Session.OSCORE` for deriving
  application keys and an OSCORE security context.
- Reproduces both RFC 9529 traces byte for byte, and interoperates with
  lakers 0.6.2 in both roles.
