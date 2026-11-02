# Changelog

All notable changes to this project are listed here. Versions follow
[semantic versioning](https://semver.org/). Until v1.0.0, minor versions may
include breaking changes.

## v0.2.0 (unreleased)

This release changes the API so that one `Config` can serve every session on
a side.

Breaking changes:

- `Config.ConnID` is gone. Pass the connection identifier to
  `NewInitiator(cfg, connID)` or `NewResponder(cfg, connID)` instead.
- `Config.PeerSuites` is gone. After a wrong-suite error, pass the suites from
  the `*PeerError` to `NewInitiator(cfg, connID, peerErr.Suites...)`.
- `Config.PeerCredential` now takes a `*PeerInfo` instead of an `IDCred`. It
  carries the ID_CRED field in `ID`, the EAD items of the same message, and
  both connection identifiers. Replace `func(id edhoc.IDCred)` with
  `func(p *edhoc.PeerInfo)` and use `p.ID`.

Other changes:

- `IDCred` values can be compared with `==` and used as map keys.
- `Session` is safe for concurrent use. `OSCORE` derives the secret and salt
  from the same PRK_out even while another goroutine calls `KeyUpdate`.
- An unsupported critical EAD item now fails the session before
  `PeerCredential` is called.
- The `Config.Key` documentation lists ES384 keys.

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
