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
  both connection identifiers. It also takes a `context.Context`: the one
  passed to `ReadMessage2` or `ReadMessage3`, which now take it as their first
  argument. Replace `func(id edhoc.IDCred)` with
  `func(ctx context.Context, p *edhoc.PeerInfo)` and use `p.ID`.
- `Error.Code`, `PeerError.Code` and the `ErrCode` constants have their own
  type, `ErrCode`, instead of `int`.
- `ReadMessage1`, `ReadMessage2`, `ReadMessage3` and `ReadMessage4` return the
  EAD items of the message, and `PeerEAD` is gone. `ReadMessage1` now takes a
  `context.Context` as its first argument, passed to `Config.GetConfig`.
- `Initiator.PeerCredential` and `Responder.PeerCredential` are gone. Use
  `Session.PeerCredential`, or record the credential in
  `Config.PeerCredential`.
- `OSCOREContext` is renamed `OSCOREParams`.
- `Config.Key` has type `crypto.PrivateKey`.
- A Responder's `Config.Key` must be usable with every suite in
  `Config.Suites`, and an Initiator's with the suite it selects.
  `NewResponder` and `NewInitiator` return an error otherwise, instead of the
  session failing at message_2 or message_3.

Other changes:

- `Config.GetConfig` lets a Responder choose its `Config` after reading
  message_1, from the method, the suites, EAD_1 and the connection
  identifiers. One Responder can then accept several methods, or use a
  different credential per suite.
- `CoAPMessage1`, `CoAPRequest` and `ParseCoAPRequest` build and split the
  payloads of CoAP requests to the EDHOC resource (RFC 9528, Appendix A.2).
- `Session.Close` erases the session's keys. The Initiator and Responder erase
  the handshake keys once they are no longer needed.
- Examples of a CoAP server, a retry after a wrong-suite error, and X.509
  certificates checked against a root.

- `Method`, `Suite` and `ErrCode` have `String` methods.
- `ErrWrongState` is returned when a method is called out of order or after
  the session has failed, and can be checked with `errors.Is`.
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
