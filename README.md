# edhoc

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16246/badge)](https://www.bestpractices.dev/projects/16246)

A Go implementation of EDHOC ([RFC 9528](https://www.rfc-editor.org/rfc/rfc9528)),
the lightweight authenticated key exchange used to set up
[OSCORE](https://www.rfc-editor.org/rfc/rfc8613) contexts on constrained devices.
The package turns EDHOC messages into bytes and back; carrying them, over CoAP
or anything else, is left to the application.

## Status

All of RFC 9528 is implemented except cipher suite 25, which needs X448 and
Ed448, neither of which Go has. Both RFC 9529 traces are reproduced exactly, and
handshakes with [lakers](https://github.com/openwsn-berkeley/lakers) 0.6.2 work
in both roles. The API may change before v1.0.

Supported:

- Authentication methods 0–3, with signature or static DH keys on either side
- Cipher suites 0–6 and 24
- Raw public keys (CCS) by `kid` and X.509 certificates by `x5t`, or either by
  value in `kccs` or `x5chain`; other ID_CRED forms through `ParseIDCred`
- message_4, EAD, error messages and cipher suite negotiation
- EDHOC_Exporter, EDHOC_KeyUpdate and OSCORE parameters
- CoAP payloads (RFC 9528, Appendix A.2)
- A Responder `Config` chosen per session with `Config.GetConfig`

The code is pure Go with no cgo or `unsafe`, and depends only on the standard
library and `golang.org/x/crypto`. Names and comments follow RFC 9528 so the two
can be read side by side.

## Example

See [example_test.go](example_test.go) for complete handshakes, a CoAP server,
cipher suite negotiation and X.509 certificates. In short, with error handling
left out:

```go
cfg := &edhoc.Config{
	Method:         edhoc.MethodStaticStatic,
	Suites:         []edhoc.Suite{edhoc.Suite2},
	Credential:     myCredential,
	Key:            myKey,
	PeerCredential: lookUpPeer, // func(context.Context, *edhoc.PeerInfo) (edhoc.Credential, error)
}

// Initiator
initiator, err := edhoc.NewInitiator(cfg, []byte{0x37}) // C_I for this session
msg1, err := initiator.WriteMessage1()
// send msg1, receive msg2
ead2, err := initiator.ReadMessage2(ctx, msg2)
msg3, err := initiator.WriteMessage3()
// send msg3, receive msg4
ead4, err := initiator.ReadMessage4(msg4)
session, err := initiator.Session()
oscore, err := session.OSCORE()

// Responder
responder, err := edhoc.NewResponder(cfg)
m1, err := responder.ReadMessage1(ctx, msg1)
msg2, err := responder.WriteMessage2(cR) // C_R, different from m1.PeerConnID
// send msg2, receive msg3
ead3, err := responder.ReadMessage3(ctx, msg3)
msg4, err := responder.WriteMessage4()
// send msg4
session, err := responder.Session()
```

When a Read method fails, send `edhoc.ErrorMessage(err)` to the peer, if it is
not nil. Without message_4, the Initiator should not use the session's keys
until it has received a message protected with them (RFC 9528, Section 5.4.2).

## Go versions

Go 1.25 or later. CI tests 1.25 and the two latest releases.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Copyright 2026 Last Lock Inc. Apache License 2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE).
