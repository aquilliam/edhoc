// Package edhoc implements EDHOC, the Ephemeral Diffie-Hellman Over COSE key
// exchange defined in RFC 9528.
//
// EDHOC runs between an Initiator and a Responder:
//
//	Initiator                         Responder
//	WriteMessage1  --- message_1 -->  ReadMessage1
//	ReadMessage2   <-- message_2 ---  WriteMessage2
//	WriteMessage3  --- message_3 -->  ReadMessage3
//	ReadMessage4   <-- message_4 ---  WriteMessage4   (optional)
//
// The package only turns messages into bytes and back; carrying them is up
// to the application. For CoAP (RFC 9528, Appendix A.2), CoAPMessage1 and
// CoAPRequest build request payloads, and ParseCoAPRequest gives a server the
// C_R that tells it which Responder a message_3 is for. Each Read method
// returns the EAD items of the message. When a Read method fails, send the
// peer the bytes from ErrorMessage, if any, and drop the session.
//
// After message_3, both sides have a Session, from which application keys are
// derived with Session.Exporter, or the parameters of an OSCORE context with
// Session.OSCORE. Session.Close erases its keys.
//
// # Credentials
//
// Each side has a Credential (CRED_I or CRED_R), identified on the wire by an
// IDCred (ID_CRED_I or ID_CRED_R). The library calls Config.PeerCredential to
// turn the peer's IDCred into its Credential, then checks that the peer holds
// the private key. Deciding whether that credential is one the application
// trusts for this connection is up to the application (RFC 9528, Appendix D).
// A Responder can choose its own credential, key and method once it has seen
// message_1 with Config.GetConfig.
// That matters most when the peer sends its credential by value, in an
// x5chain (IDCred.X5Chain) or kccs (IDCred.KCCS): anyone can send a
// credential, so PeerCredential must check it against a trust anchor or a
// list of known keys before returning it.
//
// # Status
//
// The package implements all four authentication methods with cipher suites
// 0 to 6 and 24. Credentials can be raw public keys in a CWT Claims Set (NewCCS,
// ParseCCS) or X.509 certificates (NewX509); any other form can be used by
// filling in a Credential directly. The API may change before v1.0.
package edhoc
