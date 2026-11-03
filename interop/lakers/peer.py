"""One side of an EDHOC session run by lakers, driven over stdin and stdout.

Usage: peer.py initiator|responder reference|value

Messages, including message_4, are exchanged as hex lines. After the handshake the peer prints the
OSCORE master secret and salt, then the master secret after a key update.
"""

import sys

import lakers

# From the lakers-python tests: RFC 9529 trace 2 keys, with CRED_I shortened.
CRED_I = bytes.fromhex("A202617808A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
I = bytes.fromhex("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b")
R = bytes.fromhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")
CRED_R = bytes.fromhex("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072")
CONTEXT = bytes.fromhex("a01158fdb820890cd6be169602b8bcea")


def send(b):
    print(bytes(b).hex(), flush=True)


def recv():
    return bytes.fromhex(sys.stdin.readline().strip())


def main():
    role, transfer = sys.argv[1], sys.argv[2]
    t = lakers.CredentialTransfer.ByValue if transfer == "value" else lakers.CredentialTransfer.ByReference
    if role == "initiator":
        p = lakers.EdhocInitiator()
        send(p.prepare_message_1(c_i=None, ead_1=None))
        _, id_cred_r, _ = p.parse_message_2(recv())
        p.verify_message_2(I, CRED_I, lakers.credential_check_or_fetch(id_cred_r, CRED_R))
        message_3, _ = p.prepare_message_3(t, None)
        send(message_3)
        p.process_message_4(recv())
    else:
        p = lakers.EdhocResponder(R, CRED_R)
        p.process_message_1(recv())
        send(p.prepare_message_2(t, None, None))
        id_cred_i, _ = p.parse_message_3(recv())
        p.verify_message_3(lakers.credential_check_or_fetch(id_cred_i, CRED_I))
        send(p.prepare_message_4(None))
    send(p.edhoc_exporter(0, [], 16))
    send(p.edhoc_exporter(1, [], 8))
    p.edhoc_key_update(list(CONTEXT))
    send(p.edhoc_exporter(0, [], 16))


main()
