/*
 * One side of an EDHOC session run by libedhoc, driven over stdin and stdout
 * like peer.py. Credentials are sent by reference only.
 *
 * Usage: peer initiator|responder reference
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include <edhoc/edhoc.h>

/* The keys and credentials of peer.py. Public keys are x-coordinates. */
static const char *CRED_I_HEX =
	"A202617808A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
static const char *I_HEX =
	"fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
static const char *G_I_HEX =
	"AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB6";
static const char *CRED_R_HEX =
	"A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
static const char *R_HEX =
	"72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac";
static const char *G_R_HEX =
	"BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F0";
static const char *CONTEXT_HEX = "a01158fdb820890cd6be169602b8bcea";

static const uint8_t KID_I[] = { 0x2b };
static const uint8_t KID_R[] = { 0x0a };

struct party {
	struct edhoc_buffer cred, kid, pub;
	const char *priv_hex;
};

static struct party own, other;

static void fail(const char *what, int code)
{
	fprintf(stderr, "libedhoc peer: %s: %d\n", what, code);
	exit(1);
}

static struct edhoc_buffer unhex(const char *s, uint8_t *buf, size_t size)
{
	size_t n = strlen(s) / 2;
	if (n > size)
		fail("hex too long", (int)n);
	for (size_t i = 0; i < n; i++) {
		unsigned v;
		if (sscanf(s + 2 * i, "%2x", &v) != 1)
			fail("bad hex", 0);
		buf[i] = (uint8_t)v;
	}
	return (struct edhoc_buffer){ .value = buf, .length = n };
}

static void send_bytes(const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		fprintf(stdout, "%02x", p[i]);
	fputc('\n', stdout);
	fflush(stdout);
}

static size_t recv_bytes(uint8_t *buf, size_t size)
{
	static char line[8192];
	if (!fgets(line, sizeof(line), stdin))
		fail("stdin closed", 0);
	line[strcspn(line, "\r\n")] = 0;
	return unhex(line, buf, size).length;
}

static int select_local(void *user_ctx, const struct edhoc_call_context *call,
			struct edhoc_credential_selected *selected)
{
	(void)user_ctx;
	(void)call;
	selected->asymmetric.label = EDHOC_COSE_HEADER_KID;
	selected->asymmetric.kid.identifier = own.kid;
	selected->asymmetric.kid.credential = own.cred;
	selected->asymmetric.kid.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	uint8_t priv[32];
	unhex(own.priv_hex, priv, sizeof(priv));
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_key_id_t id = PSA_KEY_ID_NULL;
	if (psa_import_key(&attr, priv, sizeof(priv), &id) != PSA_SUCCESS)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	memcpy(selected->asymmetric.private_key_id, &id, sizeof(id));
	return EDHOC_SUCCESS;
}

static int authenticate_peer(void *user_ctx,
			     const struct edhoc_call_context *call,
			     const struct edhoc_credential_received *received,
			     struct edhoc_credential_trusted *trusted)
{
	(void)user_ctx;
	(void)call;
	if (received->label != EDHOC_COSE_HEADER_KID ||
	    received->kid.identifier.length != other.kid.length ||
	    memcmp(received->kid.identifier.value, other.kid.value,
		   other.kid.length) != 0)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	trusted->asymmetric.credential = other.cred;
	trusted->asymmetric.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
	trusted->asymmetric.public_key = other.pub;
	return EDHOC_SUCCESS;
}

static void zeroize(void *p, size_t n)
{
	memset(p, 0, n);
}

static void check(const char *what, int ret)
{
	if (ret != EDHOC_SUCCESS)
		fail(what, ret);
}

static void send_message(struct edhoc_context *ctx,
			 int (*compose)(struct edhoc_context *, uint8_t *,
					size_t, size_t *),
			 const char *what)
{
	uint8_t buf[1024];
	size_t len = 0;
	check(what, compose(ctx, buf, sizeof(buf), &len));
	send_bytes(buf, len);
}

static void receive_message(struct edhoc_context *ctx,
			    int (*process)(struct edhoc_context *,
					   const uint8_t *, size_t),
			    const char *what)
{
	uint8_t buf[1024];
	size_t len = recv_bytes(buf, sizeof(buf));
	check(what, process(ctx, buf, len));
}

static void export_secret_and_salt(struct edhoc_context *ctx, int with_salt)
{
	uint8_t secret[16], salt[8], sid[8], rid[8];
	size_t sid_len = 0, rid_len = 0;
	check("export OSCORE context",
	      edhoc_export_oscore_context_raw(ctx, secret, sizeof(secret), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len));
	send_bytes(secret, sizeof(secret));
	if (with_salt)
		send_bytes(salt, sizeof(salt));
}

int main(int argc, char **argv)
{
	if (argc != 3)
		fail("usage: peer initiator|responder reference", 0);
	if (strcmp(argv[2], "reference") != 0)
		fail("only credentials by reference are supported", 0);
	int initiator = strcmp(argv[1], "initiator") == 0;

	static uint8_t cred_i[128], cred_r[128], g_i[32], g_r[32];
	struct party i = {
		.cred = unhex(CRED_I_HEX, cred_i, sizeof(cred_i)),
		.kid = { .value = KID_I, .length = sizeof(KID_I) },
		.pub = unhex(G_I_HEX, g_i, sizeof(g_i)),
		.priv_hex = I_HEX,
	};
	struct party r = {
		.cred = unhex(CRED_R_HEX, cred_r, sizeof(cred_r)),
		.kid = { .value = KID_R, .length = sizeof(KID_R) },
		.pub = unhex(G_R_HEX, g_r, sizeof(g_r)),
		.priv_hex = R_HEX,
	};
	own = initiator ? i : r;
	other = initiator ? r : i;

	if (psa_crypto_init() != PSA_SUCCESS)
		fail("psa_crypto_init", 0);

	struct edhoc_context *ctx = calloc(1, edhoc_context_size());
	const enum edhoc_method methods[] = { EDHOC_METHOD_3 };
	const uint8_t cid[] = { 0x0c };
	const struct edhoc_buffer conn_id = { .value = cid,
					      .length = sizeof(cid) };
	static const struct edhoc_credentials creds = {
		.select_local = select_local,
		.authenticate_peer = authenticate_peer,
	};
	static const struct edhoc_platform platform = { .zeroize = zeroize };

	check("context init", edhoc_context_init(ctx));
	check("methods", edhoc_set_methods(ctx, methods, 1));
	check("cipher suites",
	      edhoc_set_cipher_suites(
		      ctx, edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2),
		      1));
	check("connection id", edhoc_set_connection_id(ctx, &conn_id));
	check("crypto",
	      edhoc_bind_crypto(
		      ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2)));
	check("platform", edhoc_bind_platform(ctx, &platform));
	check("credentials", edhoc_bind_credentials(ctx, &creds));

	if (initiator) {
		send_message(ctx, edhoc_message_1_compose, "message_1");
		receive_message(ctx, edhoc_message_2_process, "message_2");
		send_message(ctx, edhoc_message_3_compose, "message_3");
		receive_message(ctx, edhoc_message_4_process, "message_4");
	} else {
		receive_message(ctx, edhoc_message_1_process, "message_1");
		send_message(ctx, edhoc_message_2_compose, "message_2");
		receive_message(ctx, edhoc_message_3_process, "message_3");
		send_message(ctx, edhoc_message_4_compose, "message_4");
	}

	export_secret_and_salt(ctx, 1);
	uint8_t context[16];
	struct edhoc_buffer c = unhex(CONTEXT_HEX, context, sizeof(context));
	check("key update", edhoc_export_key_update(ctx, c.value, c.length));
	export_secret_and_salt(ctx, 0);
	return 0;
}
