/*
 * One side of an EDHOC session run by uoscore-uedhoc, driven over stdin and
 * stdout like peer.py.
 *
 * Usage: peer initiator|responder reference|value
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dh.h>

#include "edhoc.h"

/* The keys and credentials of peer.py. */
static const char *CRED_I_HEX =
	"A202617808A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
static const char *I_HEX =
	"fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
/* Static DH public keys as x-coordinates, the form the tinycrypt backend
 * decompresses. */
static const char *G_I_HEX =
	"AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB6";
static const char *CRED_R_HEX =
	"A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";
static const char *R_HEX =
	"72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac";
static const char *G_R_HEX =
	"BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F0";
static const char *CONTEXT_HEX = "a01158fdb820890cd6be169602b8bcea";

static uint8_t KID_I[] = { 0xa1, 0x04, 0x41, 0x2b };
static uint8_t KID_R[] = { 0xa1, 0x04, 0x41, 0x0a };

static void fail(const char *what, int code)
{
	fprintf(stderr, "uoscore peer: %s: %d\n", what, code);
	exit(1);
}

static struct byte_array unhex(const char *s)
{
	size_t n = strlen(s) / 2;
	uint8_t *b = malloc(n ? n : 1);
	for (size_t i = 0; i < n; i++) {
		unsigned v;
		if (sscanf(s + 2 * i, "%2x", &v) != 1)
			fail("bad hex", 0);
		b[i] = (uint8_t)v;
	}
	return (struct byte_array){ .len = (uint32_t)n, .ptr = b };
}

static void send_bytes(const uint8_t *p, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++)
		fprintf(stdout, "%02x", p[i]);
	fputc('\n', stdout);
	fflush(stdout);
}

static enum err tx(void *sock, struct byte_array *data)
{
	(void)sock;
	send_bytes(data->ptr, data->len);
	return ok;
}

static enum err rx(void *sock, struct byte_array *data)
{
	(void)sock;
	static char line[8192];
	if (!fgets(line, sizeof(line), stdin))
		fail("stdin closed", 0);
	line[strcspn(line, "\r\n")] = 0;
	struct byte_array b = unhex(line);
	if (b.len > data->len)
		fail("message too long", (int)b.len);
	memcpy(data->ptr, b.ptr, b.len);
	data->len = b.len;
	free(b.ptr);
	return ok;
}

static enum err ead_process(void *params, struct byte_array *ead)
{
	(void)params;
	(void)ead;
	return ok;
}

/* by_value returns { 14 : ccs }, the ID_CRED that carries ccs by value. */
static struct byte_array by_value(struct byte_array ccs)
{
	uint8_t *b = malloc(ccs.len + 2);
	b[0] = 0xa1;
	b[1] = 0x0e;
	memcpy(b + 2, ccs.ptr, ccs.len);
	return (struct byte_array){ .len = ccs.len + 2, .ptr = b };
}

static void export_all(uint8_t prk_out_buf[32])
{
	struct byte_array prk_out = { .len = 32, .ptr = prk_out_buf };
	uint8_t exp_buf[32], out_buf[16], new_buf[32];
	struct byte_array prk_exporter = { .len = 32, .ptr = exp_buf };
	struct byte_array out;
	enum err e;

	if ((e = prk_out2exporter(SHA_256, &prk_out, &prk_exporter)) != ok)
		fail("prk_out2exporter", e);
	out = (struct byte_array){ .len = 16, .ptr = out_buf };
	if ((e = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
				&out)) != ok)
		fail("exporter", e);
	send_bytes(out.ptr, out.len);
	out = (struct byte_array){ .len = 8, .ptr = out_buf };
	if ((e = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter,
				&out)) != ok)
		fail("exporter", e);
	send_bytes(out.ptr, out.len);

	struct byte_array context = unhex(CONTEXT_HEX);
	struct byte_array prk_new = { .len = 32, .ptr = new_buf };
	if ((e = prk_out_update(SHA_256, &prk_out, &context, &prk_new)) != ok)
		fail("prk_out_update", e);
	prk_exporter.len = 32;
	if ((e = prk_out2exporter(SHA_256, &prk_new, &prk_exporter)) != ok)
		fail("prk_out2exporter", e);
	out = (struct byte_array){ .len = 16, .ptr = out_buf };
	if ((e = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
				&out)) != ok)
		fail("exporter", e);
	send_bytes(out.ptr, out.len);
}

int main(int argc, char **argv)
{
	if (argc != 3)
		fail("usage: peer initiator|responder reference|value", 0);
	int initiator = strcmp(argv[1], "initiator") == 0;
	int value = strcmp(argv[2], "value") == 0;

	uint8_t pub[64], priv[32], g_x[32];
	if (!uECC_make_key(pub, priv, uECC_secp256r1()))
		fail("ephemeral key", 0);
	memcpy(g_x, pub, 32);
	struct byte_array eph_pub = { .len = 32, .ptr = g_x };
	struct byte_array eph_priv = { .len = 32, .ptr = priv };

	uint8_t c_x[] = { 0x0c };
	uint8_t suites[] = { 2 };
	uint8_t err_buf[64], prk_out_buf[32];
	struct byte_array err_msg = { .len = sizeof(err_buf), .ptr = err_buf };
	struct byte_array prk_out = { .len = sizeof(prk_out_buf),
				      .ptr = prk_out_buf };
	enum err e;

	if (initiator) {
		struct byte_array cred_i = unhex(CRED_I_HEX);
		struct other_party_cred peer = {
			.id_cred = { .len = sizeof(KID_R), .ptr = KID_R },
			.cred = unhex(CRED_R_HEX),
			.g = unhex(G_R_HEX),
		};
		struct cred_array peers = { .len = 1, .ptr = &peer };
		struct edhoc_initiator_context c = {
			.c_i = { .len = sizeof(c_x), .ptr = c_x },
			.method = INITIATOR_SDHK_RESPONDER_SDHK,
			.suites_i = { .len = sizeof(suites), .ptr = suites },
			.id_cred_i = value ? by_value(cred_i) :
					     (struct byte_array){ .len = sizeof(KID_I),
								  .ptr = KID_I },
			.cred_i = cred_i,
			.g_x = eph_pub,
			.x = eph_priv,
			.g_i = unhex(G_I_HEX),
			.i = unhex(I_HEX),
		};
		e = edhoc_initiator_run(&c, &peers, &err_msg, &prk_out, tx, rx,
					ead_process);
		if (e != ok)
			fail("edhoc_initiator_run", e);
	} else {
		struct byte_array cred_r = unhex(CRED_R_HEX);
		struct other_party_cred peer = {
			.id_cred = { .len = sizeof(KID_I), .ptr = KID_I },
			.cred = unhex(CRED_I_HEX),
			.g = unhex(G_I_HEX),
		};
		struct cred_array peers = { .len = 1, .ptr = &peer };
		struct edhoc_responder_context c = {
			.c_r = { .len = sizeof(c_x), .ptr = c_x },
			.suites_r = { .len = sizeof(suites), .ptr = suites },
			.g_y = eph_pub,
			.y = eph_priv,
			.g_r = unhex(G_R_HEX),
			.r = unhex(R_HEX),
			.id_cred_r = value ? by_value(cred_r) :
					     (struct byte_array){ .len = sizeof(KID_R),
								  .ptr = KID_R },
			.cred_r = cred_r,
		};
		e = edhoc_responder_run(&c, &peers, &err_msg, &prk_out, tx, rx,
					ead_process);
		if (e != ok)
			fail("edhoc_responder_run", e);
	}
	export_all(prk_out_buf);
	return 0;
}
