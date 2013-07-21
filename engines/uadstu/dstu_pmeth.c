/*
 * dstu_pkey.c
 *
 *  Created on: Mar 4, 2013
 *      Author: ignat
 */
#include "dstu_engine.h"
#include "dstu_key.h"
#include "dstu_params.h"
#include <openssl/asn1.h>

/* Since we cannot access fields of EVP_PKEY_CTX to get associated methods to determine method nid later
 * we use different init callbacks for each method and store the nid in the data field of ctx
 */
static int dstu_pkey_init_le(EVP_PKEY_CTX *ctx)
{
	DSTU_KEY_CTX* dstu_ctx = DSTU_KEY_CTX_new();
printf("dstu_pkey_init_le\n");
	if (!dstu_ctx)
		return 0;

	dstu_ctx->type = dstu_nids[0];
	EVP_PKEY_CTX_set_data(ctx, dstu_ctx);
	return 1;
}

static int dstu_pkey_init_be(EVP_PKEY_CTX *ctx)
{
	DSTU_KEY_CTX* dstu_ctx = DSTU_KEY_CTX_new();
	printf("dstu_pkey_init_be %p %p\n", dstu_ctx, dstu_ctx->group);
	if (!dstu_ctx)
		return 0;

	dstu_ctx->type = dstu_nids[1];
	EVP_PKEY_CTX_set_data(ctx, dstu_ctx);
	return 1;
}

static void dstu_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
	DSTU_KEY_CTX* dstu_ctx = EVP_PKEY_CTX_get_data(ctx);
	printf("dstu_pkey_cleanup %p %p\n", dstu_ctx, dstu_ctx->group);
	if (dstu_ctx)
	{
		DSTU_KEY_CTX_free(dstu_ctx);
		/* Just to make sure */
		EVP_PKEY_CTX_set_data(ctx, NULL);
	}
}

/*static int dstu_pkey_paramgen_init(EVP_PKEY_CTX *ctx)
{
	printf("dstu_pkey_paramgen_init\n");
	return 1;
}

static int dstu_pkey_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	printf("dstu_pkey_paramgen\n");
	return 1;
}*/

/*static int dstu_pkey_keygen_init(EVP_PKEY_CTX *ctx)
{
	printf("dstu_pkey_keygen_init\n");
	return 1;
}*/

static int dstu_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	DSTU_KEY* key = EVP_PKEY_get0(pkey);
	DSTU_KEY_CTX* dstu_ctx = EVP_PKEY_CTX_get_data(ctx);
	unsigned char* sbox = NULL;
	int ret = 0;
	if (!dstu_ctx)
		return 0;
	printf("dstu_pkey_keygen\n");
	if (!(dstu_ctx->group))
	{
		dstu_ctx->group = get_default_group();
		if (!(dstu_ctx->group))
			return 0;
	}

	if (!key)
	{
		key = DSTU_KEY_new();
		if (!key)
			goto err;
	}

	if (!EC_KEY_set_group(key->ec, dstu_ctx->group))
		goto err;

	if (!dstu_generate_key(key->ec))
		goto err;

	if (dstu_ctx->sbox)
	{
		sbox = copy_sbox(dstu_ctx->sbox);
		if (!sbox)
			goto err;
		DSTU_KEY_set(key, NULL, sbox);
	}

	if (!EVP_PKEY_assign(pkey, dstu_ctx->type, key))
		goto err;

	key = NULL;
	ret = 1;

err:
	if (key)
		DSTU_KEY_free(key);

	return ret;
}

static int dstu_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	printf("dstu_pkey_ctrl\n");
	/* TODO: set custom sbox and curve */
	return 1;
}

static int dstu_pkey_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
	printf("dstu_pkey_ctrl_str\n");
	printf("%s: %s\n", type, value);
	/*test_cipher();*/
	return 1;
}

/*static int dstu_pkey_sign_init(EVP_PKEY_CTX *ctx)
{
	return 0;
}*/

static int dstu_pkey_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	DSTU_KEY* key = NULL;
	const EC_GROUP* group = NULL;
	int field_size, ret = 0, encoded_sig_size;
	ASN1_OCTET_STRING *dstu_sig = NULL;
	unsigned char *sig_data = NULL;
	printf("dstu_pkey_sign %p %d\n", sig, *siglen);
	if (!pkey)
		return 0;

	key = EVP_PKEY_get0(pkey);
	if (!key)
		return 0;

	group = EC_KEY_get0_group(key->ec);
	if (!group)
		return 0;

	field_size = (EC_GROUP_get_degree(group) + 7) / 8;
	encoded_sig_size = EVP_PKEY_size(pkey);

	if (encoded_sig_size > *siglen)
	{
		*siglen = encoded_sig_size;
		return 0;
	}

	*siglen = encoded_sig_size;

	if (sig)
	{
		dstu_sig = ASN1_OCTET_STRING_new();
		if (!dstu_sig)
			goto err;

		sig_data = OPENSSL_malloc(2 * field_size);
		if (!sig_data)
			goto err;

		if (!dstu_do_sign(key->ec, tbs, tbslen, sig_data))
			goto err;

		if (dstu_nids[0] == EVP_PKEY_id(pkey))
			reverse_bytes(sig_data, 2 * field_size);

		ASN1_STRING_set0((ASN1_STRING *)dstu_sig, sig_data, 2 * field_size);
		sig_data = NULL;

		*siglen = i2d_ASN1_OCTET_STRING(dstu_sig, &sig);
	}

	ret = 1;

err:

	if (sig_data)
		OPENSSL_free(sig_data);

	if (dstu_sig)
		ASN1_OCTET_STRING_free(dstu_sig);

	return ret;
}

/*static int dstu_pkey_verify_init(EVP_PKEY_CTX *ctx)
{
	return 0;
}*/

static int dstu_pkey_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	DSTU_KEY* key = NULL;
	const EC_GROUP* group = NULL;
	int field_size, ret = 0;
	unsigned char *sig_be;
	ASN1_OCTET_STRING *dstu_sig = NULL;
	printf("dstu_pkey_verify\n");
	if (!pkey)
		return 0;

	key = EVP_PKEY_get0(pkey);
	if (!key)
		return 0;

	group = EC_KEY_get0_group(key->ec);
	if (!group)
		return 0;

	field_size = (EC_GROUP_get_degree(group) + 7) / 8;

	if (!d2i_ASN1_OCTET_STRING(&dstu_sig, &sig, siglen))
		return 0;

	sig = ASN1_STRING_data(dstu_sig);
	siglen = ASN1_STRING_length(dstu_sig);

	if (siglen & 0x01)
		goto err;

	if (siglen < (2 * field_size))
		goto err;

	if (dstu_nids[0] == EVP_PKEY_id(pkey))
	{
		/* Signature is little-endian, need to reverse it */
		sig_be = OPENSSL_malloc(siglen);
		if (!sig_be)
			goto err;

		reverse_bytes_copy(sig_be, sig, siglen);
		ret = dstu_do_verify(key->ec, tbs, tbslen, sig_be, siglen);
		OPENSSL_free(sig_be);
	}
	else
		ret = dstu_do_verify(key->ec, tbs, tbslen, sig, siglen);

err:
	if (dstu_sig)
		ASN1_OCTET_STRING_free(dstu_sig);

	return ret;
}

static int dstu_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	DSTU_KEY_CTX *dstu_src_ctx = EVP_PKEY_CTX_get_data(src), *dstu_dst_ctx;
	printf("dstu_pkey_copy %p %p\n", dstu_src_ctx, dstu_src_ctx->group);

	if (dstu_src_ctx)
	{
		dstu_dst_ctx = DSTU_KEY_CTX_copy(dstu_src_ctx);
		if (!dstu_dst_ctx)
			return 0;
		EVP_PKEY_CTX_set_data(dst, dstu_dst_ctx);
		printf("dstu_pkey_copy2 %p %p\n", dstu_dst_ctx, dstu_dst_ctx->group);
	}

	return 1;
}

EVP_PKEY_METHOD *dstu_pkey_meth_le = NULL, *dstu_pkey_meth_be = NULL;

int dstu_pkey_meth_init(void)
{
	dstu_pkey_meth_le = EVP_PKEY_meth_new(dstu_nids[0], 0);
	if (!dstu_pkey_meth_le)
		return 0;

	dstu_pkey_meth_be = EVP_PKEY_meth_new(dstu_nids[1], 0);
	if (!dstu_pkey_meth_be)
	{
		EVP_PKEY_meth_free(dstu_pkey_meth_le);
		dstu_pkey_meth_le = NULL;
		return 0;
	}

	EVP_PKEY_meth_set_init(dstu_pkey_meth_le, dstu_pkey_init_le);
	EVP_PKEY_meth_set_cleanup(dstu_pkey_meth_le, dstu_pkey_cleanup);
	/*EVP_PKEY_meth_set_paramgen(dstu_pkey_meth, dstu_pkey_paramgen_init, dstu_pkey_paramgen);*/
	EVP_PKEY_meth_set_keygen(dstu_pkey_meth_le, /*dstu_pkey_keygen_init*/ NULL, dstu_pkey_keygen);
	EVP_PKEY_meth_set_ctrl(dstu_pkey_meth_le, dstu_pkey_ctrl, dstu_pkey_ctrl_str);
	EVP_PKEY_meth_set_sign(dstu_pkey_meth_le, /*dstu_pkey_sign_init*/ NULL, dstu_pkey_sign);
	EVP_PKEY_meth_set_verify(dstu_pkey_meth_le, /*dstu_pkey_verify_init*/ NULL, dstu_pkey_verify);
	EVP_PKEY_meth_set_copy(dstu_pkey_meth_le, dstu_pkey_copy);

	EVP_PKEY_meth_set_init(dstu_pkey_meth_be, dstu_pkey_init_be);
	EVP_PKEY_meth_set_cleanup(dstu_pkey_meth_be, dstu_pkey_cleanup);
	/*EVP_PKEY_meth_set_paramgen(dstu_pkey_meth, dstu_pkey_paramgen_init, dstu_pkey_paramgen);*/
	EVP_PKEY_meth_set_keygen(dstu_pkey_meth_be, /*dstu_pkey_keygen_init*/ NULL, dstu_pkey_keygen);
	EVP_PKEY_meth_set_ctrl(dstu_pkey_meth_be, dstu_pkey_ctrl, dstu_pkey_ctrl_str);
	EVP_PKEY_meth_set_sign(dstu_pkey_meth_be, /*dstu_pkey_sign_init*/ NULL, dstu_pkey_sign);
	EVP_PKEY_meth_set_verify(dstu_pkey_meth_be, /*dstu_pkey_verify_init*/ NULL, dstu_pkey_verify);
	EVP_PKEY_meth_set_copy(dstu_pkey_meth_be, dstu_pkey_copy);

	return 1;
}

void dstu_pkey_meth_finish(void)
{
	if (dstu_pkey_meth_le)
		EVP_PKEY_meth_free(dstu_pkey_meth_le);

	if (dstu_pkey_meth_be)
		EVP_PKEY_meth_free(dstu_pkey_meth_be);
}

