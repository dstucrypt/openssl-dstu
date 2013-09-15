/*
 * dstu_cipher.c
 *
 *  Created on: Jun 17, 2013
 *      Author: ignat
 */

#include "dstu_engine.h"
#include "dstu_params.h"
#include "../ccgost/gost89.h"

/* DSTU uses Russian GOST 28147 but with different s-boxes and no key meshing */
/* We implement CFB mode here because it is mostly used */

#define DSTU_CIPHER_BLOCK_SIZE 8

static int dstu_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	gost_subst_block sbox;
	gost_ctx* gctx = ctx->cipher_data;

	unpack_sbox(default_sbox, &sbox);
	gost_init(gctx, &sbox);
	gost_key(gctx, key);

	memcpy(ctx->oiv, iv, DSTU_CIPHER_BLOCK_SIZE);
	memcpy(ctx->iv, iv, DSTU_CIPHER_BLOCK_SIZE);
	gostcrypt(gctx, ctx->iv, ctx->buf);

	return 1;
}

static int dstu_cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
	size_t to_use, i, blocks;
	gost_ctx* gctx = ctx->cipher_data;
	unsigned char tmpiv[DSTU_CIPHER_BLOCK_SIZE];

	if (!inl)
		return 1;

	if (ctx->num)
	{
		to_use = (ctx->num < inl) ? ctx->num : inl;

		for (i = 0; i < to_use; i++)
		{
			*out = *in ^ ctx->buf[DSTU_CIPHER_BLOCK_SIZE - ctx->num + i];
			if (ctx->encrypt)
				ctx->iv[DSTU_CIPHER_BLOCK_SIZE - ctx->num + i] = *out;
			else
				ctx->iv[DSTU_CIPHER_BLOCK_SIZE - ctx->num + i] = *in;
			in++;
			out++;
		}

		ctx->num -= to_use;
		inl -= to_use;

		if (!ctx->num)
			gostcrypt(gctx, ctx->iv, ctx->buf);
	}

	if (inl)
	{
		blocks = inl >> 3;

		if (blocks)
		{
			if (ctx->encrypt)
			{
				gost_enc_cfb(gctx, ctx->iv, in, out, blocks);
				memcpy(ctx->iv, out + (blocks * DSTU_CIPHER_BLOCK_SIZE) - DSTU_CIPHER_BLOCK_SIZE, DSTU_CIPHER_BLOCK_SIZE);
			}
			else
			{
				memcpy(tmpiv, ctx->iv, DSTU_CIPHER_BLOCK_SIZE);
				memcpy(ctx->iv, in + (blocks * DSTU_CIPHER_BLOCK_SIZE) - DSTU_CIPHER_BLOCK_SIZE, DSTU_CIPHER_BLOCK_SIZE);
				gost_dec_cfb(gctx, tmpiv, in, out, blocks);
			}
			gostcrypt(gctx, ctx->iv, ctx->buf);

			out += blocks * DSTU_CIPHER_BLOCK_SIZE;
			in += blocks * DSTU_CIPHER_BLOCK_SIZE;
			inl -= blocks * DSTU_CIPHER_BLOCK_SIZE;
		}
	}

	if (inl)
	{
		for (i = 0; i < inl; i++)
		{
			*out = *in ^ ctx->buf[i];
			if (ctx->encrypt)
				ctx->iv[i] = *out;
			else
				ctx->iv[i] = *in;
			in++;
			out++;
		}

		ctx->num = DSTU_CIPHER_BLOCK_SIZE - inl;
	}

	return 1;
}

static int dstu_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
	return 1;
}

static int dstu_cipher_ctrl(EVP_CIPHER_CTX *ctx, int cmd, int p1, void *p2)
{
	gost_subst_block sbox;
	gost_ctx* gctx = ctx->cipher_data;

	switch (cmd)
	{
	case DSTU_SET_CUSTOM_SBOX:
		if ((!p2) || (sizeof(default_sbox) != p1))
			return 0;
		unpack_sbox((unsigned char *)p2, &sbox);
		gost_init(gctx, &sbox);
		memcpy(ctx->iv, ctx->oiv, DSTU_CIPHER_BLOCK_SIZE);
		gostcrypt(gctx, ctx->iv, ctx->buf);
		return 1;
	}

	return 0;
}

EVP_CIPHER dstu_cipher =
{
	NID_dstu28147_cfb,
	1,
	32,
	DSTU_CIPHER_BLOCK_SIZE,
	EVP_CIPH_CFB_MODE| EVP_CIPH_NO_PADDING | EVP_CIPH_CUSTOM_IV,
	dstu_cipher_init,
	dstu_cipher_do_cipher,
	dstu_cipher_cleanup,
	sizeof(gost_ctx),
	NULL,
	NULL,
	dstu_cipher_ctrl,
	NULL
};

/*void test_cipher(void)
{
	unsigned char data[50];
	unsigned char enc[sizeof(data)];
	unsigned char dec[sizeof(data)];
	unsigned char key[32];
	unsigned char iv[8];
	EVP_CIPHER_CTX ctx;
	int i, inl = sizeof(data), outl = sizeof(enc);

	for (i = 0; i < sizeof(data); i++)
		data[i] = i;

	for (i = 0; i < sizeof(key); i++)
		key[i] = i;

	for (i = 0; i < sizeof(iv); i++)
		iv[i] = i;

	EVP_CIPHER_CTX_init(&ctx);
	printf("%p\n", EVP_get_cipherbyname("dstu28147"));

	if (!EVP_EncryptInit(&ctx, EVP_get_cipherbyname("dstu28147"), key, iv))
		printf("EVP_EncryptInit\n");

	for (i=0; i<sizeof(enc); i++)
	{
		if (!EVP_EncryptUpdate(&ctx, &enc[i], &outl, &data[i], 1))
			printf("EVP_EncryptUpdate\n");
	}

	printf("outl: %d\n", outl);

	if (!EVP_DecryptInit(&ctx, EVP_get_cipherbyname("dstu28147"), key, iv))
		printf("EVP_DecryptInit\n");

	if (!EVP_DecryptUpdate(&ctx, dec, &outl, enc, sizeof(enc)))
		printf("EVP_DecryptUpdate\n");

	EVP_CIPHER_CTX_cleanup(&ctx);

	if (!memcmp(data, dec, sizeof(data)))
		printf("MATCH\n");
	else
		printf("no match\n");

}*/
