/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

#include "dstu_engine.h"
#include "dstu_params.h"
#include "../ccgost/gost89.h"

/* DSTU uses Russian GOST 28147 but with different s-boxes and no key meshing */
/* We implement CFB mode here because it is mostly used */

#define DSTU_CIPHER_BLOCK_SIZE 8

static int dstu_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
    {
    gost_subst_block sbox;
    gost_ctx* gctx = ctx->cipher_data;

    unpack_sbox(default_sbox, &sbox);
    gost_init(gctx, &sbox);

    if (key)
	gost_key(gctx, key);

    if (iv)
	{
	memcpy(ctx->oiv, iv, DSTU_CIPHER_BLOCK_SIZE);
	memcpy(ctx->iv, iv, DSTU_CIPHER_BLOCK_SIZE);
	gostcrypt(gctx, ctx->iv, ctx->buf);
	ctx->num = 0;
	}

    return 1;
    }

static int dstu_cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t inl)
    {
    size_t to_use, i, blocks;
    gost_ctx* gctx = ctx->cipher_data;
    unsigned char tmpiv[DSTU_CIPHER_BLOCK_SIZE], *out_start = out;

    if ((!inl) && (!in))
	return 0;

    if ((!inl) || (!in))
	return -1;

    if (ctx->num)
	{
	to_use = (ctx->num < inl) ? ctx->num : inl;

	for (i = 0; i < to_use; i++)
	    {
	    if (ctx->encrypt)
		{
		*out = *in ^ ctx->buf[DSTU_CIPHER_BLOCK_SIZE - ctx->num + i];
		ctx->iv[DSTU_CIPHER_BLOCK_SIZE - ctx->num + i] = *out;
		}
	    else
		{
		ctx->iv[DSTU_CIPHER_BLOCK_SIZE - ctx->num + i] = *in;
		*out = *in ^ ctx->buf[DSTU_CIPHER_BLOCK_SIZE - ctx->num + i];
		}
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
		memcpy(ctx->iv,	out + (blocks * DSTU_CIPHER_BLOCK_SIZE)- DSTU_CIPHER_BLOCK_SIZE,
			DSTU_CIPHER_BLOCK_SIZE);
		}
	    else
		{
		memcpy(tmpiv, ctx->iv, DSTU_CIPHER_BLOCK_SIZE);
		memcpy(ctx->iv,	in + (blocks * DSTU_CIPHER_BLOCK_SIZE)- DSTU_CIPHER_BLOCK_SIZE,
			DSTU_CIPHER_BLOCK_SIZE);
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
	    if (ctx->encrypt)
		{
		*out = *in ^ ctx->buf[i];
		ctx->iv[i] = *out;
		}
	    else
		{
		ctx->iv[i] = *in;
		*out = *in ^ ctx->buf[i];
		}
	    in++;
	    out++;
	    }

	ctx->num = DSTU_CIPHER_BLOCK_SIZE - inl;
	}

    return out - out_start;
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
	unpack_sbox((unsigned char *) p2, &sbox);
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
	    EVP_CIPH_CFB_MODE | EVP_CIPH_NO_PADDING | EVP_CIPH_CUSTOM_IV
		    | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT,
	    dstu_cipher_init,
	    dstu_cipher_do_cipher,
	    dstu_cipher_cleanup,
	    sizeof(gost_ctx),
	    NULL,
	    NULL,
	    dstu_cipher_ctrl,
	    NULL
    };

