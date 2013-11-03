/*
 * dstu_md.c
 *
 *  Created on: May 20, 2013
 *      Author: ignat
 */

#include "dstu_engine.h"
#include "dstu_params.h"
#include "dstu_key.h"
#include "../ccgost/gosthash.h"

struct dstu_digest_ctx
    {
	gost_hash_ctx dctx;
	gost_ctx cctx;
    };

static int dstu_md_init(EVP_MD_CTX *ctx)
    {
    gost_subst_block sbox;
    int use_default_sbox = 1;
    struct dstu_digest_ctx *c = ctx->md_data;
    DSTU_KEY* dstu_key = NULL;
    EVP_PKEY* pkey = NULL;

    /* If we have pkey_ctx, it may contain custom sbox, so let's check it */

    if (ctx->pctx)
	{
	pkey = EVP_PKEY_CTX_get0_pkey(ctx->pctx);
	if (pkey)
	    {
	    dstu_key = EVP_PKEY_get0(pkey);
	    if (dstu_key)
		{
		if (dstu_key->sbox)
		    {
		    unpack_sbox(dstu_key->sbox, &sbox);
		    use_default_sbox = 0;
		    }
		}
	    }
	}

    if (use_default_sbox)
	unpack_sbox(default_sbox, &sbox);
    memset(&(c->dctx), 0, sizeof(gost_hash_ctx));
    gost_init(&(c->cctx), &sbox);
    c->dctx.cipher_ctx = &(c->cctx);
    return 1;
    }

static int dstu_md_update(EVP_MD_CTX *ctx, const void *data, size_t count)
    {
    return hash_block((gost_hash_ctx *) (ctx->md_data), data, count);
    }

static int dstu_md_final(EVP_MD_CTX *ctx, unsigned char *md)
    {
    return finish_hash((gost_hash_ctx *) (ctx->md_data), md);
    }

static int dstu_md_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
    {
    struct dstu_digest_ctx *md_ctx = to->md_data;
    if (to->md_data && from->md_data)
	{
	memcpy(to->md_data, from->md_data, sizeof(struct dstu_digest_ctx));
	md_ctx->dctx.cipher_ctx = &(md_ctx->cctx);
	}
    return 1;
    }

static int dstu_md_cleanup(EVP_MD_CTX *ctx)
    {
    if (ctx->md_data)
	memset(ctx->md_data, 0, sizeof(struct dstu_digest_ctx));
    return 1;
    }

static int dstu_md_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
    {
    gost_subst_block sbox;
    struct dstu_digest_ctx *c = ctx->md_data;

    switch (cmd)
	{
    case DSTU_SET_CUSTOM_SBOX:
	if ((!p2) || (sizeof(default_sbox) != p1))
	    return 0;
	unpack_sbox((unsigned char *) p2, &sbox);
	gost_init(&(c->cctx), &sbox);
	return 1;
	}

    return 0;
    }

EVP_MD dstu_md =
    {
	    NID_dstu34311,
	    0,
	    32,
	    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
	    dstu_md_init,
	    dstu_md_update,
	    dstu_md_final,
	    dstu_md_copy,
	    dstu_md_cleanup,
	    NULL,
	    NULL,
		{
		0, 0, 0, 0, 0
		},
	    32,
	    sizeof(struct dstu_digest_ctx),
	    dstu_md_ctrl
    };
