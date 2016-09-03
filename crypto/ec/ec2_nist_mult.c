/* crypto/ec/ec2_mult_nist.c */
/*
 * Modified crypto/ec/ec2_mult.c by Manuel Bluhm for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifndef OPENSSL_NO_EC2M

#ifdef OPENSSL_FAST_EC2M

#include <openssl/err.h>
#include "ec_lcl.h"


static int gf2m_Maddle_nist163k(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_nist163k(x, x1, z1, x2, z2, k)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_nist163r(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_nist163r(x, x1, z1, x2, z2, k, c)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_sect193r(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_sect193r(x, x1, z1, x2, z2, k, c)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_nist233k(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_nist233k(x, x1, z1, x2, z2, k)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_nist233r(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_nist233r(x, x1, z1, x2, z2, k, c)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_sect239k(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_sect239k(x, x1, z1, x2, z2, k)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_nist283k(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_nist283k(x, x1, z1, x2, z2, k)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_nist283r(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_nist283r(x, x1, z1, x2, z2, k, c)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_nist409k(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_nist409k(x, x1, z1, x2, z2, k)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_nist409r(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_nist409r(x, x1, z1, x2, z2, k, c)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_nist571k(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_nist571k(x, x1, z1, x2, z2, k)) goto err;

	ret = 1;

 err:
	return ret;
	}

static int gf2m_Maddle_nist571r(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
	const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c, BN_CTX *ctx)
	{
	int ret = 0;

	if (!BN_GF2m_Maddle_xmm_nist571r(x, x1, z1, x2, z2, k, c)) goto err;

	ret = 1;

 err:
	return ret;
	}

/* Compute the x, y affine coordinates from the point (x1, z1) (x2, z2) 
 * using Montgomery point multiplication algorithm Mxy() in appendix of 
 *     Lopez, J. and Dahab, R.  "Fast multiplication on elliptic curves over 
 *     GF(2^m) without precomputation" (CHES '99, LNCS 1717).
 * Returns:
 *     0 on error
 *     1 if return value should be the point at infinity
 *     2 otherwise
 */
static int gf2m_Mxy(const EC_GROUP *group, const BIGNUM *x, const BIGNUM *y, BIGNUM *x1, 
	BIGNUM *z1, BIGNUM *x2, BIGNUM *z2, BN_ULONG field_size, BN_CTX *ctx)
	{
	BIGNUM *t3, *t4, *t5;
	int ret = 0;

	if (BN_GF2m_const_cmp_zero(z1))
		{
		BN_GF2m_const_setword(x2, 0);
		BN_GF2m_const_setword(z2, 0);
		return 1;
		}

	if (BN_GF2m_const_cmp_zero(z2))
		{
		if (!BN_GF2m_const_copy(x2, x)) return 0;
		if (!BN_GF2m_const_add(z2, x, y)) return 0;
		return 2;
		}
		
	/* Since Mxy is static we can guarantee that ctx != NULL. */
	BN_CTX_start(ctx);
	t3 = BN_CTX_get(ctx);
	t4 = BN_CTX_get(ctx);
	t5 = BN_CTX_get(ctx);
	if (t5 == NULL) goto err;

	if (!BN_GF2m_const_init(t3, field_size)) goto err;
	if (!BN_GF2m_const_init(t4, field_size)) goto err;
	if (!BN_GF2m_const_init(t5, field_size)) goto err;

	if (!BN_GF2m_const_setone(t5)) goto err;

	if (!group->meth->field_mul(group, t3, z1, z2, ctx)) goto err;
	if (!group->meth->field_mul(group, z1, z1, x, ctx)) goto err;
	if (!BN_GF2m_const_add(z1, z1, x1)) goto err;
	if (!group->meth->field_mul(group, z2, z2, x, ctx)) goto err;
	if (!group->meth->field_mul(group, x1, z2, x1, ctx)) goto err;
	if (!BN_GF2m_const_add(z2, z2, x2)) goto err;

	if (!group->meth->field_mul(group, z2, z2, z1, ctx)) goto err;
	if (!group->meth->field_sqr(group, t4, x, ctx)) goto err;
	if (!BN_GF2m_const_add(t4, t4, y)) goto err;
	if (!group->meth->field_mul(group, t4, t4, t3, ctx)) goto err;
	if (!BN_GF2m_const_add(t4, t4, z2)) goto err;

	if (!group->meth->field_mul(group, t3, t3, x, ctx)) goto err;
	if (!group->meth->field_div(group, t3, t5, t3, ctx)) goto err;
	if (!group->meth->field_mul(group, t4, t3, t4, ctx)) goto err;
	if (!group->meth->field_mul(group, x2, x1, t3, ctx)) goto err;
	if (!BN_GF2m_const_add(z2, x2, x)) goto err;

	if (!group->meth->field_mul(group, z2, z2, t4, ctx)) goto err;
	if (!BN_GF2m_const_add(z2, z2, y)) goto err;

	ret = 2;

 err:
	BN_CTX_end(ctx);
	return ret;
	}


/* Computes scalar*point and stores the result in r.
 * point can not equal r.
 * Uses algorithm 2P of
 *     Lopez, J. and Dahab, R.  "Fast multiplication on elliptic curves over 
 *     GF(2^m) without precomputation" (CHES '99, LNCS 1717).
 */
int ec_GF2m_montgomery_point_multiply(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	const EC_POINT *point, BN_CTX *ctx)
	{
	/* Init */
	int ret = 0, i;
	BIGNUM *x1, *x2, *z1, *z2, *fscalar, *forder;
	const BIGNUM *c = NULL;
	BN_ULONG mask, word, keybit, field_size;

	static int (*gf2m_Maddle)(const EC_GROUP *, const BIGNUM *, BIGNUM *, BIGNUM *,
			const BIGNUM *, const BIGNUM *, BN_ULONG, const BIGNUM *, BN_CTX *);

	if (r == point)
		{
		ECerr(EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY, EC_R_INVALID_ARGUMENT);
		return 0;
		}

	/* if result should be point at infinity */
	if ((scalar == NULL) || BN_is_zero(scalar) || (point == NULL) || 
		EC_POINT_is_at_infinity(group, point))
		{
		return EC_POINT_set_to_infinity(group, r);
		}

	/* only support affine coordinates */
	if (!point->Z_is_one) return 0;

	/* Since point_multiply is static we can guarantee that ctx != NULL. */
	BN_CTX_start(ctx);
	forder = BN_CTX_get(ctx);
	fscalar = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	z1 = BN_CTX_get(ctx);
	if (z1 == NULL) goto err;

	/* Set constant field size of BN_BITS2-words */
	field_size = (group->poly[0] / BN_BITS2) + 1;

	/* Initialize constant size elements */
	if (!BN_GF2m_const_init(fscalar, (&group->order)->top)) goto err;
	if (!BN_GF2m_const_init(forder, (&group->order)->top)) goto err;
	if (!BN_GF2m_const_init(x1, field_size)) goto err;
	if (!BN_GF2m_const_init(z1, field_size)) goto err;
	if (!BN_GF2m_const_init(&r->X, field_size)) goto err;
	if (!BN_GF2m_const_init(&r->Y, field_size)) goto err;

	x2 = &r->X;
	z2 = &r->Y;

	/* Set Double&Add method for improved 2P algorithm */
	switch ( group->curve_name )
		{
		case NID_sect163k1:		gf2m_Maddle = gf2m_Maddle_nist163k; break;
		case NID_sect163r1:		gf2m_Maddle = gf2m_Maddle_nist163r;	break;
		case NID_sect163r2:		gf2m_Maddle = gf2m_Maddle_nist163r; break;
		case NID_sect193r1:		gf2m_Maddle = gf2m_Maddle_sect193r; break;
		case NID_sect193r2:		gf2m_Maddle = gf2m_Maddle_sect193r; break;
		case NID_sect233k1:		gf2m_Maddle = gf2m_Maddle_nist233k; break;
		case NID_sect233r1:		gf2m_Maddle = gf2m_Maddle_nist233r; break;
		case NID_sect239k1:		gf2m_Maddle = gf2m_Maddle_sect239k; break;
		case NID_sect283k1:		gf2m_Maddle = gf2m_Maddle_nist283k; break;
		case NID_sect283r1:		gf2m_Maddle = gf2m_Maddle_nist283r; break;
		case NID_sect409k1:		gf2m_Maddle = gf2m_Maddle_nist409k; break;
		case NID_sect409r1:		gf2m_Maddle = gf2m_Maddle_nist409r; break;
		case NID_sect571k1:		gf2m_Maddle = gf2m_Maddle_nist571k; break;
		case NID_sect571r1:		gf2m_Maddle = gf2m_Maddle_nist571r; break;

		default:				goto err;
		}

	/* Load precomputed value c = sqrt(b) = b^(2^(m-1)), only if group parameter b != 1*/
	if ( !BN_GF2m_const_cmp_one(&group->b) )
		{
		if ( (c = ec_GF2m_get_sqrt_b(group)) == NULL ) goto err;
		}

	/* Precompute coordinates */
	if (!BN_GF2m_const_copy(x1, &point->X)) goto err; 				// x1 = x
	if (!BN_GF2m_const_setone(z1)) goto err; 						// z1 = 1
	if (!group->meth->field_sqr(group, z2, x1, ctx)) goto err; 		// z2 = x1^2 = x^2
	if (!group->meth->field_sqr(group, x2, z2, ctx)) goto err;
	if (!BN_GF2m_const_add(x2, x2, &group->b)) goto err; 			// x2 = x^4 + b

	/* Add group order to scalar to assert certain bit length */
	if (!BN_GF2m_copy(fscalar, scalar)) goto err;

	if (!BN_GF2m_const_int_add(fscalar, fscalar, &group->order)) goto err;
	i = (&group->order)->top - 1;
	mask = BN_TBIT;
	word = (&group->order)->d[i];
	while (!(word & mask)) mask >>= 1;
	mask <<= 1;

	mask = (0 - ((mask & (fscalar->d[fscalar->top-1]))==0));
	for (i=0; i < forder->top; i++)
		{
		forder->d[i] = mask & (&group->order)->d[i];
		}
	if (!BN_GF2m_const_int_add(fscalar, fscalar, forder)) goto err;

	/* find top most bit and go one past it */
	i = fscalar->top - 1;
	mask = BN_TBIT;
	word = fscalar->d[i];
	while (!(word & mask)) mask >>= 1;
	mask >>= 1;

	/* if top most bit was at word break, go to next word */
	if (!mask)
		{
		i--;
		mask = BN_TBIT;
		}

	for (; i >= 0; i--)
		{
		word = fscalar->d[i];
		while (mask)
			{

			/* Set keybit */
			keybit = ((word & mask) != 0);

			/* Execute Madd & Mdouble */
			if (!(*gf2m_Maddle)(group, &point->X, x1, z1, x2, z2, keybit, c, ctx)) goto err;

			mask >>= 1;
			}
		mask = BN_TBIT;
		}

	/* convert out of "projective" coordinates */
	i = gf2m_Mxy(group, &point->X, &point->Y, x1, z1, x2, z2, field_size, ctx);
	if (i == 0) goto err;
	else if (i == 1) 
		{
		if (!EC_POINT_set_to_infinity(group, r)) goto err;
		}
	else
		{
		if (!BN_one(&r->Z)) goto err;
		r->Z_is_one = 1;
		}

	/* GF(2^m) field elements should always have BIGNUM::neg = 0 */
	(&r->X)->neg = 0;
	(&r->Y)->neg = 0;

	ret = 1;

 err:
	BN_CTX_end(ctx);
	return ret;
	}


/* Computes the sum
 *     scalar*group->generator + scalars[0]*points[0] + ... + scalars[num-1]*points[num-1]
 * gracefully ignoring NULL scalar values.
 */
int ec_GF2m_nist_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	int ret = 0;
	size_t i;
	EC_POINT *p=NULL;
	EC_POINT *acc = NULL;

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
		}

	/* This implementation newer uses ec_wNAF_mult. */

	if ((p = EC_POINT_new(group)) == NULL) goto err;
	if ((acc = EC_POINT_new(group)) == NULL) goto err;

	if (!EC_POINT_set_to_infinity(group, acc)) goto err;

	if (scalar)
		{
		if (!ec_GF2m_montgomery_point_multiply(group, p, scalar, group->generator, ctx)) goto err;
		if (BN_is_negative(scalar))
			if (!group->meth->invert(group, p, ctx)) goto err;
		if (!group->meth->add(group, acc, acc, p, ctx)) goto err;
		}

	for (i = 0; i < num; i++)
		{
		if (!ec_GF2m_montgomery_point_multiply(group, p, scalars[i], points[i], ctx)) goto err;
		if (BN_is_negative(scalars[i]))
			if (!group->meth->invert(group, p, ctx)) goto err;
		if (!group->meth->add(group, acc, acc, p, ctx)) goto err;
		}

	if (!EC_POINT_copy(r, acc)) goto err;
	ret = 1;

  err:
	if (p) EC_POINT_free(p);
	if (acc) EC_POINT_free(acc);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	}

#endif

#endif
