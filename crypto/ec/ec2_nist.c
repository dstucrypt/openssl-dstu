/* crypto/ec/ec2_nist.c */
/*
 * Written by Manuel Bluhm for the OpenSSL project.
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


#include "ec_lcl.h"
#include <openssl/err.h>

#ifndef OPENSSL_NO_EC2M

#ifdef OPENSSL_FIPS
	#ifdef OPENSSL_FAST_EC2M
	#undef OPENSSL_FAST_EC2M
	#endif
#endif

#ifdef OPENSSL_FAST_EC2M

const EC_METHOD *EC_GF2m_nist163_method(void)
	{
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_characteristic_two_field,
		ec_GF2m_simple_group_init,
		ec_GF2m_simple_group_finish,
		ec_GF2m_simple_group_clear_finish,
		ec_GF2m_nist_group_copy,
		ec_GF2m_nist_group_set_curve,
		ec_GF2m_simple_group_get_curve,
		ec_GF2m_simple_group_get_degree,
		ec_GF2m_simple_group_check_discriminant,
		ec_GF2m_simple_point_init,
		ec_GF2m_simple_point_finish,
		ec_GF2m_simple_point_clear_finish,
		ec_GF2m_nist_point_copy,
		ec_GF2m_nist_point_set_to_infinity,
		0 /* set_Jprojective_coordinates_GFp */,
		0 /* get_Jprojective_coordinates_GFp */,
		ec_GF2m_nist_point_set_affine_coordinates,
		ec_GF2m_nist_point_get_affine_coordinates,
		0,0,0,
		ec_GF2m_nist_add,
		ec_GF2m_nist_dbl,
		ec_GF2m_nist_invert,
		ec_GF2m_nist_is_at_infinity,
		ec_GF2m_nist_is_on_curve,
		ec_GF2m_nist_cmp,
		ec_GF2m_nist_make_affine,
		ec_GF2m_nist_points_make_affine,

		/* the following method function is defined in ec2_nist_mult.c */
		ec_GF2m_nist_mul,
		ec_GF2m_precompute_mult,
		ec_GF2m_have_precompute_mult,

		ec_GF2m_nist163_field_mul,
		ec_GF2m_nist163_field_sqr,
		ec_GF2m_nist163_field_div,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
	}


const EC_METHOD *EC_GF2m_sect193_method(void)
	{
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_characteristic_two_field,
		ec_GF2m_simple_group_init,
		ec_GF2m_simple_group_finish,
		ec_GF2m_simple_group_clear_finish,
		ec_GF2m_nist_group_copy,
		ec_GF2m_nist_group_set_curve,
		ec_GF2m_simple_group_get_curve,
		ec_GF2m_simple_group_get_degree,
		ec_GF2m_simple_group_check_discriminant,
		ec_GF2m_simple_point_init,
		ec_GF2m_simple_point_finish,
		ec_GF2m_simple_point_clear_finish,
		ec_GF2m_nist_point_copy,
		ec_GF2m_nist_point_set_to_infinity,
		0 /* set_Jprojective_coordinates_GFp */,
		0 /* get_Jprojective_coordinates_GFp */,
		ec_GF2m_nist_point_set_affine_coordinates,
		ec_GF2m_nist_point_get_affine_coordinates,
		0,0,0,
		ec_GF2m_nist_add,
		ec_GF2m_nist_dbl,
		ec_GF2m_nist_invert,
		ec_GF2m_nist_is_at_infinity,
		ec_GF2m_nist_is_on_curve,
		ec_GF2m_nist_cmp,
		ec_GF2m_nist_make_affine,
		ec_GF2m_nist_points_make_affine,

		/* the following method function is defined in ec2_nist_mult.c */
		ec_GF2m_nist_mul,
		ec_GF2m_precompute_mult,
		ec_GF2m_have_precompute_mult,

		ec_GF2m_sect193_field_mul,
		ec_GF2m_sect193_field_sqr,
		ec_GF2m_sect193_field_div,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
	}


const EC_METHOD *EC_GF2m_nist233_method(void)
	{
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_characteristic_two_field,
		ec_GF2m_simple_group_init,
		ec_GF2m_simple_group_finish,
		ec_GF2m_simple_group_clear_finish,
		ec_GF2m_nist_group_copy,
		ec_GF2m_nist_group_set_curve,
		ec_GF2m_simple_group_get_curve,
		ec_GF2m_simple_group_get_degree,
		ec_GF2m_simple_group_check_discriminant,
		ec_GF2m_simple_point_init,
		ec_GF2m_simple_point_finish,
		ec_GF2m_simple_point_clear_finish,
		ec_GF2m_nist_point_copy,
		ec_GF2m_nist_point_set_to_infinity,
		0 /* set_Jprojective_coordinates_GFp */,
		0 /* get_Jprojective_coordinates_GFp */,
		ec_GF2m_nist_point_set_affine_coordinates,
		ec_GF2m_nist_point_get_affine_coordinates,
		0,0,0,
		ec_GF2m_nist_add,
		ec_GF2m_nist_dbl,
		ec_GF2m_nist_invert,
		ec_GF2m_nist_is_at_infinity,
		ec_GF2m_nist_is_on_curve,
		ec_GF2m_nist_cmp,
		ec_GF2m_nist_make_affine,
		ec_GF2m_nist_points_make_affine,

		/* the following method function is defined in ec2_nist_mult.c */
		ec_GF2m_nist_mul,
		ec_GF2m_precompute_mult,
		ec_GF2m_have_precompute_mult,

		ec_GF2m_nist233_field_mul,
		ec_GF2m_nist233_field_sqr,
		ec_GF2m_nist233_field_div,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
	}


const EC_METHOD *EC_GF2m_sect239_method(void)
	{
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_characteristic_two_field,
		ec_GF2m_simple_group_init,
		ec_GF2m_simple_group_finish,
		ec_GF2m_simple_group_clear_finish,
		ec_GF2m_nist_group_copy,
		ec_GF2m_nist_group_set_curve,
		ec_GF2m_simple_group_get_curve,
		ec_GF2m_simple_group_get_degree,
		ec_GF2m_simple_group_check_discriminant,
		ec_GF2m_simple_point_init,
		ec_GF2m_simple_point_finish,
		ec_GF2m_simple_point_clear_finish,
		ec_GF2m_nist_point_copy,
		ec_GF2m_nist_point_set_to_infinity,
		0 /* set_Jprojective_coordinates_GFp */,
		0 /* get_Jprojective_coordinates_GFp */,
		ec_GF2m_nist_point_set_affine_coordinates,
		ec_GF2m_nist_point_get_affine_coordinates,
		0,0,0,
		ec_GF2m_nist_add,
		ec_GF2m_nist_dbl,
		ec_GF2m_nist_invert,
		ec_GF2m_nist_is_at_infinity,
		ec_GF2m_nist_is_on_curve,
		ec_GF2m_nist_cmp,
		ec_GF2m_nist_make_affine,
		ec_GF2m_nist_points_make_affine,

		/* the following method function is defined in ec2_nist_mult.c */
		ec_GF2m_nist_mul,
		ec_GF2m_precompute_mult,
		ec_GF2m_have_precompute_mult,

		ec_GF2m_sect239_field_mul,
		ec_GF2m_sect239_field_sqr,
		ec_GF2m_sect239_field_div,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
	}



const EC_METHOD *EC_GF2m_nist283_method(void)
	{
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_characteristic_two_field,
		ec_GF2m_simple_group_init,
		ec_GF2m_simple_group_finish,
		ec_GF2m_simple_group_clear_finish,
		ec_GF2m_nist_group_copy,
		ec_GF2m_nist_group_set_curve,
		ec_GF2m_simple_group_get_curve,
		ec_GF2m_simple_group_get_degree,
		ec_GF2m_simple_group_check_discriminant,
		ec_GF2m_simple_point_init,
		ec_GF2m_simple_point_finish,
		ec_GF2m_simple_point_clear_finish,
		ec_GF2m_nist_point_copy,
		ec_GF2m_nist_point_set_to_infinity,
		0 /* set_Jprojective_coordinates_GFp */,
		0 /* get_Jprojective_coordinates_GFp */,
		ec_GF2m_nist_point_set_affine_coordinates,
		ec_GF2m_nist_point_get_affine_coordinates,
		0,0,0,
		ec_GF2m_nist_add,
		ec_GF2m_nist_dbl,
		ec_GF2m_nist_invert,
		ec_GF2m_nist_is_at_infinity,
		ec_GF2m_nist_is_on_curve,
		ec_GF2m_nist_cmp,
		ec_GF2m_nist_make_affine,
		ec_GF2m_nist_points_make_affine,

		/* the following method function is defined in ec2_nist_mult.c */
		ec_GF2m_nist_mul,
		ec_GF2m_precompute_mult,
		ec_GF2m_have_precompute_mult,

		ec_GF2m_nist283_field_mul,
		ec_GF2m_nist283_field_sqr,
		ec_GF2m_nist283_field_div,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
	}


const EC_METHOD *EC_GF2m_nist409_method(void)
	{
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_characteristic_two_field,
		ec_GF2m_simple_group_init,
		ec_GF2m_simple_group_finish,
		ec_GF2m_simple_group_clear_finish,
		ec_GF2m_nist_group_copy,
		ec_GF2m_nist_group_set_curve,
		ec_GF2m_simple_group_get_curve,
		ec_GF2m_simple_group_get_degree,
		ec_GF2m_simple_group_check_discriminant,
		ec_GF2m_simple_point_init,
		ec_GF2m_simple_point_finish,
		ec_GF2m_simple_point_clear_finish,
		ec_GF2m_nist_point_copy,
		ec_GF2m_nist_point_set_to_infinity,
		0 /* set_Jprojective_coordinates_GFp */,
		0 /* get_Jprojective_coordinates_GFp */,
		ec_GF2m_nist_point_set_affine_coordinates,
		ec_GF2m_nist_point_get_affine_coordinates,
		0,0,0,
		ec_GF2m_nist_add,
		ec_GF2m_nist_dbl,
		ec_GF2m_nist_invert,
		ec_GF2m_nist_is_at_infinity,
		ec_GF2m_nist_is_on_curve,
		ec_GF2m_nist_cmp,
		ec_GF2m_nist_make_affine,
		ec_GF2m_nist_points_make_affine,

		/* the following method function is defined in ec2_nist_mult.c */
		ec_GF2m_nist_mul,
		ec_GF2m_precompute_mult,
		ec_GF2m_have_precompute_mult,

		ec_GF2m_nist409_field_mul,
		ec_GF2m_nist409_field_sqr,
		ec_GF2m_nist409_field_div,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
	}


const EC_METHOD *EC_GF2m_nist571_method(void)
	{
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_characteristic_two_field,
		ec_GF2m_simple_group_init,
		ec_GF2m_simple_group_finish,
		ec_GF2m_simple_group_clear_finish,
		ec_GF2m_nist_group_copy,
		ec_GF2m_nist_group_set_curve,
		ec_GF2m_simple_group_get_curve,
		ec_GF2m_simple_group_get_degree,
		ec_GF2m_simple_group_check_discriminant,
		ec_GF2m_simple_point_init,
		ec_GF2m_simple_point_finish,
		ec_GF2m_simple_point_clear_finish,
		ec_GF2m_nist_point_copy,
		ec_GF2m_nist_point_set_to_infinity,
		0 /* set_Jprojective_coordinates_GFp */,
		0 /* get_Jprojective_coordinates_GFp */,
		ec_GF2m_nist_point_set_affine_coordinates,
		ec_GF2m_nist_point_get_affine_coordinates,
		0,0,0,
		ec_GF2m_nist_add,
		ec_GF2m_nist_dbl,
		ec_GF2m_nist_invert,
		ec_GF2m_nist_is_at_infinity,
		ec_GF2m_nist_is_on_curve,
		ec_GF2m_nist_cmp,
		ec_GF2m_nist_make_affine,
		ec_GF2m_nist_points_make_affine,

		/* the following method function is defined in ec2_nist_mult.c */
		ec_GF2m_nist_mul,
		ec_GF2m_precompute_mult,
		ec_GF2m_have_precompute_mult,

		ec_GF2m_nist571_field_mul,
		ec_GF2m_nist571_field_sqr,
		ec_GF2m_nist571_field_div,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
	}


/* Copy a GF(2^m)-based EC_GROUP structure.
 * Note that all other members are handled by EC_GROUP_copy.
 */
int ec_GF2m_nist_group_copy(EC_GROUP *dest, const EC_GROUP *src)
	{
	int ret=0;
	int field_size = (src->poly[0] / BN_BITS2) + 1;

	if (!BN_GF2m_const_init(&dest->a, field_size)) goto err;
	if (!BN_GF2m_const_init(&dest->b, field_size)) goto err;

	if (!BN_copy(&dest->field, &src->field)) goto err;
	if (!BN_GF2m_const_copy(&dest->a, &src->a)) goto err;
	if (!BN_GF2m_const_copy(&dest->b, &src->b)) goto err;

	dest->poly[0] = src->poly[0];
	dest->poly[1] = src->poly[1];
	dest->poly[2] = src->poly[2];
	dest->poly[3] = src->poly[3];
	dest->poly[4] = src->poly[4];
	dest->poly[5] = src->poly[5];

	ret = 1;
err:
	return ret;
	}

/* Set the curve parameters of an EC_GROUP structure. */
int ec_GF2m_nist_group_set_curve(EC_GROUP *group,
	const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	int ret = 0, i;

	/* group->field */
	if (!BN_copy(&group->field, p)) goto err;
	i = BN_GF2m_poly2arr(&group->field, group->poly, 6) - 1;
	if ((i != 5) && (i != 3))
		{
		ECerr(EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE, EC_R_UNSUPPORTED_FIELD);
		goto err;
		}

	int field_size = (group->poly[0] / BN_BITS2) + 1;

	/* group->a */
	if( !BN_GF2m_const_init(&group->a, field_size)) goto err;
	if (!BN_GF2m_copy(&group->a, a)) goto err;

	/* group->b */
	if( !BN_GF2m_const_init(&group->b, field_size)) goto err;
	if (!BN_GF2m_copy(&group->b, b)) goto err;
	ret = 1;
  err:
	return ret;
	}

/* Copy the contents of one EC_POINT into another.  Assumes dest is initialized. */
int ec_GF2m_nist_point_copy(EC_POINT *dest, const EC_POINT *src)
	{
	if (!BN_GF2m_const_init(&dest->X, (&src->X)->top)) return 0;
	if (!BN_GF2m_const_init(&dest->Y, (&src->Y)->top)) return 0;

	if (!BN_GF2m_const_copy(&dest->X, &src->X)) return 0;
	if (!BN_GF2m_const_copy(&dest->Y, &src->Y)) return 0;
	if (!BN_copy(&dest->Z, &src->Z)) return 0;
	dest->Z_is_one = src->Z_is_one;
	return 1;
	}


/* Set an EC_POINT to the point at infinity.
 * A point at infinity is represented by having Z=0.
 */
int ec_GF2m_nist_point_set_to_infinity(const EC_GROUP *group, EC_POINT *point)
	{
	point->Z_is_one = 0;
	BN_zero(&point->Z);
	return 1;
	}


/* Set the coordinates of an EC_POINT using affine coordinates.
 * Note that the simple implementation only uses affine coordinates.
 */
int ec_GF2m_nist_point_set_affine_coordinates(const EC_GROUP *group, EC_POINT *point,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)
	{
	int field_size, ret = 0;
	if (x == NULL || y == NULL)
		{
		ECerr(EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}

	field_size = (group->poly[0] / BN_BITS2) + 1;

	if (!BN_GF2m_const_init(&point->X, field_size)) goto err;
	if (!BN_GF2m_const_init(&point->Y, field_size)) goto err;

	if (!BN_GF2m_copy(&point->X, x)) goto err;
	BN_set_negative(&point->X, 0);

	if (!BN_GF2m_copy(&point->Y, y)) goto err;
	BN_set_negative(&point->Y, 0);

	if (!BN_copy(&point->Z, BN_value_one())) goto err;
	BN_set_negative(&point->Z, 0);
	point->Z_is_one = 1;
	ret = 1;

  err:
	return ret;
	}


/* Gets the affine coordinates of an EC_POINT.
 * Note that the simple/nist implementations only uses affine coordinates.
 */
int ec_GF2m_nist_point_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *point,
	BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
	{
	int field_size, ret = 0;

	field_size = (group->poly[0] / BN_BITS2) + 1;

	if (EC_POINT_is_at_infinity(group, point))
		{
		ECerr(EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES, EC_R_POINT_AT_INFINITY);
		return 0;
		}

	if (BN_cmp(&point->Z, BN_value_one()))
		{
		ECerr(EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (x != NULL)
		{
		if (!BN_GF2m_const_init(x, field_size)) goto err;
		if (!BN_GF2m_const_copy(x, &point->X)) goto err;
		bn_correct_top(x);
		x->neg = 0;
		BN_set_negative(x, 0);
		}
	if (y != NULL)
		{
		if (!BN_GF2m_const_init(y, field_size)) goto err;
		if (!BN_GF2m_const_copy(y, &point->Y)) goto err;
		bn_correct_top(y);
		BN_set_negative(y, 0);
		}
	ret = 1;

 err:
	return ret;
	}

/* Computes a + b and stores the result in r.  r could be a or b, a could be b.
 * Uses algorithm A.10.2 of IEEE P1363.
 */
int ec_GF2m_nist_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	BIGNUM *x0, *y0, *x1, *y1, *x2, *y2, *s, *t;
	int ret = 0;

	if (EC_POINT_is_at_infinity(group, a))
		{
		if (!EC_POINT_copy(r, b)) return 0;
		return 1;
		}

	if (EC_POINT_is_at_infinity(group, b))
		{
		if (!EC_POINT_copy(r, a)) return 0;
		return 1;
		}

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
		}

	/* Set constant field size */
	int field_size = (group->poly[0] / BN_BITS2) + 1;

	BN_CTX_start(ctx);
	x0 = BN_CTX_get(ctx);
	y0 = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	y1 = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);
	s = BN_CTX_get(ctx);
	t = BN_CTX_get(ctx);
	if (t == NULL) goto err;

	if( !BN_GF2m_const_init(x0, field_size)) goto err;
	if( !BN_GF2m_const_init(y0, field_size)) goto err;
	if( !BN_GF2m_const_init(x1, field_size)) goto err;
	if( !BN_GF2m_const_init(y1, field_size)) goto err;
	if( !BN_GF2m_const_init(x2, field_size)) goto err;
	if( !BN_GF2m_const_init(y2, field_size)) goto err;
	if( !BN_GF2m_const_init(s, field_size)) goto err;
	if( !BN_GF2m_const_init(t, field_size)) goto err;

	if (a->Z_is_one)
		{
		if (!BN_GF2m_const_copy(x0, &a->X)) goto err;
		if (!BN_GF2m_const_copy(y0, &a->Y)) goto err;
		}
	else
		{
		if (!EC_POINT_get_affine_coordinates_GF2m(group, a, x0, y0, ctx)) goto err;
		}
	if (b->Z_is_one)
		{
		if (!BN_GF2m_const_copy(x1, &b->X)) goto err;
		if (!BN_GF2m_const_copy(y1, &b->Y)) goto err;
		}
	else
		{
		if (!EC_POINT_get_affine_coordinates_GF2m(group, b, x1, y1, ctx)) goto err;
		}


	if (!BN_GF2m_const_cmp_eq(x0, x1))
		{
		if (!BN_GF2m_const_add(t, x0, x1)) goto err;
		if (!BN_GF2m_const_add(s, y0, y1)) goto err;
		if (!group->meth->field_div(group, s, s, t, ctx)) goto err;
		if (!group->meth->field_sqr(group, x2, s, ctx)) goto err;
		if (!BN_GF2m_const_add(x2, x2, &group->a)) goto err;
		if (!BN_GF2m_const_add(x2, x2, s)) goto err;
		if (!BN_GF2m_const_add(x2, x2, t)) goto err;
		}
	else
		{
		if (!BN_GF2m_const_cmp_eq(y0, y1) || BN_GF2m_const_cmp_zero(x1))
			{
			if (!EC_POINT_set_to_infinity(group, r)) goto err;
			ret = 1;
			goto err;
			}
		if (!group->meth->field_div(group, s, y1, x1, ctx)) goto err;
		if (!BN_GF2m_const_add(s, s, x1)) goto err;

		if (!group->meth->field_sqr(group, x2, s, ctx)) goto err;
		if (!BN_GF2m_const_add(x2, x2, s)) goto err;
		if (!BN_GF2m_const_add(x2, x2, &group->a)) goto err;
		}

	if (!BN_GF2m_const_add(y2, x1, x2)) goto err;
	if (!group->meth->field_mul(group, y2, y2, s, ctx)) goto err;
	if (!BN_GF2m_const_add(y2, y2, x2)) goto err;
	if (!BN_GF2m_const_add(y2, y2, y1)) goto err;

	if (!EC_POINT_set_affine_coordinates_GF2m(group, r, x2, y2, ctx)) goto err;

	ret = 1;

 err:
	BN_CTX_end(ctx);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	}


/* Computes 2 * a and stores the result in r.  r could be a.
 * Uses algorithm A.10.2 of IEEE P1363.
 */
int ec_GF2m_nist_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx)
	{
	return ec_GF2m_nist_add(group, r, a, a, ctx);
	}


int ec_GF2m_nist_invert(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)
	{
	if (EC_POINT_is_at_infinity(group, point) || BN_is_zero(&point->Y))
		/* point is its own inverse */
		return 1;

	if (!EC_POINT_make_affine(group, point, ctx)) return 0;

	return BN_GF2m_const_add(&point->Y, &point->X, &point->Y);
	}


/* Indicates whether the given point is the point at infinity. */
int ec_GF2m_nist_is_at_infinity(const EC_GROUP *group, const EC_POINT *point)
	{
	return BN_is_zero(&point->Z);
	}


/* Determines whether the given EC_POINT is an actual point on the curve defined
 * in the EC_GROUP.  A point is valid if it satisfies the Weierstrass equation:
 *      y^2 + x*y = x^3 + a*x^2 + b.
 */
int ec_GF2m_nist_is_on_curve(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx)
	{
	int ret = -1;
	BN_CTX *new_ctx = NULL;
	BIGNUM *lh, *y2;
	int (*field_mul)(const EC_GROUP *, BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
	int (*field_sqr)(const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *);
	int field_size;

	if (EC_POINT_is_at_infinity(group, point))
		return 1;

	field_mul = group->meth->field_mul;
	field_sqr = group->meth->field_sqr;
	field_size= (group->poly[0] / BN_BITS2) + 1;

	/* only support affine coordinates */
	if (!point->Z_is_one) return -1;

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return -1;
		}

	BN_CTX_start(ctx);
	y2 = BN_CTX_get(ctx);
	lh = BN_CTX_get(ctx);
	if (lh == NULL) goto err;

	if (!BN_GF2m_const_init(y2, field_size)) goto err;
	if (!BN_GF2m_const_init(lh, field_size)) goto err;

	/* We have a curve defined by a Weierstrass equation
	 *      y^2 + x*y = x^3 + a*x^2 + b.
	 *  <=> x^3 + a*x^2 + x*y + b + y^2 = 0
	 *  <=> ((x + a) * x + y ) * x + b + y^2 = 0
	 */
	if (!BN_GF2m_const_add(lh, &point->X, &group->a)) goto err;
	if (!field_mul(group, lh, lh, &point->X, ctx)) goto err;
	if (!BN_GF2m_const_add(lh, lh, &point->Y)) goto err;
	if (!field_mul(group, lh, lh, &point->X, ctx)) goto err;
	if (!BN_GF2m_const_add(lh, lh, &group->b)) goto err;
	if (!field_sqr(group, y2, &point->Y, ctx)) goto err;
	if (!BN_GF2m_const_add(lh, lh, y2)) goto err;

	ret = BN_GF2m_const_cmp_zero(lh);
 err:
	if (ctx) BN_CTX_end(ctx);
	if (new_ctx) BN_CTX_free(new_ctx);
	return ret;
	}


/* Indicates whether two points are equal.
 * Return values:
 *  -1   error
 *   0   equal (in affine coordinates)
 *   1   not equal
 */
int ec_GF2m_nist_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx)
	{
	BIGNUM *aX, *aY, *bX, *bY;
	BN_CTX *new_ctx = NULL;
	int field_size, ret = -1;
	field_size = (group->poly[0] / BN_BITS2) + 1;

	if (EC_POINT_is_at_infinity(group, a))
		{
		return EC_POINT_is_at_infinity(group, b) ? 0 : 1;
		}

	if (EC_POINT_is_at_infinity(group, b))
		return 1;

	if (a->Z_is_one && b->Z_is_one)
		{
		return ((BN_GF2m_const_cmp_eq(&a->X, &b->X)) && BN_GF2m_const_cmp_eq(&a->Y, &b->Y)) ? 0 : 1; 
		}

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return -1;
		}

	BN_CTX_start(ctx);
	aX = BN_CTX_get(ctx);
	aY = BN_CTX_get(ctx);
	bX = BN_CTX_get(ctx);
	bY = BN_CTX_get(ctx);
	if (bY == NULL) goto err;

	if (!BN_GF2m_const_init(aX, field_size)) goto err;
	if (!BN_GF2m_const_init(aY, field_size)) goto err;
	if (!BN_GF2m_const_init(bX, field_size)) goto err;
	if (!BN_GF2m_const_init(bY, field_size)) goto err;

	if (!EC_POINT_get_affine_coordinates_GF2m(group, a, aX, aY, ctx)) goto err;
	if (!EC_POINT_get_affine_coordinates_GF2m(group, b, bX, bY, ctx)) goto err;
	ret = ((BN_GF2m_const_cmp_eq(aX, bX)) && BN_GF2m_const_cmp_eq(aY, bY)) ? 0 : 1;

  err:
	if (ctx) BN_CTX_end(ctx);
	if (new_ctx) BN_CTX_free(new_ctx);
	return ret;
	}


/* Forces the given EC_POINT to internally use affine coordinates. */
int ec_GF2m_nist_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	BIGNUM *x, *y;
	int ret = 0;

	if (point->Z_is_one || EC_POINT_is_at_infinity(group, point))
		return 1;

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
		}

	int field_size = (group->poly[0] / BN_BITS2) + 1;

	BN_CTX_start(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	if (y == NULL) goto err;

	if (!BN_GF2m_const_init(x, field_size)) goto err;
	if (!BN_GF2m_const_init(y, field_size)) goto err;

	if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x, y, ctx)) goto err;
	if (!BN_GF2m_const_copy(&point->X, x)) goto err;
	if (!BN_GF2m_const_copy(&point->Y, y)) goto err;
	if (!BN_one(&point->Z)) goto err;

	ret = 1;

  err:
	if (ctx) BN_CTX_end(ctx);
	if (new_ctx) BN_CTX_free(new_ctx);
	return ret;
	}


/* Forces each of the EC_POINTs in the given array to use affine coordinates. */
int ec_GF2m_nist_points_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[], BN_CTX *ctx)
	{
	size_t i;

	for (i = 0; i < num; i++)
		{
		if (!group->meth->make_affine(group, points[i], ctx)) return 0;
		}

	return 1;
	}



/* Wrapper to binary polynomial field multiplication implementation. */
int ec_GF2m_nist163_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_mul_xmm_nist163(r, a, b);
	}


/* Wrapper to binary polynomial field squaring implementation. */
int ec_GF2m_nist163_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	return BN_GF2m_sqr_xmm_nist163(r, a);
	}


/* Wrapper to binary polynomial field division implementation. */
int ec_GF2m_nist163_field_div(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_div_xmm_nist163(r, a, b);
	}


/* Wrapper to binary polynomial field multiplication implementation. */
int ec_GF2m_sect193_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_mul_xmm_sect193(r, a, b);
	}


/* Wrapper to binary polynomial field squaring implementation. */
int ec_GF2m_sect193_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	return BN_GF2m_sqr_xmm_sect193(r, a);
	}

/* Wrapper to binary polynomial field division implementation. */
int ec_GF2m_sect193_field_div(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_div_xmm_sect193(r, a, b);
	}


/* Wrapper to binary polynomial field multiplication implementation. */
int ec_GF2m_nist233_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_mul_xmm_nist233(r, a, b);
	}


/* Wrapper to binary polynomial field squaring implementation. */
int ec_GF2m_nist233_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	return BN_GF2m_sqr_xmm_nist233(r, a);
	}


/* Wrapper to binary polynomial field division implementation. */
int ec_GF2m_nist233_field_div(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_div_xmm_nist233(r, a, b);
	}

/* Wrapper to binary polynomial field multiplication implementation. */
int ec_GF2m_sect239_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_mul_xmm_sect239(r, a, b);
	}


/* Wrapper to binary polynomial field squaring implementation. */
int ec_GF2m_sect239_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	return BN_GF2m_sqr_xmm_sect239(r, a);
	}


/* Wrapper to binary polynomial field division implementation. */
int ec_GF2m_sect239_field_div(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_div_xmm_sect239(r, a, b);
	}


/* Wrapper to binary polynomial field multiplication implementation. */
int ec_GF2m_nist283_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_mul_xmm_nist283(r, a, b);
	}


/* Wrapper to binary polynomial field squaring implementation. */
int ec_GF2m_nist283_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	return BN_GF2m_sqr_xmm_nist283(r, a);
	}


/* Wrapper to binary polynomial field division implementation. */
int ec_GF2m_nist283_field_div(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_div_xmm_nist283(r, a, b);
	}



/* Wrapper to binary polynomial field multiplication implementation. */
int ec_GF2m_nist409_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_mul_xmm_nist409(r, a, b);
	}


/* Wrapper to binary polynomial field squaring implementation. */
int ec_GF2m_nist409_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	return BN_GF2m_sqr_xmm_nist409(r, a);
	}


/* Wrapper to binary polynomial field division implementation. */
int ec_GF2m_nist409_field_div(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_div_xmm_nist409(r, a, b);
	}


/* Wrapper to binary polynomial field multiplication implementation. */
int ec_GF2m_nist571_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_mul_xmm_nist571(r, a, b);
	}


/* Wrapper to binary polynomial field squaring implementation. */
int ec_GF2m_nist571_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	return BN_GF2m_sqr_xmm_nist571(r, a);
	}


/* Wrapper to binary polynomial field division implementation. */
int ec_GF2m_nist571_field_div(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	return BN_GF2m_div_xmm_nist571(r, a, b);
	}


#else

/* Fallback to simple method */
const EC_METHOD *EC_GF2m_nist163_method(void)
	{
	return EC_GF2m_simple_method();
	}
const EC_METHOD *EC_GF2m_sect193_method(void)
	{
	return EC_GF2m_simple_method();
	}
const EC_METHOD *EC_GF2m_nist233_method(void)
	{
	return EC_GF2m_simple_method();
	}
const EC_METHOD *EC_GF2m_sect239_method(void)
	{
	return EC_GF2m_simple_method();
	}
const EC_METHOD *EC_GF2m_nist283_method(void)
	{
	return EC_GF2m_simple_method();
	}
const EC_METHOD *EC_GF2m_nist409_method(void)
	{
	return EC_GF2m_simple_method();
	}
const EC_METHOD *EC_GF2m_nist571_method(void)
	{
	return EC_GF2m_simple_method();
	}

#endif

#endif
