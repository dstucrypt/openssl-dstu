/* crypto/ec/ec2_prec.c */
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

#ifdef OPENSSL_FAST_EC2M

#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include "ec_lcl.h"

#define 	BN_NIST163_TOP		(163 / BN_BITS2) + 1
#define 	BN_SECT193_TOP 		(193 / BN_BITS2) + 1
#define 	BN_NIST233_TOP 		(233 / BN_BITS2) + 1
#define 	BN_SECT239_TOP 		(239 / BN_BITS2) + 1
#define 	BN_NIST283_TOP 		(283 / BN_BITS2) + 1
#define 	BN_NIST409_TOP 		(409 / BN_BITS2) + 1
#define 	BN_SECT571_TOP 		(571 / BN_BITS2) + 1

/* Precomputation values of c = sqrt(b) = b^(2^(m-1)) for SECT/NIST CURVES */

static const BN_ULONG _gf2m_nist163r1[] = {
	0xCD01BFB889B95835ULL, 0x6E1856BC7EA9A472LL, 0x000000009917A255ULL
};

static const BN_ULONG _gf2m_nist163r2[] = {
	0xDA89C03969F34DA5ULL, 0xDF8927593D21C366ULL, 0x00000002C25B85BAULL
};

static const BN_ULONG _gf2m_sect193r1[] = {
	0xD43F8BE752FDFB06ULL, 0x139483AFD24E42E9ULL, 0xDE5FB3D7DDEE67CDULL,
	0x0000000000000001ULL
};

static const BN_ULONG _gf2m_sect193r2[] = {
	0x03830909465F6662ULL, 0xBFBA42912F39ACBDULL, 0x5F74B124AEFB0E63ULL,
	0x0000000000000001ULL
};

static const BN_ULONG _gf2m_nist233r1[] = {
	0xE5F946D061DA9138ULL, 0x71CAAEEA52F21253ULL, 0x7874E747EE31E06DULL,
	0x00000187F85627B9ULL
};

static const BN_ULONG _gf2m_nist283r1[] = {
	0x17442AEDE9B9B3F6ULL, 0x304424CA17C082AEULL, 0x9FB6F835A2FD220AULL,
	0x5792B1EBE8198308ULL, 0x00000000072BCC9CULL
};

static const BN_ULONG _gf2m_nist409r1[] = {
	0x872ACCF0BC25D5EFULL, 0x73326C528A48E27BULL, 0xFDE895950CF65767ULL,
	0xD0AD7CE57C1B2649ULL, 0xA29F53CB5D93AB2EULL, 0xE4768EE2EF22F9B4ULL,
	0x00000000009935F7ULL
};

static const BN_ULONG _gf2m_nist571r1[] = {
	0x699B08443B761C43ULL, 0x71BEDFC10CE39B64ULL, 0x06F0340E3594A7F7ULL,
	0x60536B58460CD20CULL, 0x362C4800A874AB0BULL, 0x041D7AA1255902E6ULL,
	0x68D41C59135429EBULL, 0xDD739A058DFFD582ULL, 0x0732D556640C20B5ULL
};


/* BIGNUM declarations */
static const BIGNUM _bignum_gf2m_nist163r1 =
{
	(BN_ULONG *)_gf2m_nist163r1,
	BN_NIST163_TOP,
	BN_NIST163_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_gf2m_nist163r2 =
{
	(BN_ULONG *)_gf2m_nist163r2,
	BN_NIST163_TOP,
	BN_NIST163_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_gf2m_sect193r1 =
{
	(BN_ULONG *)_gf2m_sect193r1,
	BN_SECT193_TOP,
	BN_SECT193_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_gf2m_sect193r2 =
{
	(BN_ULONG *)_gf2m_sect193r2,
	BN_SECT193_TOP,
	BN_SECT193_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_gf2m_nist233r1 =
{
	(BN_ULONG *)_gf2m_nist233r1,
	BN_NIST233_TOP,
	BN_NIST233_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_gf2m_nist283r1 =
{
	(BN_ULONG *)_gf2m_nist283r1,
	BN_NIST283_TOP,
	BN_NIST283_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_gf2m_nist409r1 =
{
	(BN_ULONG *)_gf2m_nist409r1,
	BN_NIST409_TOP,
	BN_NIST409_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_gf2m_nist571r1 =
{
	(BN_ULONG *)_gf2m_nist571r1,
	BN_SECT571_TOP,
	BN_SECT571_TOP,
	0,
	BN_FLG_STATIC_DATA
};

/* Returns the precomputation value for a specific curve or NULL. */
const BIGNUM *ec_GF2m_get_sqrt_b(const EC_GROUP *group)
{
	const BIGNUM *ret;

	switch ( group->curve_name )
	{
		case NID_sect163r1:					ret = &_bignum_gf2m_nist163r1; 		break;
		case NID_sect163r2:					ret = &_bignum_gf2m_nist163r2; 		break;
		case NID_sect193r1:					ret = &_bignum_gf2m_sect193r1; 		break;
		case NID_sect193r2:					ret = &_bignum_gf2m_sect193r2; 		break;
		case NID_sect233r1:					ret = &_bignum_gf2m_nist233r1; 		break;
		case NID_sect283r1:					ret = &_bignum_gf2m_nist283r1; 		break;
		case NID_sect409r1:					ret = &_bignum_gf2m_nist409r1; 		break;
		case NID_sect571r1:					ret = &_bignum_gf2m_nist571r1; 		break;

		default:							ret =  NULL; 						break;

	}

	return ret;
}

#endif
