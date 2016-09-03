/* crypto/bn/bn_gf2m_xmm.c */
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
#ifndef OPENSSL_NO_EC2M

#ifdef OPENSSL_FAST_EC2M

#include "bn_lcl.h"

#if defined(__INTEL_COMPILER)
	#include <ia32intrin.h>
#elif defined(__GNUC__)
	#include <x86intrin.h>
#endif


/* Load, store and extraction */
#define	 	LOAD_64		_mm_loadl_epi64
#define	 	LOAD128		_mm_load_si128
#define	 	STORE_64	_mm_storel_epi64
#define	 	STORE128	_mm_store_si128
#define	 	SET64		_mm_set_epi64x
#define	 	GET64		_mm_extract_epi64

/* Arithmetic */
#define	 	CLMUL		_mm_clmulepi64_si128
#define	 	SHUFFLE		_mm_shuffle_epi8
#define	 	XOR			_mm_xor_si128
#define	 	AND			_mm_and_si128
#define	 	NAND		_mm_andnot_si128
#define	 	OR			_mm_or_si128
#define	 	SHL			_mm_slli_epi64
#define	 	SHR			_mm_srli_epi64
#define	 	SHL128		_mm_slli_si128
#define	 	SHR128		_mm_srli_si128

/* Memory alignment */
#define	 	ZERO		_mm_setzero_si128()
#define  	ALIGNR		_mm_alignr_epi8
#define  	MOVE64		_mm_move_epi64
#define	 	UNPACKLO8	_mm_unpacklo_epi8
#define	 	UNPACKHI8	_mm_unpackhi_epi8
#define	 	UNPACKLO64	_mm_unpacklo_epi64
#define	 	UNPACKHI64	_mm_unpackhi_epi64


/*********************************************************************************************
 *	BN <-> XMM CONVERSATIONS
 *
 *  Functions to convert between XMM and BN representation.
 *
 *********************************************************************************************/

static inline void BN_to_XMM_3term(__m128i z[2], BN_ULONG *a)
    {
    z[0] = LOAD128((__m128i *) (a + 0));
    z[1] = LOAD_64((__m128i *) (a + 2));
    }

static inline void BN_to_XMM_4term(__m128i z[2], BN_ULONG *a)
    {
    z[0] = LOAD128((__m128i *) (a + 0));
    z[1] = LOAD128((__m128i *) (a + 2));
    }

static inline void BN_to_XMM_5term(__m128i z[3], BN_ULONG *a)
    {
    z[0] = LOAD128((__m128i *) (a + 0));
    z[1] = LOAD128((__m128i *) (a + 2));
    z[2] = LOAD_64((__m128i *) (a + 4));
    }

static inline void BN_to_XMM_6term(__m128i z[3], BN_ULONG *a)
    {
    z[0] = LOAD128((__m128i *) (a + 0));
    z[1] = LOAD128((__m128i *) (a + 2));
    z[2] = LOAD128((__m128i *) (a + 4));
    }

static inline void BN_to_XMM_7term(__m128i z[4], BN_ULONG *a)
    {
    z[0] = LOAD128((__m128i *) (a + 0));
    z[1] = LOAD128((__m128i *) (a + 2));
    z[2] = LOAD128((__m128i *) (a + 4));
    z[3] = LOAD_64((__m128i *) (a + 6));
    }

static inline void BN_to_XMM_8term(__m128i z[4], BN_ULONG *a)
    {
    z[0] = LOAD128((__m128i *) (a + 0));
    z[1] = LOAD128((__m128i *) (a + 2));
    z[2] = LOAD128((__m128i *) (a + 4));
    z[3] = LOAD128((__m128i *) (a + 6));
    }

static inline void BN_to_XMM_9term(__m128i z[5], BN_ULONG *a)
    {
    z[0] = LOAD128((__m128i *) (a + 0));
    z[1] = LOAD128((__m128i *) (a + 2));
    z[2] = LOAD128((__m128i *) (a + 4));
    z[3] = LOAD128((__m128i *) (a + 6));
    z[4] = LOAD_64((__m128i *) (a + 8));
    }

static inline void XMM_to_BN_3term(BN_ULONG *z, __m128i a[2])
    {
    STORE128((__m128i *) (z), a[0]);
    STORE_64((__m128i *) (z + 2), a[1]);
    }

static inline void XMM_to_BN_4term(BN_ULONG *z, __m128i a[2])
    {
    STORE128((__m128i *) (z + 0), a[0]);
    STORE128((__m128i *) (z + 2), a[1]);
    }

static inline void XMM_to_BN_5term(BN_ULONG *z, __m128i a[3])
    {
    STORE128((__m128i *) (z + 0), a[0]);
    STORE128((__m128i *) (z + 2), a[1]);
    STORE_64((__m128i *) (z + 4), a[2]);
    }

static inline void XMM_to_BN_6term(BN_ULONG *z, __m128i a[3])
    {
    STORE128((__m128i *) (z + 0), a[0]);
    STORE128((__m128i *) (z + 2), a[1]);
    STORE128((__m128i *) (z + 4), a[2]);
    }

static inline void XMM_to_BN_7term(BN_ULONG *z, __m128i a[4])
    {
    STORE128((__m128i *) (z + 0), a[0]);
    STORE128((__m128i *) (z + 2), a[1]);
    STORE128((__m128i *) (z + 4), a[2]);
    STORE_64((__m128i *) (z + 6), a[3]);
    }

static inline void XMM_to_BN_8term(BN_ULONG *z, __m128i a[4])
    {
    STORE128((__m128i *) (z + 0), a[0]);
    STORE128((__m128i *) (z + 2), a[1]);
    STORE128((__m128i *) (z + 4), a[2]);
    STORE128((__m128i *) (z + 6), a[3]);
    }

static inline void XMM_to_BN_9term(BN_ULONG *z, __m128i a[5])
    {
    STORE128((__m128i *) (z + 0), a[0]);
    STORE128((__m128i *) (z + 2), a[1]);
    STORE128((__m128i *) (z + 4), a[2]);
    STORE128((__m128i *) (z + 6), a[3]);
    STORE_64((__m128i *) (z + 8), a[4]);
    }

/*********************************************************************************************
 *	XMM COPY
 *
 *  Functions to copy numbers in XMM representation.
 *
 *********************************************************************************************/

static inline void XMM_GF2m_copy_2term(__m128i z[2], const __m128i a[2])
    {
    z[0] = a[0];
    z[1] = a[1];
    }

static inline void XMM_GF2m_copy_3term(__m128i z[3], const __m128i a[3])
    {
    z[0] = a[0];
    z[1] = a[1];
    z[2] = a[2];
    }

static inline void XMM_GF2m_copy_4term(__m128i z[4], const __m128i a[4])
    {
    z[0] = a[0];
    z[1] = a[1];
    z[2] = a[2];
    z[3] = a[3];
    }

static inline void XMM_GF2m_copy_5term(__m128i z[5], const __m128i a[5])
    {
    z[0] = a[0];
    z[1] = a[1];
    z[2] = a[2];
    z[3] = a[3];
    z[4] = a[4];
    }

/*********************************************************************************************
 *	XMM ADDITION
 *
 *  This section implements addition in GF(2^m) in XMM registers.
 *
 *********************************************************************************************/

static inline void XMM_GF2m_add_2term(__m128i z[2], __m128i a[2], __m128i b[2])
	{
    z[0] = XOR(a[0], b[0]);
    z[1] = XOR(a[1], b[1]);
	}

static inline void XMM_GF2m_add_3term(__m128i z[3], __m128i a[3], __m128i b[3])
	{
    z[0] = XOR(a[0], b[0]);
    z[1] = XOR(a[1], b[1]);
    z[2] = XOR(a[2], b[2]);
	}

static inline void XMM_GF2m_add_4term(__m128i z[4], __m128i a[4], __m128i b[4])
	{
    z[0] = XOR(a[0], b[0]);
    z[1] = XOR(a[1], b[1]);
    z[2] = XOR(a[2], b[2]);
    z[3] = XOR(a[3], b[3]);
    }

static inline void XMM_GF2m_add_5term(__m128i z[5], __m128i a[5], __m128i b[5])
	{
    z[0] = XOR(a[0], b[0]);
    z[1] = XOR(a[1], b[1]);
    z[2] = XOR(a[2], b[2]);
    z[3] = XOR(a[3], b[3]);
    z[4] = XOR(a[4], b[4]);
	}

static inline void XMM_GF2m_add_7term(__m128i z[7], __m128i a[7], __m128i b[7])
	{
 	z[0] = XOR(a[0], b[0]);
	z[1] = XOR(a[1], b[1]);
	z[2] = XOR(a[2], b[2]);
	z[3] = XOR(a[3], b[3]);
	z[4] = XOR(a[4], b[4]);
	z[5] = XOR(a[5], b[5]);
	z[6] = XOR(a[6], b[6]);
	}

static inline void XMM_GF2m_add_9term(__m128i z[9], __m128i a[9], __m128i b[9])
	{
     z[0] = XOR(a[0], b[0]);
     z[1] = XOR(a[1], b[1]);
     z[2] = XOR(a[2], b[2]);
     z[3] = XOR(a[3], b[3]);
     z[4] = XOR(a[4], b[4]);
     z[5] = XOR(a[5], b[5]);
     z[6] = XOR(a[6], b[6]);
     z[7] = XOR(a[7], b[7]);
     z[8] = XOR(a[8], b[8]);
	}

/*********************************************************************************************
 *	XMM VEILING
 *
 *  This section implements the data veiling for the Montgomery point multiplication.
 *
 *********************************************************************************************/

static inline void XMM_GF2m_mask_2term(__m128i z[2], __m128i y[2],
		__m128i a[2], __m128i b[2], __m128i mask)
	{
	z[0] = AND(mask, a[0]);
	z[1] = AND(mask, a[1]);
	y[0] = NAND(mask, b[0]);
	y[1] = NAND(mask, b[1]);
	}

static inline void XMM_GF2m_mask_3term(__m128i z[3], __m128i y[3],
		__m128i a[3], __m128i b[3], __m128i mask)
	{
	z[0] = AND(mask, a[0]);
	z[1] = AND(mask, a[1]);
	z[2] = AND(mask, a[2]);
	y[0] = NAND(mask, b[0]);
	y[1] = NAND(mask, b[1]);
	y[2] = NAND(mask, b[2]);
	}

static inline void XMM_GF2m_mask_4term(__m128i z[4], __m128i y[4],
		__m128i a[4], __m128i b[4], __m128i mask)
	{
	z[0] = AND(mask, a[0]);
	z[1] = AND(mask, a[1]);
	z[2] = AND(mask, a[2]);
	z[3] = AND(mask, a[3]);
	y[0] = NAND(mask, b[0]);
	y[1] = NAND(mask, b[1]);
	y[2] = NAND(mask, b[2]);
	y[3] = NAND(mask, b[3]);
	}

static inline void XMM_GF2m_mask_5term(__m128i z[4], __m128i y[4],
		__m128i a[4], __m128i b[4], __m128i mask)
	{
	z[0] = AND(mask, a[0]);
	z[1] = AND(mask, a[1]);
	z[2] = AND(mask, a[2]);
	z[3] = AND(mask, a[3]);
	z[4] = AND(mask, a[4]);
	y[0] = NAND(mask, b[0]);
	y[1] = NAND(mask, b[1]);
	y[2] = NAND(mask, b[2]);
	y[3] = NAND(mask, b[3]);
	y[4] = NAND(mask, b[4]);
	}


static inline void XMM_GF2m_veil_2term(__m128i x1[2], __m128i z1[2], __m128i x2[2], __m128i z2[2],
		__m128i tx1[2], __m128i tz1[2], __m128i tx2[2], __m128i tz2[2], BN_ULONG k)
	{
	__m128i mask, t1[2], t2[2];
	BN_ULONG mk;

	mk = (0 - k);
	mask = SET64(mk, mk);

	XMM_GF2m_mask_2term(t1,t2,tx1,tx2,mask);
	XMM_GF2m_add_2term(x1, t1, t2);

	XMM_GF2m_mask_2term(t1,t2,tx2,tx1,mask);
	XMM_GF2m_add_2term(x2, t1, t2);

	XMM_GF2m_mask_2term(t1,t2,tz1,tz2,mask);
	XMM_GF2m_add_2term(z1, t1, t2);

	XMM_GF2m_mask_2term(t1,t2,tz2,tz1,mask);
	XMM_GF2m_add_2term(z2, t1, t2);
	}

static inline void XMM_GF2m_veil_3term(__m128i x1[3], __m128i z1[3], __m128i x2[3], __m128i z2[3],
		__m128i tx1[3], __m128i tz1[3], __m128i tx2[3], __m128i tz2[3], BN_ULONG k)
	{
	__m128i mask, t1[3], t2[3];
	BN_ULONG mk;

	mk = (0 - k);
	mask = SET64(mk, mk);

	XMM_GF2m_mask_3term(t1,t2,tx1,tx2,mask);
	XMM_GF2m_add_3term(x1, t1, t2);

	XMM_GF2m_mask_3term(t1,t2,tx2,tx1,mask);
	XMM_GF2m_add_3term(x2, t1, t2);

	XMM_GF2m_mask_3term(t1,t2,tz1,tz2,mask);
	XMM_GF2m_add_3term(z1, t1, t2);

	XMM_GF2m_mask_3term(t1,t2,tz2,tz1,mask);
	XMM_GF2m_add_3term(z2, t1, t2);
	}

static inline void XMM_GF2m_veil_4term(__m128i x1[4], __m128i z1[4], __m128i x2[4], __m128i z2[4],
		__m128i tx1[4], __m128i tz1[4], __m128i tx2[4], __m128i tz2[4], BN_ULONG k)
	{
	__m128i mask, t1[4], t2[4];
	BN_ULONG mk;

	mk = (0 - k);
	mask = SET64(mk, mk);

	XMM_GF2m_mask_4term(t1,t2,tx1,tx2,mask);
	XMM_GF2m_add_4term(x1, t1, t2);

	XMM_GF2m_mask_4term(t1,t2,tx2,tx1,mask);
	XMM_GF2m_add_4term(x2, t1, t2);

	XMM_GF2m_mask_4term(t1,t2,tz1,tz2,mask);
	XMM_GF2m_add_4term(z1, t1, t2);

	XMM_GF2m_mask_4term(t1,t2,tz2,tz1,mask);
	XMM_GF2m_add_4term(z2, t1, t2);
	}

static inline void XMM_GF2m_veil_5term(__m128i x1[5], __m128i z1[5], __m128i x2[5], __m128i z2[5],
		__m128i tx1[5], __m128i tz1[5], __m128i tx2[5], __m128i tz2[5], BN_ULONG k)
	{
	__m128i mask, t1[5], t2[5];
	BN_ULONG mk;

	mk = (0 - k);
	mask = SET64(mk, mk);

	XMM_GF2m_mask_5term(t1,t2,tx1,tx2,mask);
	XMM_GF2m_add_5term(x1, t1, t2);

	XMM_GF2m_mask_5term(t1,t2,tx2,tx1,mask);
	XMM_GF2m_add_5term(x2, t1, t2);

	XMM_GF2m_mask_5term(t1,t2,tz1,tz2,mask);
	XMM_GF2m_add_5term(z1, t1, t2);

	XMM_GF2m_mask_5term(t1,t2,tz2,tz1,mask);
	XMM_GF2m_add_5term(z2, t1, t2);
	}


/*********************************************************************************************
 *	XMM REDUCTION
 *
 *  Reductions of elements with double field size (2*m bits) r to elements of GF(2^m) for
 *  selected SECT/NIST curves.
 *  Results are stored in z. The content of r may be destroyed and should not be re-
 *  used after calling this functions.
 *
 *********************************************************************************************/

static inline void XMM_GF2m_mod_nist163(__m128i z[2], __m128i r[3])
    {
    __m128i x[5];

	x[0] = SHR(r[2], 35);
	x[1] = SHL(r[2], 29);

	x[3] = SHL128(r[2], 4);
	x[1] = XOR(x[1], x[3]);

	x[2] = SHR(r[2], 29);
	x[3] = SHL(r[2], 35);
	x[0] = XOR(x[0], x[2]);
	x[1] = XOR(x[1], x[3]);

	x[2] = SHR(r[2], 28);
	x[3] = SHL(r[2], 36);
	x[0] = XOR(x[0], x[2]);
	x[1] = XOR(x[1], x[3]);

	x[2] = SHL128(x[1], 8);
	x[1] = SHR128(x[1], 8);
	x[0] = XOR(x[0], x[1]);

	z[0] = XOR(r[0], x[2]);
	z[1] = XOR(r[1], x[0]);

	/* Clear top */
	x[1] = SET64(0xFFFFFFFFFFFFFFFF, 0xFFFFFFF800000000);
	x[4] = AND(x[1], z[1]);
	z[1] = NAND(x[1], z[1]);

	x[0] = SHR(x[4], 35);
	x[1] = SHL(x[4], 29);

	x[2] = SHR128(x[4], 4);
	x[0] = XOR(x[0], x[2]);

	x[2] = SHR(x[4], 29);
	x[3] = SHL(x[4], 35);
	x[0] = XOR(x[0], x[2]);
	x[1] = XOR(x[1], x[3]);

	x[2] = SHR(x[4], 28);
	x[3] = SHL(x[4], 36);
	x[0] = XOR(x[0], x[2]);
	x[1] = XOR(x[1], x[3]);

	x[1] = SHR128(x[1], 8);
	x[0] = XOR(x[0], x[1]);
	z[0] = XOR(z[0], x[0]);

    }


static inline void XMM_GF2m_mod_nist163_clmul(__m128i z[2], __m128i a[3])
	{
	__m128i _p, x[2], m[2];

	_p = SET64(0, 0x000001920000000);

	m[0] = CLMUL(a[2], _p, 0x01);
	m[1] = CLMUL(a[2], _p, 0x00);
	
	z[1] = XOR(a[1], m[0]);
	x[0] = SHL128(m[1], 8);
	x[1] = SHR128(m[1], 8);
	z[0] = XOR(a[0], x[0]);
	z[1] = XOR(z[1], x[1]);

	x[0] = SET64(0xFFFFFFFFFFFFFFFF, 0xFFFFFFF800000000);
	x[1] = AND(x[0], z[1]);
	z[1] = NAND(x[0], z[1]);

	m[0] = CLMUL(x[1], _p, 0x01);
	m[1] = CLMUL(x[1], _p, 0x00);
	
	z[0] = XOR(z[0], m[0]);
	x[0] = SHR128(m[1], 8);
	z[0] = XOR(z[0], x[0]);
	}

static inline void XMM_GF2m_mod_sect193(__m128i z[2], __m128i r[4])
    {
    __m128i x[5];

    x[0] = SHL(r[3], 14);
    x[1] = SHR(r[3], 1);
    x[2] = SHL(r[3], 63);
    z[1] = XOR(r[1], x[2]);
    x[4] = XOR(x[0], x[1]);

    x[0] = SHR(r[2], 50);
    x[1] = SHL(r[2], 14);
    x[2] = SHR(r[2], 1);
    x[3] = SHL(r[2], 63);
    z[1] = XOR(z[1], x[0]);
    z[0] = XOR(r[0], x[3]);
    x[0] = XOR(x[1], x[2]);
    x[4] = ALIGNR(x[4], x[0], 8);
    z[1] = XOR(z[1], x[4]);

    /* Clear top */
    x[3] = SET64(0x0000000000000001, 0xFFFFFFFFFFFFFFFF);
    x[4] = NAND(x[3], z[1]);
    z[1] = AND(z[1], x[3]);
    x[1] = SHR(x[4], 1);
    x[0] = ALIGNR(x[0], x[1], 8);
    x[1] = MOVE64(x[0]);
    z[0] = XOR(z[0], x[0]);
    x[1] = SHL(x[1], 15);
    z[0] = XOR(z[0], x[1]);
    x[2] = SHR(x[4], 50);
    z[0] = XOR(z[0], x[2]);
    }

static inline void XMM_GF2m_mod_nist233(__m128i z[2], __m128i r[4])
    {
    __m128i x[6];

    x[0] = SHL(r[3], 33);
    x[1] = SHR(r[3], 31);
    x[2] = SHL(r[3], 23);
    x[3] = SHR(r[3], 41);

    x[4] = XOR(x[0], x[3]);
    x[3] = SHR128(x[4], 8);
    z[1] = XOR(r[1], x[2]);
    r[2] = XOR(r[2], x[1]);
    r[2] = XOR(r[2], x[3]);

    x[0] = SHL(r[2], 33);
    x[1] = SHR(r[2], 31);
    x[2] = SHL(r[2], 23);
    x[3] = SHR(r[2], 41);

    x[5] = XOR(x[0], x[3]);
    x[3] = ALIGNR(x[4], x[5], 8);
    z[0] = XOR(r[0], x[2]);
    z[1] = XOR(z[1], x[1]);
    z[1] = XOR(z[1], x[3]);

    /* Clear top */
    x[2] = SET64(0x000001FFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
    x[0] = NAND(x[2], z[1]);
    x[0] = SHR(x[0], 41);
    x[1] = ALIGNR(x[5], x[0], 8);
    z[0] = XOR(z[0], x[1]);
    x[1] = SHL(x[0], 10);
    z[0] = XOR(z[0], x[1]);
    z[1] = AND(z[1], x[2]);

    }

/* Reduction of elements in GF(2^239) is provided in 64-bit mode only. */
static inline void XMM_GF2m_mod_sect239(__m128i z[2], __m128i r[4])
    {
    BN_ULONG zz, x[8];

    STORE128((__m128i *) (x + 0), r[0]);
    STORE128((__m128i *) (x + 2), r[1]);
    STORE128((__m128i *) (x + 4), r[2]);
    STORE128((__m128i *) (x + 6), r[3]);

    zz = x[7];
    x[6] ^= (zz >> 17);
    x[5] ^= (zz << 47);
    x[4] ^= (zz >> 47);
    x[3] ^= (zz << 17);

    zz = x[6];
    x[5] ^= (zz >> 17);
    x[4] ^= (zz << 47);
    x[3] ^= (zz >> 47);
    x[2] ^= (zz << 17);

    zz = x[5];
    x[4] ^= (zz >> 17);
    x[3] ^= (zz << 47);
    x[2] ^= (zz >> 47);
    x[1] ^= (zz << 17);

    zz = x[4];
    x[3] ^= (zz >> 17);
    x[2] ^= (zz << 47);
    x[1] ^= (zz >> 47);
    x[0] ^= (zz << 17);

    /* Clear top */
    zz = (x[3] >> 47);
    x[3] &= 0x00007FFFFFFFFFFF;
    x[0] ^= zz;
    x[2] ^= (zz << 30);

    z[0] = LOAD128((__m128i *) (x));
    z[1] = LOAD128((__m128i *) (x + 2));
    }

static inline void XMM_GF2m_mod_nist283_clmul(__m128i z[3], __m128i r[5])
	{
	__m128i poly, x[2], m[5];

	poly = SET64(0, 0x0002142000000000);

	m[0] = CLMUL(r[4], poly, 0x00);
	m[1] = CLMUL(r[3], poly, 0x01);
	m[2] = CLMUL(r[3], poly, 0x00);

	x[0] = SHR128(m[0], 8);
	z[2] = XOR(r[2], x[0]);
	z[1] = XOR(m[1], r[1]);
	x[0] = ALIGNR(m[0], m[2], 8);
	z[1] = XOR(x[0], z[1]);

	x[0] = SHL128(m[2], 8);
	z[0] = XOR(x[0], r[0]);

	x[0] = SET64(0x0000000000000000, 0x0000000007FFFFFF);
	x[1] = NAND(x[0], z[2]);
	z[2] = AND(x[0], z[2]);

	m[3] = CLMUL(x[1], poly, 0x01);
	m[4] = CLMUL(x[1], poly, 0x00);

	x[0] = SHR128(m[4], 8);
	z[0] = XOR(x[0], z[0]);
	z[0] = XOR(m[3], z[0]);
	}

static inline void XMM_GF2m_mod_nist283(__m128i z[3], __m128i r[5])
    {
    __m128i x[4];

    x[0] = ALIGNR(r[3], r[2], 8);
    x[1] = ALIGNR(r[4], r[3], 8);
    x[3] = r[2];

    r[4] = SHR(r[4], 27);
    r[3] = SHR(r[3], 27);
    x[2] = SHL(x[1], 37);
    r[3] = XOR(r[3], x[2]);
    r[2] = SHR(r[2], 27);
    x[2] = SHL(x[0], 37);
    r[2] = XOR(r[2], x[2]);

    x[0] = ALIGNR(r[4], r[3], 15);
    x[2] = SHR(x[0], 1);
    r[4] = XOR(r[4], x[2]);

    x[1] = ALIGNR(r[3], r[2], 8);
    x[2] = SHL(r[3], 7);
    r[3] = XOR(r[3], x[2]);
    x[2] = SHR(x[1], 57);
    r[3] = XOR(r[3], x[2]);

    x[0] = ALIGNR(r[2], ZERO, 8);
    x[2] = SHL(r[2], 7);
    r[2] = XOR(r[2], x[2]);
    x[2] = SHR(x[0], 57);
    r[2] = XOR(r[2], x[2]);

    x[0] = ALIGNR(r[4], r[3], 15);
    x[1] = SHR(x[0], 3);
    r[4] = XOR(r[4], x[1]);

    x[1] = ALIGNR(r[3], r[2], 8);
    x[2] = SHL(r[3], 5);
    r[3] = XOR(r[3], x[2]);
    x[2] = SHR(x[1], 59);
    r[3] = XOR(r[3], x[2]);

    x[0] = ALIGNR(r[2], ZERO, 8);
    x[2] = SHL(r[2], 5);
    r[2] = XOR(r[2], x[2]);
    x[2] = SHR(x[0], 59);
    r[2] = XOR(r[2], x[2]);

    z[0] = XOR(r[0], r[2]);
    z[1] = XOR(r[1], r[3]);
    z[2] = XOR(x[3], r[4]);

    /* Clear top */
    x[0] = SHR(r[4], 27);
    x[2] = SHL(x[0], 5);
    x[1] = XOR(x[0], x[2]);
    x[2] = SHL(x[1], 7);
    x[0] = XOR(x[1], x[2]);

    z[0] = XOR(z[0], x[0]);
    x[2] = SET64(0x0000000000000000, 0x0000000007FFFFFF);
    z[2] = AND(z[2], x[2]);
    }

static inline void XMM_GF2m_mod_nist409(__m128i z[4], __m128i r[7])
    {
    __m128i x[3], m[12];

    m[0] = SHR(r[6], 2);
    m[1] = SHL(r[6], 62);
    m[2] = SHR(r[6], 25);
    m[3] = SHL(r[6], 39);
    m[4] = SHR(r[5], 2);
    m[5] = SHL(r[5], 62);
    m[6] = SHR(r[5], 25);
    m[7] = SHL(r[5], 39);
    m[8] = SHR(r[4], 2);
    m[9] = SHL(r[4], 62);
    m[10] = SHR(r[4], 25);
    m[11] = SHL(r[4], 39);

    x[0] = XOR(m[1], m[2]);
    z[3] = XOR(r[3], x[0]);
    x[1] = XOR(m[4], m[3]);
    x[2] = ALIGNR(m[0], x[1], 8);
    z[3] = XOR(z[3], x[2]);
    x[0] = XOR(m[5], m[6]);
    z[2] = XOR(r[2], x[0]);
    m[7] = XOR(m[7], m[8]);
    x[1] = ALIGNR(x[1], m[7], 8);
    z[2] = XOR(z[2], x[1]);
    x[2] = XOR(m[9], m[10]);
    z[1] = XOR(r[1], x[2]);

    /* Clear top */
    x[0] = SET64(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFE000000);
    x[0] = AND(z[3], x[0]);
    z[3] = XOR(z[3], x[0]);

    m[0] = SHR(x[0], 2);
    m[1] = SHL(x[0], 62);
    m[2] = SHR(x[0], 25);
    m[3] = SHL(x[0], 39);

    x[0] = XOR(m[11], m[0]);
    x[1] = ALIGNR(m[7], x[0], 8);
    z[1] = XOR(z[1], x[1]);
    x[2] = XOR(m[1], m[2]);
    z[0] = XOR(r[0], x[2]);
    x[0] = ALIGNR(x[0], m[3], 8);
    z[0] = XOR(z[0], x[0]);
    }

static inline void XMM_GF2m_mod_nist571(__m128i z[5], __m128i r[9])
    {
	/* Init */
    const int n = 4;
    int i;
    __m128i x[5];

    x[4] = ZERO;
    for (i=8; i > n; i--)
		{
		x[0] = SHL(r[i], 5);
		x[1] = SHR(r[i], 59);

		x[2] = SHL(r[i], 7);
		x[3] = SHR(r[i], 57);
		x[0] = XOR(x[0], x[2]);
		x[1] = XOR(x[1], x[3]);

		x[2] = SHL(r[i], 10);
		x[3] = SHR(r[i], 54);
		x[0] = XOR(x[0], x[2]);
		x[1] = XOR(x[1], x[3]);

		x[2] = SHL(r[i], 15);
		x[3] = SHR(r[i], 49);
		x[0] = XOR(x[0], x[2]);
		x[1] = XOR(x[1], x[3]);

		x[2] = ALIGNR(x[4], x[0], 8);
		r[i-n] = XOR(r[i-n], x[2]);
		r[i-n] = XOR(r[i-n], x[1]);

		x[4] = x[0];
		}

    x[0] = SHL128(x[4], 8);
    r[i-n] = XOR(r[i-n], x[0]);

    /* Clear top */
    x[4] = SET64(0xFFFFFFFFFFFFFFFF, 0xF800000000000000);
    x[4] = AND(r[4], x[4]);
    r[4] = XOR(r[4], x[4]);

    x[0] = SHR(x[4], 59);
    x[1] = SHL(x[4], 5);

    x[2] = SHR(x[4], 57);
    x[3] = SHL(x[4], 7);
    x[0] = XOR(x[0], x[2]);
    x[1] = XOR(x[1], x[3]);

    x[2] = SHR(x[4], 54);
    x[3] = SHL(x[4], 10);
    x[0] = XOR(x[0], x[2]);
    x[1] = XOR(x[1], x[3]);

    x[2] = SHR(x[4], 49);
    x[3] = SHL(x[4], 15);
    x[0] = XOR(x[0], x[2]);
    x[1] = XOR(x[1], x[3]);

    x[1] = SHR128(x[1], 8);
    r[0] = XOR(r[0], x[1]);

    r[0] = XOR(r[0], x[0]);

    XMM_GF2m_copy_5term(z, r);
    }

static inline void XMM_GF2m_mod_nist571_clmul(__m128i z[5], __m128i r[9])
	{
	__m128i _p, x[10];

	_p = SET64(0, 0x00000000000084A0);

	x[0] = CLMUL(r[8], _p, 0x01);
	x[1] = CLMUL(r[8], _p, 0x00);
	x[2] = CLMUL(r[7], _p, 0x01);
	x[3] = CLMUL(r[7], _p, 0x00);
	x[4] = CLMUL(r[6], _p, 0x01);
	x[5] = CLMUL(r[6], _p, 0x00);
	x[6] = CLMUL(r[5], _p, 0x01);
	x[7] = CLMUL(r[5], _p, 0x00);

	z[4] = XOR(x[0], r[4]);
	z[3] = XOR(x[2], r[3]);
	z[2] = XOR(x[4], r[2]);
	z[1] = XOR(x[6], r[1]);

	x[8] = SHR128(x[1], 8);
	z[4] = XOR(x[8], z[4]);
	x[9] = ALIGNR(x[1], x[3], 8);
	z[3] = XOR(x[9], z[3]);
	x[8] = ALIGNR(x[3], x[5], 8);
	z[2] = XOR(x[8], z[2]);
	x[9] = ALIGNR(x[5], x[7], 8);
	z[1] = XOR(x[9], z[1]);
	x[0] = SHL128(x[7], 8);
	z[0] = XOR(x[0], r[0]);

	x[3] = SET64(0xFFFFFFFFFFFFFFFF, 0xF800000000000000);
	x[3] = AND(z[4], x[3]);
	z[4] = XOR(z[4], x[3]);

	x[1] = CLMUL(x[3], _p, 0x01);
	x[2] = CLMUL(x[3], _p, 0x00);

	z[0] = XOR(x[1], z[0]);
	x[2] = SHR128(x[2], 8);
	z[0] = XOR(x[2], z[0]);
	}

/*********************************************************************************************
 *	XMM SQUARING
 *
 *  This section provides general squaring in GF(2^m) and square&reduce functions for
 *  selected SECT/NIST curves.
 *
 *  XMM_GF2m_sqr_{Z}term:
 *		Squares elements of size <= Z*64 bit.
 *		Results are stored in z with size <= 2*64*Z bit.
 *
 *  XMM_GF2m_mod_sqr_sect{Z}:
 *		Squares elements a € GF(2^Z).
 *		Results are reduced to field elements of GF(2^Z) and stored in z.
 *
 *********************************************************************************************/

static inline void	XMM_GF2m_sqr_3term(__m128i z[3], const __m128i a[2])
	{
	__m128i x[2], sqrT, mask;

	sqrT = SET64(0x5554515045444140, 0x1514111005040100 );
	mask = SET64(0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F );

	x[0] = AND(a[0], mask);
	x[1] = SHR(a[0], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[0] = UNPACKLO8(x[0], x[1]);
	z[1] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[1], mask);
	x[1] = SHR(a[1], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[2] = UNPACKLO8(x[0], x[1]);
	}

static inline void	XMM_GF2m_sqr_4term(__m128i z[4], const __m128i a[2])
	{
	__m128i x[2], sqrT, mask;

	sqrT = SET64(0x5554515045444140, 0x1514111005040100 );
	mask = SET64(0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F );

	x[0] = AND(a[0], mask);
	x[1] = SHR(a[0], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[0] = UNPACKLO8(x[0], x[1]);
	z[1] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[1], mask);
	x[1] = SHR(a[1], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[2] = UNPACKLO8(x[0], x[1]);
	z[3] = UNPACKHI8(x[0], x[1]);
	}

static inline void	XMM_GF2m_sqr_5term(__m128i z[5], const __m128i a[3])
	{
	__m128i x[2], sqrT, mask;

	sqrT = SET64(0x5554515045444140, 0x1514111005040100 );
	mask = SET64(0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F );

	x[0] = AND(a[0], mask);
	x[1] = SHR(a[0], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[0] = UNPACKLO8(x[0], x[1]);
	z[1] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[1], mask);
	x[1] = SHR(a[1], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[2] = UNPACKLO8(x[0], x[1]);
	z[3] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[2], mask);
	x[1] = SHR(a[2], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[4] = UNPACKLO8(x[0], x[1]);
	}

static inline void	XMM_GF2m_sqr_7term(__m128i z[7], const __m128i a[4])
	{
	__m128i x[2], sqrT, mask;

	sqrT = SET64(0x5554515045444140, 0x1514111005040100 );
	mask = SET64(0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F );

	x[0] = AND(a[0], mask);
	x[1] = SHR(a[0], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[0] = UNPACKLO8(x[0], x[1]);
	z[1] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[1], mask);
	x[1] = SHR(a[1], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[2] = UNPACKLO8(x[0], x[1]);
	z[3] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[2], mask);
	x[1] = SHR(a[2], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[4] = UNPACKLO8(x[0], x[1]);
	z[5] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[3], mask);
	x[1] = SHR(a[3], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[6] = UNPACKLO8(x[0], x[1]);
	}

static inline void	XMM_GF2m_sqr_9term(__m128i z[9], const __m128i a[5])
	{
	__m128i x[2], sqrT, mask;

	sqrT = SET64(0x5554515045444140, 0x1514111005040100 );
	mask = SET64(0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F );

	x[0] = AND(a[0], mask);
	x[1] = SHR(a[0], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[0] = UNPACKLO8(x[0], x[1]);
	z[1] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[1], mask);
	x[1] = SHR(a[1], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[2] = UNPACKLO8(x[0], x[1]);
	z[3] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[2], mask);
	x[1] = SHR(a[2], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[4] = UNPACKLO8(x[0], x[1]);
	z[5] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[3], mask);
	x[1] = SHR(a[3], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[6] = UNPACKLO8(x[0], x[1]);
	z[7] = UNPACKHI8(x[0], x[1]);

	x[0] = AND(a[4], mask);
	x[1] = SHR(a[4], 4);
	x[1] = AND(x[1], mask);
	x[0] = SHUFFLE(sqrT, x[0] );
	x[1] = SHUFFLE(sqrT, x[1] );
	z[8] = UNPACKLO8(x[0], x[1]);
	}

static inline void XMM_GF2m_mod_sqr_nist163(__m128i z[2], const __m128i a[2])
    {
	/* Init */
    __m128i t[3];

    /* Square */
    XMM_GF2m_sqr_3term(t, a);

    /* Reduce */
#ifdef FAST_PCLMUL
    XMM_GF2m_mod_nist163_clmul(z, t);
#else
    XMM_GF2m_mod_nist163(z, t);
#endif
    }

static inline void XMM_GF2m_mod_sqr_sect193(__m128i z[2], const __m128i a[2])
    {
	/* Init */
    __m128i t[4];

    /* Square */
    XMM_GF2m_sqr_4term(t, a);

    /* Reduce */
    XMM_GF2m_mod_sect193(z, t);
    }

static inline void XMM_GF2m_mod_sqr_nist233(__m128i z[2], const __m128i a[2])
    {
	/* Init */
    __m128i t[4];

    /* Square */
    XMM_GF2m_sqr_4term(t, a);

    /* Reduce */
    XMM_GF2m_mod_nist233(z, t);
    }

static inline void XMM_GF2m_mod_sqr_sect239(__m128i z[2], const __m128i a[2])
    {
	/* Init */
    __m128i t[4];

    /* Square */
    XMM_GF2m_sqr_4term(t, a);

    /* Reduce */
    XMM_GF2m_mod_sect239(z, t);

    }

static inline void XMM_GF2m_mod_sqr_nist283(__m128i z[3], const __m128i a[3])
    {
	/* Init */
    __m128i t[5];

    /* Square */
    XMM_GF2m_sqr_5term(t, a);

    /* Reduce */
#ifdef FAST_PCLMUL
    XMM_GF2m_mod_nist283_clmul(z, t);
#else
    XMM_GF2m_mod_nist283(z, t);
#endif
    }

static inline void XMM_GF2m_mod_sqr_nist409(__m128i z[4], const __m128i a[4])
    {
	/* Init */
	__m128i t[7];

    /* Square */
    XMM_GF2m_sqr_7term(t, a);

    /* Reduce */
    XMM_GF2m_mod_nist409(z, t);
    }

static inline void XMM_GF2m_mod_sqr_nist571(__m128i z[5], const __m128i a[5])
    {
	/* Init */
	__m128i t[9];

    /* Square */
    XMM_GF2m_sqr_9term(t, a);

    /* Reduce */
#ifdef FAST_PCLMUL
    XMM_GF2m_mod_nist571_clmul(z, t);
#else
    XMM_GF2m_mod_nist571(z, t);
#endif
    }

/*********************************************************************************************
 *	XMM MULTIPLICATION
 *
 *  This section adds fast multiplication for two elements in GF(2^m) and multiply&reduce
 *  functions for selected SECT/NIST curves. The multiplication is accelerated with the
 *  CLMUL instruction and various KARATSUBA-OFMAN multiplication techniques.
 *
 *  XMM_GF2m_{Z}x{Z}_mul:
 *		Multiplies elements a,b with size <= Z*64 bit.
 *		Results are stored in z with size <= 2*64*Z bit.
 *
 *  XMM_GF2m_mod_mul_sect{Z}:
 *		Multiplies elements a,b € GF(2^Z).
 * 		Results are reduced to field elements of GF(2^Z) and stored in z.
 *
 *********************************************************************************************/

/* Simple 2-term Karatsuba multiplication. */
static inline void XMM_GF2m_2x2_mul(__m128i z[2], const __m128i a, const __m128i b)
    {
	__m128i x[4];

	/* Prepare temporary operands */
	x[0] = SHR128(a, 8);
    x[1] = XOR(a, x[0]);
    x[2] = SHR128(b, 8);
    x[3] = XOR(b, x[2]);

    /* Do multiplications */
    z[0] = CLMUL(a, b, 0x00);
    z[1] = CLMUL(a, b, 0x11);
    x[0] = CLMUL(x[1], x[3], 0x00);

    x[1] = XOR(z[0], z[1]);
    x[0] = XOR(x[0], x[1]);

    x[1] = SHL128(x[0], 8);
    x[2] = SHR128(x[0], 8);

    z[0] = XOR(z[0], x[1]);
    z[1] = XOR(z[1], x[2]);
    }

/* Simple 3-term Karatsuba multiplication. */
static inline void XMM_GF2m_3x3_mul(__m128i z[3], const __m128i a[2], const __m128i b[2])
    {
	__m128i m[3], t[4];

	/* Prepare temporary operands */
	t[0] = ALIGNR(a[1], a[0], 8);
    t[1] = XOR(a[0], t[0]);
    t[2] = ALIGNR(b[1], b[0], 8);
    t[3] = XOR(b[0], t[2]);
    t[0] = XOR(a[0], a[1]);
    t[2] = XOR(b[0], b[1]);

    /* Do multiplications */
    z[0] = CLMUL(a[0], b[0], 0x00);
    z[1] = CLMUL(a[0], b[0], 0x11);
    z[2] = CLMUL(a[1], b[1], 0x00);
    m[0] = CLMUL(t[1], t[3], 0x00);
    m[1] = CLMUL(t[2], t[0], 0x00);
    m[2] = CLMUL(t[1], t[3], 0x11);

    m[0] = XOR(m[0], z[0]);
    m[0] = XOR(m[0], z[1]);
    m[1] = XOR(m[1], z[0]);
    m[1] = XOR(m[1], z[2]);
    m[2] = XOR(m[2], z[1]);
    m[2] = XOR(m[2], z[2]);

    t[0] = SHL128(m[0], 8);
    z[0] = XOR(z[0], t[0]);
    t[1] = ALIGNR(m[2], m[0], 8);
    z[1] = XOR(z[1], t[1]);
    z[1] = XOR(z[1], m[1]);
    t[3] = SHR128(m[2], 8);
    z[2] = XOR(z[2], t[3]);

    }

/* Recursive 4-term Karatsuba multiplication. */
static inline void XMM_GF2m_4x4_mul(__m128i z[4], const __m128i a[2], const __m128i b[2])
    {
	__m128i t[4];

    /* Do multiplication */
    XMM_GF2m_2x2_mul(z, a[0], b[0]);
    XMM_GF2m_2x2_mul(z + 2, a[1], b[1]);

    t[2] = XOR(a[0], a[1]);
    t[3] = XOR(b[0], b[1]);
    XMM_GF2m_2x2_mul(t, t[2], t[3]);

    t[0] = XOR(t[0], z[0]);
    t[0] = XOR(t[0], z[2]);
    t[1] = XOR(t[1], z[1]);
    t[1] = XOR(t[1], z[3]);
    z[1] = XOR(z[1], t[0]);
    z[2] = XOR(z[2], t[1]);

    }

/* Advanced 5-term Karatsuba multiplication as suggested in "Five, Six, and Seven-Term
 * Karatsuba-Like Formulae" by Peter L. Montgomery, requiring 13 multiplications.
 */
static inline void XMM_GF2m_5x5_mul(__m128i z[5], const __m128i a[3], const __m128i b[3])
    {
	__m128i m[13], t[13];

    /* Prepare temporary operands */
    t[0] = UNPACKLO64(a[0], b[0]);
    t[1] = UNPACKHI64(a[0], b[0]);
    t[2] = UNPACKLO64(a[1], b[1]);
    t[3] = UNPACKHI64(a[1], b[1]);
    t[4] = UNPACKLO64(a[2], b[2]);

    t[5] = XOR(t[0], t[1]);
    t[6] = XOR(t[0], t[2]);
    t[7] = XOR(t[2], t[4]);
    t[8] = XOR(t[3], t[4]);
    t[9] = XOR(t[3], t[6]);
    t[10] = XOR(t[1], t[7]);
    t[11] = XOR(t[5], t[8]);
    t[12] = XOR(t[2], t[11]);

    /* Do multiplications */
    m[0]  = CLMUL(t[0], t[0], 0x01);
    m[1]  = CLMUL(t[1], t[1], 0x01);
    m[2]  = CLMUL(t[2], t[2], 0x01);
    m[3]  = CLMUL(t[3], t[3], 0x01);
    m[4]  = CLMUL(t[4], t[4], 0x01);
    m[5]  = CLMUL(t[5], t[5], 0x01);
    m[6]  = CLMUL(t[6], t[6], 0x01);
    m[7]  = CLMUL(t[7], t[7], 0x01);
    m[8]  = CLMUL(t[8], t[8], 0x01);
    m[9]  = CLMUL(t[9], t[9], 0x01);
    m[10] = CLMUL(t[10], t[10], 0x01);
    m[11] = CLMUL(t[11], t[11], 0x01);
    m[12] = CLMUL(t[12], t[12], 0x01);

	/* Combine results */
    t[0] = m[0];
    t[8] = m[4];
    t[1] = XOR(t[0], m[1]);
    t[2] = XOR(t[1], m[6]);
    t[1] = XOR(t[1], m[5]);
    t[2] = XOR(t[2], m[2]);
    t[7] = XOR(t[8], m[3]);
    t[6] = XOR(t[7], m[7]);
    t[7] = XOR(t[7], m[8]);
    t[6] = XOR(t[6], m[2]);
    t[5] = XOR(m[11], m[12]);

    t[3] = XOR(t[5], m[9]);
    t[3] = XOR(t[3], t[0]);
    t[3] = XOR(t[3], t[6]);

    t[4] = XOR(t[1], t[7]);
    t[4] = XOR(t[4], m[9]);
    t[4] = XOR(t[4], m[10]);
    t[4] = XOR(t[4], m[12]);

    t[5] = XOR(t[5], t[2]);
    t[5] = XOR(t[5], t[8]);
    t[5] = XOR(t[5], m[10]);

    t[9] = SHR128(t[7], 8);
    t[7] = ALIGNR(t[7], t[5], 8);
    t[5] = ALIGNR(t[5], t[3], 8);
    t[3] = ALIGNR(t[3], t[1], 8);
    t[1] = SHL128(t[1], 8);

    z[0] = XOR(t[0], t[1]);
    z[1] = XOR(t[2], t[3]);
    z[2] = XOR(t[4], t[5]);
    z[3] = XOR(t[6], t[7]);
    z[4] = XOR(t[8], t[9]);

    }

/* 7-term Karatsuba multiplication with 4-4-3 strategy. */
static inline void XMM_GF2m_7x7_mul(__m128i z[7], const __m128i a[4], const __m128i b[4])
    {
	__m128i t[4], e[4];

    /* Multiply lower part */
    XMM_GF2m_4x4_mul(z, a, b);

    /* Multiply upper part */
    XMM_GF2m_3x3_mul(z + 4, a + 2, b + 2);

    t[0] = XOR(a[0], a[2]);
    t[1] = XOR(a[1], a[3]);
    t[2] = XOR(b[0], b[2]);
    t[3] = XOR(b[1], b[3]);

    /* Multiply middle part */
    XMM_GF2m_4x4_mul(e, t + 2, t);

    /* Combine results */
    t[0] = XOR(e[0], z[4]);
    t[1] = XOR(e[1], z[5]);
    t[2] = XOR(e[2], z[6]);
    t[3] = XOR(e[3], z[3]);

    e[0] = XOR(t[0], z[0]);
    e[1] = XOR(t[1], z[1]);
    e[2] = XOR(t[2], z[2]);

    z[2] = XOR(z[2], e[0]);
    z[3] = XOR(z[3], e[1]);
    z[4] = XOR(z[4], e[2]);
    z[5] = XOR(z[5], t[3]);

    }

/* 9-term Karatsuba multiplication with 5-5-4 strategy. */
static inline void XMM_GF2m_9x9_mul(__m128i z[9], const __m128i a[5], const __m128i b[5])
    {
	__m128i t[5], e[4], f[5], at[5], bt[5];

    /* Multiply lower part */
    XMM_GF2m_5x5_mul(z, a, b);

    /* Make local copy of a,b to not destroy them */
    at[4] = ALIGNR(a[4], a[3], 8);
    at[3] = ALIGNR(a[3], a[2], 8);
    at[2] = MOVE64(a[2]);
    XMM_GF2m_copy_2term(at, a);

    bt[4] = ALIGNR(b[4], b[3], 8);
    bt[3] = ALIGNR(b[3], b[2], 8);
    bt[2] = MOVE64(b[2]);
    XMM_GF2m_copy_2term(bt, b);

    /* Prepare operands */
    t[0] = XOR(at[0], at[3]);			// t0 = [ (a6+a1);(a5+a0) ]
    t[1] = XOR(at[1], at[4]);			// t1 = [ (a8+a3);(a7+a2) ]
    t[2] = at[2];						// t2 = [ 0;a4 ]

    e[0] = XOR(bt[0], bt[3]);			// e0 = [ (b6+b1);(b5+b0) ]
    e[1] = XOR(bt[1], bt[4]);			// e1 = [ (b8+b3);(b7+b2) ]
    e[2] = bt[2];						// e2 = [ 0;b4 ]

    /* Multiply middle part */
    XMM_GF2m_5x5_mul(f, t, e);

    t[0] = XOR(f[0], z[0]);
    t[1] = XOR(f[1], z[1]);
    t[2] = XOR(f[2], z[2]);
    t[3] = XOR(f[3], z[3]);
    t[4] = XOR(f[4], z[4]);

    /* Multiply upper part */
    XMM_GF2m_4x4_mul(z + 5, at + 3, bt + 3);

    /* Combine results */
    e[0] = XOR(t[0], z[5]);
    e[1] = XOR(t[1], z[6]);
    e[2] = XOR(t[2], z[7]);
    e[3] = XOR(t[3], z[8]);

    f[0] = SHL128(e[0], 8);
    z[2] = XOR(z[2], f[0]);
    f[1] = ALIGNR(e[1], e[0], 8);
    z[3] = XOR(z[3], f[1]);
    f[2] = ALIGNR(e[2], e[1], 8);
    z[4] = XOR(z[4], f[2]);
    f[3] = ALIGNR(e[3], e[2], 8);
    z[5] = XOR(z[5], f[3]);
    f[4] = ALIGNR(t[4], e[3], 8);
    z[6] = XOR(z[6], f[4]);
    f[0] = SHR128(t[4], 8);
    z[7] = XOR(z[7], f[0]);

    }

static inline void XMM_GF2m_mod_mul_nist163(__m128i z[2], const __m128i a[2], const __m128i b[2])
    {
	/* Init */
	__m128i t[3];

    /* Do multiplication */
    XMM_GF2m_3x3_mul(t, a, b);

    /* Reduce */
#ifdef FAST_PCLMUL
    XMM_GF2m_mod_nist163_clmul(z, t);
#else
    XMM_GF2m_mod_nist163(z, t);
#endif
    }

static inline void XMM_GF2m_mod_mul_sect193(__m128i z[2], const __m128i a[2], const __m128i b[2])
    {
	/* Init */
	__m128i t[4];

    /* Do multiplication */
    XMM_GF2m_4x4_mul(t, a, b);

    /* Reduce */
    XMM_GF2m_mod_sect193(z, t);

    }

static inline void XMM_GF2m_mod_mul_nist233(__m128i z[2], const __m128i a[2], const __m128i b[2])
    {
	/* Init */
	__m128i t[4];

    /* Do multiplication */
    XMM_GF2m_4x4_mul(t, a, b);

    /* Reduce */
    XMM_GF2m_mod_nist233(z, t);

    }

static inline void XMM_GF2m_mod_mul_sect239(__m128i z[2], const __m128i a[2], const __m128i b[2])
    {
	/* Init */
	__m128i t[4];

    /* Do multiplication */
    XMM_GF2m_4x4_mul(t, a, b);

    /* Reduce */
    XMM_GF2m_mod_sect239(z, t);

    }

static inline void XMM_GF2m_mod_mul_nist283(__m128i z[3], const __m128i a[3], const __m128i b[3])
    {
	/* Init */
	__m128i t[5];

    /* Do multiplication */
    XMM_GF2m_5x5_mul(t, a, b);

    /* Reduce */
#ifdef FAST_PCLMUL
    XMM_GF2m_mod_nist283_clmul(z, t);
#else
    XMM_GF2m_mod_nist283(z, t);
#endif
    }

static inline void XMM_GF2m_mod_mul_nist409(__m128i z[4], const __m128i a[4], const __m128i b[4])
    {
	/* Init */
	__m128i t[7];

    /* Do multiplication */
    XMM_GF2m_7x7_mul(t, a, b);

    /* Reduce */
    XMM_GF2m_mod_nist409(z, t);

    }

static inline void XMM_GF2m_mod_mul_nist571(__m128i z[5], const __m128i a[5], const __m128i b[5])
    {
	/* Init */
	__m128i t[9];

    /* Do multiplication */
    XMM_GF2m_9x9_mul(t, a, b);

    /* Reduce */
#ifdef FAST_PCLMUL
    XMM_GF2m_mod_nist571_clmul(z, t);
#else
    XMM_GF2m_mod_nist571(z, t);
#endif
    }


/*********************************************************************************************
 *	XMM INVERSION & DIVISION
 *
 *  This section provides inversion and division functions in GF(2^m) for selected
 *  SECT/NIST curves using the ITOH-TSUJI algorithm. The exponent decompositions
 *  are given in the function descriptions.
 *
 *********************************************************************************************/

/*
 * Calculates z = a⁻¹ for any a € GF(2^163) with exponent decomposition:
 * (1 + 2)*(1 + 2^2((1 + 2^2)*(1 + 2^4)*(1 + 2^8)*(1 + 2^16)*(1 + 2^32*((1 + 2^32)*(1 + 2^64) )))
 */
static inline void XMM_GF2m_mod_inv_nist163(__m128i z[2], __m128i a[2])
	{
	/* Init */
	int i;
	__m128i t0[2], t1[2], t2[2];

	/* Exponent chain */
	const int chain[] = { /*1, 2,*/ 4, 8, 16, 32, 64, 32, 2 };

	/* Initial Square z = a² */
	XMM_GF2m_mod_sqr_nist163(z, a);

	/* Square t0 = z^2^1 */
	XMM_GF2m_mod_sqr_nist163(t0, z);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist163(z, z, t0);

	/* Save component t1 = z  */
	XMM_GF2m_copy_2term(t1, z);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_nist163(t0, z);
	XMM_GF2m_mod_sqr_nist163(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist163(z, z, t0);

	/* Square t0 = z^2^4 */
	XMM_GF2m_mod_sqr_nist163(t0, z);
	for(i=0; i < chain[0]-1; i++) XMM_GF2m_mod_sqr_nist163(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist163(z, z, t0);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_nist163(t0, z);
	for(i=0; i < chain[1]-1; i++) XMM_GF2m_mod_sqr_nist163(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist163(z, z, t0);

	/* Square t0 = z^2^16 */
	XMM_GF2m_mod_sqr_nist163(t0, z);
	for(i=0; i < chain[2]-1; i++) XMM_GF2m_mod_sqr_nist163(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist163(z, z, t0);

	/* Save component t2 = z */
	XMM_GF2m_copy_2term(t2, z);

	/* Square t0 = z^2^32 */
	XMM_GF2m_mod_sqr_nist163(t0, z);
	for(i=0; i < chain[3]-1; i++) XMM_GF2m_mod_sqr_nist163(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist163(z, z, t0);

	/* Square t0 = z^2^64 */
	XMM_GF2m_mod_sqr_nist163(t0, z);
	for(i=0; i < chain[4]-1; i++) XMM_GF2m_mod_sqr_nist163(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist163(z, z, t0);

	/* Square t0 = z^2^32 */
	XMM_GF2m_mod_sqr_nist163(t0, z);
	for(i=0; i < chain[5]-1; i++) XMM_GF2m_mod_sqr_nist163(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist163(z, t2, t0);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_nist163(t0, z);
	XMM_GF2m_mod_sqr_nist163(t0, t0);

	/*  Multiply component z = t1*t0 */
	XMM_GF2m_mod_mul_nist163(z, t1, t0);
	}

/*
 * Calculates z = a⁻¹ for any a € GF(2^193) with exponent decomposition:
 * (1 + 2)*(1 + 2^2)*(1 + 2^4)*(1 + 2^8)*(1 + 2^16)*(1 + 2^32)*(1 + 2^64*(1 + 2^64))
 */
static inline void XMM_GF2m_mod_inv_sect193(__m128i z[2], __m128i a[2])
	{
	/* Init */
	int i;
	__m128i t0[2], t1[2];

	/* Exponent chain */
	const int chain[] = { /*1, 2,*/ 4, 8, 16, 32, 64, 64 };

	/* Initial Square z = a² */
	XMM_GF2m_mod_sqr_sect193(z, a);

	/* Square t0 = z^2^1 */
	XMM_GF2m_mod_sqr_sect193(t0, z);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect193(z, z, t0);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_sect193(t0, z);
	XMM_GF2m_mod_sqr_sect193(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect193(z, z, t0);

	/* Square t0 = z^2^4 */
	XMM_GF2m_mod_sqr_sect193(t0, z);
	for(i=0; i < chain[0]-1; i++) XMM_GF2m_mod_sqr_sect193(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect193(z, z, t0);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_sect193(t0, z);
	for(i=0; i < chain[1]-1; i++) XMM_GF2m_mod_sqr_sect193(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect193(z, z, t0);

	/* Square t0 = z^2^16 */
	XMM_GF2m_mod_sqr_sect193(t0, z);
	for(i=0; i < chain[2]-1; i++) XMM_GF2m_mod_sqr_sect193(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect193(z, z, t0);

	/* Square t0 = z^2^32 */
	XMM_GF2m_mod_sqr_sect193(t0, z);
	for(i=0; i < chain[3]-1; i++) XMM_GF2m_mod_sqr_sect193(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect193(z, z, t0);

	/* Save component t1 = z */
	XMM_GF2m_copy_2term(t1, z);

	/* Square t0 = z^2^64 */
	XMM_GF2m_mod_sqr_sect193(t0, z);
	for(i=0; i < chain[4]-1; i++) XMM_GF2m_mod_sqr_sect193(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect193(z, z, t0);

	/* Square t0 = z^2^64 */
	XMM_GF2m_mod_sqr_sect193(t0, z);
	for(i=0; i < chain[5]-1; i++) XMM_GF2m_mod_sqr_sect193(t0, t0);

	/*  Multiply component z = t1*t0 */
	XMM_GF2m_mod_mul_sect193(z, t1, t0);
	}

/*
 * Calculates z = a⁻¹ for any a € GF(2^233) with exponent decomposition:
 * (1 + 2)(1 + 2^2)(1 + 2^4)(1 + 2^8 (1 + 2^8)(1 + 2^16)(1 + 2^32 (1 + 2^32)(1 + 2^64 (1 + 2^64))))
 */
static inline void XMM_GF2m_mod_inv_nist233(__m128i z[2], __m128i a[2])
	{
	/* Init */
	int i;
	__m128i t0[2], t1[2], t2[2], t3[2];

	/* Exponent chain */
	const int chain[] = { /*1, 2,*/ 4, 8, 16, 32, 64, 64, 32, 8 };

	/* Initial Square z = a² */
	XMM_GF2m_mod_sqr_nist233(z, a);

	/* Square t0 = z^2^1 */
	XMM_GF2m_mod_sqr_nist233(t0, z);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist233(z, z, t0);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_nist233(t0, z);
	XMM_GF2m_mod_sqr_nist233(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist233(z, z, t0);

	/* Square t0 = z^2^4 */
	XMM_GF2m_mod_sqr_nist233(t0, z);
	for(i=0; i < chain[0]-1; i++) XMM_GF2m_mod_sqr_nist233(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist233(z, z, t0);

	/* Save component t1 = z */
	XMM_GF2m_copy_2term(t1, z);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_nist233(t0, z);
	for(i=0; i < chain[1]-1; i++) XMM_GF2m_mod_sqr_nist233(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist233(z, z, t0);

	/* Square t0 = z^2^16 */
	XMM_GF2m_mod_sqr_nist233(t0, z);
	for(i=0; i < chain[2]-1; i++) XMM_GF2m_mod_sqr_nist233(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist233(z, z, t0);

	/* Save component t2 = z */
	XMM_GF2m_copy_2term(t2, z);

	/* Square t0 = z^2^32 */
	XMM_GF2m_mod_sqr_nist233(t0, z);
	for(i=0; i < chain[3]-1; i++) XMM_GF2m_mod_sqr_nist233(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist233(z, z, t0);

	/* Save component t3 = z */
	XMM_GF2m_copy_2term(t3, z);

	/* Square t0 = z^2^64 */
	XMM_GF2m_mod_sqr_nist233(t0, z);
	for(i=0; i < chain[4]-1; i++) XMM_GF2m_mod_sqr_nist233(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist233(z, z, t0);

	/* Square t0 = z^2^64 */
	XMM_GF2m_mod_sqr_nist233(t0, z);
	for(i=0; i < chain[5]-1; i++) XMM_GF2m_mod_sqr_nist233(t0, t0);

	/*  Multiply component z = t3*t0 */
	XMM_GF2m_mod_mul_nist233(z, t3, t0);

	/* Square t0 = z^2^32 */
	XMM_GF2m_mod_sqr_nist233(t0, z);
	for(i=0; i < chain[6]-1; i++) XMM_GF2m_mod_sqr_nist233(t0, t0);

	/*  Multiply component z = t2*t0 */
	XMM_GF2m_mod_mul_nist233(z, t2, t0);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_nist233(t0, z);
	for(i=0; i < chain[7]-1; i++) XMM_GF2m_mod_sqr_nist233(t0, t0);

	/*  Multiply component z = t1*t0 */
	XMM_GF2m_mod_mul_nist233(z, t1, t0);
	}

/*
 * Calculates z = a⁻¹ for any a € GF(2^239) with exponent decomposition:
 * (1 + 2)(1 + 2^2 (1 + 2^2)(1 + 2^4 (1 + 2^4)(1 + 2^8 (1 + 2^8)(1 + 2^16)(1 + 2^32 (1 + 2^32)(1 + 2^64 (1 + 2^64))))))
 */
static inline void XMM_GF2m_mod_inv_sect239(__m128i z[2], __m128i a[2])
	{
	/* Init */
	int i;
	__m128i t0[2], t1[2], t2[2], t3[2], t4[2], t5[2];

	/* Exponent chain */
	const int chain[] = { /*1, 2,*/ 4, 8, 16, 32, 64, 64, 32, 8, 4 /*, 2*/ };

	/* Initial Square z = a² */
	XMM_GF2m_mod_sqr_sect239(z, a);

	/* Square t0 = z^2^1 */
	XMM_GF2m_mod_sqr_sect239(t0, z);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect239(z, z, t0);

	/* Save component t1 = z */
	XMM_GF2m_copy_2term(t1, z);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_sect239(t0, z);
	XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect239(z, z, t0);

	/* Save component t2 = z */
	XMM_GF2m_copy_2term(t2, z);

	/* Square t0 = z^2^4 */
	XMM_GF2m_mod_sqr_sect239(t0, z);
	for(i=0; i < chain[0]-1; i++) XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect239(z, z, t0);

	/* Save component t3 = z */
	XMM_GF2m_copy_2term(t3, z);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_sect239(t0, z);
	for(i=0; i < chain[1]-1; i++) XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect239(z, z, t0);

	/* Square t0 = z^2^16 */
	XMM_GF2m_mod_sqr_sect239(t0, z);
	for(i=0; i < chain[2]-1; i++) XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect239(z, z, t0);

	/* Save component t4 = z */
	XMM_GF2m_copy_2term(t4, z);

	/* Square t0 = z^2^32*/
	XMM_GF2m_mod_sqr_sect239(t0, z);
	for(i=0; i < chain[3]-1; i++) XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect239(z, z, t0);

	/* Save component t5 = z */
	XMM_GF2m_copy_2term(t5, z);

	/* Square t0 = z^2^64 */
	XMM_GF2m_mod_sqr_sect239(t0, z);
	for(i=0; i < chain[4]-1; i++) XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_sect239(z, z, t0);

	/* Square t0 = z^2^32 */
	XMM_GF2m_mod_sqr_sect239(t0, z);
	for(i=0; i < chain[5]-1; i++) XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = t5*t0 */
	XMM_GF2m_mod_mul_sect239(z, t5, t0);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_sect239(t0, z);
	for(i=0; i < chain[6]-1; i++) XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = t4*t0 */
	XMM_GF2m_mod_mul_sect239(z, t4, t0);

	/* Square t0 = z^2^4 */
	XMM_GF2m_mod_sqr_sect239(t0, z);
	for(i=0; i < chain[7]-1; i++) XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = t3*t0 */
	XMM_GF2m_mod_mul_sect239(z, t3, t0);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_sect239(t0, z);
	for(i=0; i < chain[8]-1; i++) XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = t2*t0 */
	XMM_GF2m_mod_mul_sect239(z, t2, t0);

	XMM_GF2m_mod_sqr_sect239(t0, z);
	XMM_GF2m_mod_sqr_sect239(t0, t0);

	/*  Multiply component z = t1*t0 */
	XMM_GF2m_mod_mul_sect239(z, t1, t0);
	}


/*
 * Calculates z = a⁻¹ for any a € GF(2^283) with exponent decomposition:
 * (1 + 2)(1 + 2^2 (1 + 2^2 )(1 + 2^4 )(1 + 2^8 (1 + 2^8 )(1 + 2^16 (1 + 2^16 )(1 + 2^32 )(1 + 2^64 )(1 + 2^128 ))))
 */
static inline void XMM_GF2m_mod_inv_nist283(__m128i z[3], __m128i a[3])
	{
	/* Init */
	int i;
	__m128i t0[3], t1[3], t2[3], t3[3];

	/* Exponent chain */
	const int chain[] = { /*1, 2,*/ 4, 8, 16, 32, 64, 128, 16, 8 /*, 2*/ };

	/* Initial Square z = a² */
	XMM_GF2m_mod_sqr_nist283(z, a);

	/* Square t0 = z^2^1 */
	XMM_GF2m_mod_sqr_nist283(t0, z);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist283(z, z, t0);

	/* Save component t1 = z */
	XMM_GF2m_copy_3term(t1, z);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_nist283(t0, z);
	XMM_GF2m_mod_sqr_nist283(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist283(z, z, t0);

	/* Square t0 = z^2^4 */
	XMM_GF2m_mod_sqr_nist283(t0, z);
	for(i=0; i < chain[0]-1; i++) XMM_GF2m_mod_sqr_nist283(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist283(z, z, t0);

	/* Save component t2 = z */
	XMM_GF2m_copy_3term(t2, z);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_nist283(t0, z);
	for(i=0; i < chain[1]-1; i++) XMM_GF2m_mod_sqr_nist283(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist283(z, z, t0);

	/* Save component t3 = z */
	XMM_GF2m_copy_3term(t3, z);

	/* Square t0 = z^2^16 */
	XMM_GF2m_mod_sqr_nist283(t0, z);
	for(i=0; i < chain[2]-1; i++) XMM_GF2m_mod_sqr_nist283(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist283(z, z, t0);

	/* Square t0 = z^2^32 */
	XMM_GF2m_mod_sqr_nist283(t0, z);
	for(i=0; i < chain[3]-1; i++) XMM_GF2m_mod_sqr_nist283(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist283(z, z, t0);

	/* Square t0 = z^2^64 */
	XMM_GF2m_mod_sqr_nist283(t0, z);
	for(i=0; i < chain[4]-1; i++) XMM_GF2m_mod_sqr_nist283(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist283(z, z, t0);

	/* Square t0 = z^2^128 */
	XMM_GF2m_mod_sqr_nist283(t0, z);
	for(i=0; i < chain[5]-1; i++) XMM_GF2m_mod_sqr_nist283(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist283(z, z, t0);

	/* Square t0 = z^2^16 */
	XMM_GF2m_mod_sqr_nist283(t0, z);
	for(i=0; i < chain[6]-1; i++) XMM_GF2m_mod_sqr_nist283(t0, t0);

	/*  Multiply component z = t3*t0 */
	XMM_GF2m_mod_mul_nist283(z, t3, t0);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_nist283(t0, z);
	for(i=0; i < chain[7]-1; i++) XMM_GF2m_mod_sqr_nist283(t0, t0);

	/*  Multiply component z = t2*t0 */
	XMM_GF2m_mod_mul_nist283(z, t2, t0);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_nist283(t0, z);
	XMM_GF2m_mod_sqr_nist283(t0, t0);

	/*  Multiply component z = t1*t0 */
	XMM_GF2m_mod_mul_nist283(z, t1, t0);
	}

/*
 * Calculates z = a⁻¹ for any a € GF(2^409) with exponent decomposition:
 * (1 + 2)(1 + 2^2 )(1 + 2^4 )(1 + 2^8 (1 + 2^8 )(1 + 2^16 (1 + 2^16 )(1 + 2^32 )(1 + 2^64 )(1 + 2^128 (1 + 2^128 ))))
 */
static inline void XMM_GF2m_mod_inv_nist409(__m128i z[4], __m128i a[4])
	{
	/* Init */
	int i;
	__m128i t0[4], t1[4], t2[4], t3[4];

	/* Exponent chain */
	const int chain[] = { /*1, 2,*/ 4, 8, 16, 32, 64, 128, 128, 16, 8 };

	/* Initial Square z = a² */
	XMM_GF2m_mod_sqr_nist409(z, a);

	/* Square t0 = z^2^1 */
	XMM_GF2m_mod_sqr_nist409(t0, z);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist409(z, z, t0);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_nist409(t0, z);
	XMM_GF2m_mod_sqr_nist409(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist409(z, z, t0);

	/* Square t0 = z^2^4 */
	XMM_GF2m_mod_sqr_nist409(t0, z);
	for(i=0; i < chain[0]-1; i++) XMM_GF2m_mod_sqr_nist409(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist409(z, z, t0);

	/* Save component t1 = z */
	XMM_GF2m_copy_4term(t1, z);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_nist409(t0, z);
	for(i=0; i < chain[1]-1; i++) XMM_GF2m_mod_sqr_nist409(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist409(z, z, t0);

	/* Save component t2 = z */
	XMM_GF2m_copy_4term(t2, z);

	/* Square t0 = z^2^16 */
	XMM_GF2m_mod_sqr_nist409(t0, z);
	for(i=0; i < chain[2]-1; i++) XMM_GF2m_mod_sqr_nist409(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist409(z, z, t0);

	/* Square t0 = z^2^32 */
	XMM_GF2m_mod_sqr_nist409(t0, z);
	for(i=0; i < chain[3]-1; i++) XMM_GF2m_mod_sqr_nist409(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist409(z, z, t0);

	/* Square t0 = z^2^64 */
	XMM_GF2m_mod_sqr_nist409(t0, z);
	for(i=0; i < chain[4]-1; i++) XMM_GF2m_mod_sqr_nist409(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist409(z, z, t0);

	/* Save component t1 = z */
	XMM_GF2m_copy_4term(t3, z);

	/* Square t0 = z^2^128 */
	XMM_GF2m_mod_sqr_nist409(t0, z);
	for(i=0; i < chain[5]-1; i++) XMM_GF2m_mod_sqr_nist409(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist409(z, z, t0);

	/* Square t0 = z^2^128 */
	XMM_GF2m_mod_sqr_nist409(t0, z);
	for(i=0; i < chain[6]-1; i++) XMM_GF2m_mod_sqr_nist409(t0, t0);

	/*  Multiply component z = t3*t0 */
	XMM_GF2m_mod_mul_nist409(z, t3, t0);

	/* Square t0 = z^2^16 */
	XMM_GF2m_mod_sqr_nist409(t0, z);
	for(i=0; i < chain[7]-1; i++) XMM_GF2m_mod_sqr_nist409(t0, t0);

	/*  Multiply component z = t2*t0 */
	XMM_GF2m_mod_mul_nist409(z, t2, t0);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_nist409(t0, z);
	for(i=0; i < chain[8]-1; i++) XMM_GF2m_mod_sqr_nist409(t0, t0);

	/*  Multiply component z = t1*t0 */
	XMM_GF2m_mod_mul_nist409(z, t1, t0);
	}

/*
 * Calculates z = a⁻¹ for any a € GF(2^571) with exponent decomposition:
 * (1 + 2)(1 + 2^2 (1 + 2^2)(1 + 2^4)(1 + 2^8 (1 + 2^8)(1 + 2^16 (1 + 2^16)(1 + 2^32 (1 + 2^32)(1 + 2^64)(1 + 2^128)(1 + 2^256)))))
 */
static inline void XMM_GF2m_mod_inv_nist571(__m128i z[5], __m128i a[5])
	{
	/* Init */
	int i;
	__m128i t0[5], t1[5], t2[5], t3[5], t4[5];

	/* Exponent chain */
	const int chain[] = { /*1, 2,*/ 4, 8, 16, 32, 64, 128, 256, 32, 16, 8 /*, 2*/ };

	/* Initial Square z = a² */
	XMM_GF2m_mod_sqr_nist571(z, a);

	/* Square t0 = z^2^1 */
	XMM_GF2m_mod_sqr_nist571(t0, z);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist571(z, z, t0);

	/* Save component t1 = z */
	XMM_GF2m_copy_5term(t1, z);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist571(z, z, t0);

	/* Square t0 = z^2^4 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	for(i=0; i < chain[0]-1; i++) XMM_GF2m_mod_sqr_nist571(t0, t0);
	
	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist571(z, z, t0);

	/* Save component t2 = z */
	XMM_GF2m_copy_5term(t2, z);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	for(i=0; i < chain[1]-1; i++) XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist571(z, z, t0);

	/* Save component t3 = z */
	XMM_GF2m_copy_5term(t3, z);

	/* Square t0 = z^2^16 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	for(i=0; i < chain[2]-1; i++) XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist571(z, z, t0);

	/* Save component t4 = z */
	XMM_GF2m_copy_5term(t4, z);

	/* Square t0 = z^2^32 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	for(i=0; i < chain[3]-1; i++) XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist571(z, z, t0);

	/* Square t0 = z^2^64 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	for(i=0; i < chain[4]-1; i++) XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist571(z, z, t0);

	/* Square t0 = z^2^128 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	for(i=0; i < chain[5]-1; i++) XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist571(z, z, t0);

	/* Square t0 = z^2^256 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	for(i=0; i < chain[6]-1; i++) XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = z*t0 */
	XMM_GF2m_mod_mul_nist571(z, z, t0);

	/* Square t0 = z^2^32 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	for(i=0; i < chain[7]-1; i++) XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = t4*t0 */
	XMM_GF2m_mod_mul_nist571(z, t4, t0);

	/* Square t0 = z^2^16 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	for(i=0; i < chain[8]-1; i++) XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = t3*t0 */
	XMM_GF2m_mod_mul_nist571(z, t3, t0);

	/* Square t0 = z^2^8 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	for(i=0; i < chain[9]-1; i++) XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = t2*t0 */
	XMM_GF2m_mod_mul_nist571(z, t2, t0);

	/* Square t0 = z^2^2 */
	XMM_GF2m_mod_sqr_nist571(t0, z);
	XMM_GF2m_mod_sqr_nist571(t0, t0);

	/*  Multiply component z = t1*t0 */
	XMM_GF2m_mod_mul_nist571(z, t1, t0);
	}

/* Calculates z = a/b = a * b⁻¹ for a,b,z € GF(2^163) */
static inline void XMM_GF2m_div_nist163(__m128i z[2], __m128i a[2], __m128i b[2])
    {
    /* Init */
    __m128i c[2];

    /* Invert b */
    XMM_GF2m_mod_inv_nist163(c, b);

    /* Multiply a * b⁻¹ */
    XMM_GF2m_mod_mul_nist163(z, a, c);
    }

/* Calculates z = a/b = a * b⁻¹ for a,b,z € GF(2^193) */
static inline void XMM_GF2m_div_sect193(__m128i z[2], __m128i a[2], __m128i b[2])
    {
    /* Init */
    __m128i c[2];

    /* Invert b */
    XMM_GF2m_mod_inv_sect193(c, b);

    /* Multiply a * b⁻¹ */
    XMM_GF2m_mod_mul_sect193(z, a, c);
    }

/* Calculates z = a/b = a * b⁻¹ for a,b,z € GF(2^233) */
static inline void XMM_GF2m_div_nist233(__m128i z[2], __m128i a[2], __m128i b[2])
    {
    /* Init */
    __m128i c[2];

    /* Invert b */
    XMM_GF2m_mod_inv_nist233(c, b);

    /* Multiply a * b⁻¹ */
    XMM_GF2m_mod_mul_nist233(z, a, c);
    }

/* Calculates z = a/b = a * b⁻¹ for a,b,z € GF(2^239) */
static inline void XMM_GF2m_div_sect239(__m128i z[2], __m128i a[2], __m128i b[2])
    {
    /* Init */
    __m128i c[2];

    /* Invert b */
    XMM_GF2m_mod_inv_sect239(c, b);

    /* Multiply a * b⁻¹ */
    XMM_GF2m_mod_mul_sect239(z, a, c);
    }

/* Calculates z = a/b = a * b⁻¹ for a,b,z € GF(2^283) */
static inline void XMM_GF2m_div_nist283(__m128i z[3], __m128i a[3], __m128i b[3])
    {
    /* Init */
    __m128i c[3];

    /* Invert b */
    XMM_GF2m_mod_inv_nist283(c, b);

    /* Multiply a * b⁻¹ */
    XMM_GF2m_mod_mul_nist283(z, a, c);
    }

/* Calculates z = a/b = a * b⁻¹ for a,b,z € GF(2^409) */
static inline void XMM_GF2m_div_nist409(__m128i z[4], __m128i a[4], __m128i b[4])
    {
    /* Init */
    __m128i c[4];

    /* Invert b */
    XMM_GF2m_mod_inv_nist409(c, b);

    /* Multiply a * b⁻¹ */
    XMM_GF2m_mod_mul_nist409(z, a, c);
    }

/* Calculates z = a/b = a * b⁻¹ for a,b,z € GF(2^571) */
static inline void XMM_GF2m_div_nist571(__m128i z[5], __m128i a[5], __m128i b[5])
    {
    /* Init */
    __m128i c[5];

    /* Invert b */
    XMM_GF2m_mod_inv_nist571(c, b);

    /* Multiply a * b⁻¹ */
    XMM_GF2m_mod_mul_nist571(z, a, c);
    }

/*********************************************************************************************
 *	BIGNUM WRAPPER FUNCTIONS
 *
 *  This section provides non-static wrapper functions for selected SECT/NIST curves
 *  for the use with the OpenSSL BN/EC library.
 *
 *  All BIGNUMs are expected to have the correct amount of words according to the
 *  field. This means that a field element in GF(2^m) [m prime] needs to have
 *  exactly (m/64)+1 words.
 *
 *********************************************************************************************/

/* Calculates z = a² for all a € GF(2^163) */
int BN_GF2m_sqr_xmm_nist163(BIGNUM *z, const BIGNUM *a)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2];

    /* Load */
    BN_to_XMM_3term(_a, a->d);

    /* Square */
    XMM_GF2m_mod_sqr_nist163(_t, _a);

    /* Store */
    XMM_to_BN_3term(z->d, _t);

    ret = 1;
    return ret;
    }

/* Calculates z = a² for all a € GF(2^193) */
int BN_GF2m_sqr_xmm_sect193(BIGNUM *z, const BIGNUM *a)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2];

    /* Load */
    BN_to_XMM_4term(_a, a->d);

    /* Square */
    XMM_GF2m_mod_sqr_sect193(_t, _a);

    /* Store */
    XMM_to_BN_4term(z->d, _t);

    ret = 1;
    return ret;
    }

/* Calculates z = a² for all a € GF(2^233) */
int BN_GF2m_sqr_xmm_nist233(BIGNUM *z, const BIGNUM *a)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2];

    /* Load */
    BN_to_XMM_4term(_a, a->d);

    /* Square */
    XMM_GF2m_mod_sqr_nist233(_t, _a);

    /* Store */
    XMM_to_BN_4term(z->d, _t);

    ret = 1;
    return ret;
    }

/* Calculates z = a² for all a € GF(2^239) */
int BN_GF2m_sqr_xmm_sect239(BIGNUM *z, const BIGNUM *a)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2];

    /* Load */
    BN_to_XMM_4term(_a, a->d);

    /* Square */
    XMM_GF2m_mod_sqr_sect239(_t, _a);

    /* Store */
    XMM_to_BN_4term(z->d, _t);

    ret = 1;
    return ret;
    }

/* Calculates z = a² for all a € GF(2^283) */
int BN_GF2m_sqr_xmm_nist283(BIGNUM *z, const BIGNUM *a)
    {
    /* Init */
    int ret = 0;
    __m128i _t[3], _a[3];

    /* Load */
    BN_to_XMM_5term(_a, a->d);

    /* Square */
    XMM_GF2m_mod_sqr_nist283(_t, _a);

    /* Store */
    XMM_to_BN_5term(z->d, _t);

    ret = 1;
	return ret;
    }

/* Calculates z = a² for all a € GF(2^409) */
int BN_GF2m_sqr_xmm_nist409(BIGNUM *z, const BIGNUM *a)
    {
    /* Init */
    int ret = 0;
    __m128i _t[4], _a[4];

    /* Load */
    BN_to_XMM_7term(_a, a->d);

    /* Square */
    XMM_GF2m_mod_sqr_nist409(_t, _a);

    /* Store */
    XMM_to_BN_7term(z->d, _t);

    ret = 1;
    return ret;
    }

/* Calculates z = a² for all a € GF(2^571) */
int BN_GF2m_sqr_xmm_nist571(BIGNUM *z, const BIGNUM *a)
    {
    /* Init */
    int ret = 0;
    __m128i _t[5], _a[5];

    /* Load */
    BN_to_XMM_9term(_a, a->d);

    /* Square */
    XMM_GF2m_mod_sqr_nist571(_t, _a);

    /* Store */
    XMM_to_BN_9term(z->d, _t);

    ret = 1;
    return ret;
    }

/* Calculates z = a * b for all a,b € GF(2^163) */
int BN_GF2m_mul_xmm_nist163(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2], _b[2];

    /* Load */
    BN_to_XMM_3term(_a, a->d);
    BN_to_XMM_3term(_b, b->d);

    /* Multiply & Reduce*/
    XMM_GF2m_mod_mul_nist163(_t, _a, _b);

    /* Store */
    XMM_to_BN_3term(z->d, _t);

    ret = 1;
	return ret;
    }

/* Calculates z = a * b for all a,b € GF(2^193) */
int BN_GF2m_mul_xmm_sect193(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2], _b[2];

    /* Load */
    BN_to_XMM_4term(_a, a->d);
    BN_to_XMM_4term(_b, b->d);

    /* Multiply & Reduce*/
    XMM_GF2m_mod_mul_sect193(_t, _a, _b);

    /* Store */
    XMM_to_BN_4term(z->d, _t);

    ret = 1;
    return ret;
    }

/* Calculates z = a * b for all a,b € GF(2^233) */
int BN_GF2m_mul_xmm_nist233(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2], _b[2];

    /* Load */
    BN_to_XMM_4term(_a, a->d);
    BN_to_XMM_4term(_b, b->d);

    /* Multiply & Reduce*/
    XMM_GF2m_mod_mul_nist233(_t, _a, _b);

    /* Store */
    XMM_to_BN_4term(z->d, _t);

    ret = 1;
	return ret;
    }

/* Calculates z = a * b for all a,b € GF(2^239) */
int BN_GF2m_mul_xmm_sect239(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2], _b[2];

    /* Load */
    BN_to_XMM_4term(_a, a->d);
    BN_to_XMM_4term(_b, b->d);

    /* Multiply & Reduce*/
    XMM_GF2m_mod_mul_sect239(_t, _a, _b);

    /* Store */
    XMM_to_BN_4term(z->d, _t);

    ret = 1;
	return ret;
	}

/* Calculates z = a * b for all a,b € GF(2^283) */
int BN_GF2m_mul_xmm_nist283(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[3], _a[3], _b[3];

    /* Load */
    BN_to_XMM_5term(_a, a->d);
    BN_to_XMM_5term(_b, b->d);

    /* Multiply & Reduce*/
    XMM_GF2m_mod_mul_nist283(_t, _a, _b);

    /* Store */
    XMM_to_BN_5term(z->d, _t);

    ret = 1;
	return ret;
	}

/* Calculates z = a * b for all a,b € GF(2^409) */
int BN_GF2m_mul_xmm_nist409(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[4], _a[4], _b[4];

    /* Load */
    BN_to_XMM_7term(_a, a->d);
    BN_to_XMM_7term(_b, b->d);

    /* Multiply & Reduce*/
    XMM_GF2m_mod_mul_nist409(_t, _a, _b);

    /* Store */
    XMM_to_BN_7term(z->d, _t);

    ret = 1;
	return ret;
	}

/* Calculates z = a * b for all a,b € GF(2^571) */
int BN_GF2m_mul_xmm_nist571(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[5], _a[5], _b[5];

    /* Load */
    BN_to_XMM_9term(_a, a->d);
    BN_to_XMM_9term(_b, b->d);

    /* Multiply & Reduce*/
    XMM_GF2m_mod_mul_nist571(_t, _a, _b);

    /* Store */
    XMM_to_BN_9term(z->d, _t);

    ret = 1;
	return ret;
	}


/* Calculates z = a/b = a * b⁻¹ for all a,b € GF(2^163) */
int BN_GF2m_div_xmm_nist163(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2], _b[2];

    /* Load */
    BN_to_XMM_3term(_a, a->d);
    BN_to_XMM_3term(_b, b->d);

    /* Divide */
    XMM_GF2m_div_nist163(_t, _a, _b);

    /* Store */
    XMM_to_BN_3term(z->d, _t);

    ret = 1;
	return ret;
	}

/* Calculates z = a/b = a * b⁻¹ for all a,b € GF(2^193) */
int BN_GF2m_div_xmm_sect193(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2], _b[2];

    /* Load */
    BN_to_XMM_4term(_a, a->d);
    BN_to_XMM_4term(_b, b->d);

    /* Divide */
    XMM_GF2m_div_sect193(_t, _a, _b);

    /* Store */
    XMM_to_BN_4term(z->d, _t);

    ret = 1;
	return ret;
	}

/* Calculates z = a/b = a * b⁻¹ for all a,b € GF(2^233) */
int BN_GF2m_div_xmm_nist233(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2], _b[2];

    /* Load */
    BN_to_XMM_4term(_a, a->d);
    BN_to_XMM_4term(_b, b->d);

    /* Divide */
    XMM_GF2m_div_nist233(_t, _a, _b);

    /* Store */
    XMM_to_BN_4term(z->d, _t);

    ret = 1;
	return ret;
	}

/* Calculates z = a/b = a * b⁻¹ for all a,b € GF(2^239) */
int BN_GF2m_div_xmm_sect239(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[2], _a[2], _b[2];

    /* Load */
    BN_to_XMM_4term(_a, a->d);
    BN_to_XMM_4term(_b, b->d);

    /* Divide */
    XMM_GF2m_div_sect239(_t, _a, _b);

    /* Store */
    XMM_to_BN_4term(z->d, _t);

    ret = 1;
	return ret;
	}

/* Calculates z = a/b = a * b⁻¹ for all a,b € GF(2^283) */
int BN_GF2m_div_xmm_nist283(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[3], _a[3], _b[3];

    /* Load */
    BN_to_XMM_5term(_a, a->d);
    BN_to_XMM_5term(_b, b->d);

    /* Divide */
    XMM_GF2m_div_nist283(_t, _a, _b);

    /* Store */
    XMM_to_BN_5term(z->d, _t);

    ret = 1;
	return ret;
	}

/* Calculates z = a/b = a * b⁻¹ for all a,b € GF(2^409) */
int BN_GF2m_div_xmm_nist409(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[4], _a[4], _b[4];

    /* Load */
    BN_to_XMM_7term(_a, a->d);
    BN_to_XMM_7term(_b, b->d);

    /* Divide */
    XMM_GF2m_div_nist409(_t, _a, _b);

    /* Store */
    XMM_to_BN_7term(z->d, _t);

    ret = 1;
	return ret;
	}

/* Calculates z = a/b = a * b⁻¹ for all a,b € GF(2^571) */
int BN_GF2m_div_xmm_nist571(BIGNUM *z, const BIGNUM *a, const BIGNUM *b)
    {
    /* Init */
    int ret = 0;
    __m128i _t[5], _a[5], _b[5];

    /* Load */
    BN_to_XMM_9term(_a, a->d);
    BN_to_XMM_9term(_b, b->d);

    /* Divide */
    XMM_GF2m_div_nist571(_t, _a, _b);

    /* Store */
    XMM_to_BN_9term(z->d, _t);

    ret = 1;
	return ret;
	}


/*********************************************************************************************
 *	BIGNUM MADDLE FUNCTIONS
 *
 *  This section provides fast and constant time implementations for the Madd and Mdouble
 *  methods of the 2P algorithm from "Lopez, J. and Dahab, R.  "Fast multiplication on
 *  elliptic curves over GF(2^m) without precomputation" (CHES '99, LNCS 1717).
 *
 *  Madd has been improved with the 'lazy reduction' technique and Mdouble with an improved
 *  code flow. Additionally, both functions are joined to 'Maddle', which takes a key bit as
 *  input and enables to implement the Montgomery point multiplication without taking any
 *  branches by veiling the coordinates.
 *
 *********************************************************************************************/


int BN_GF2m_Maddle_xmm_nist163k(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[2], _t2[3], _t3[3], _x1[2], _z1[2], _x2[2], _z2[2];
	__m128i _tx1[2], _tz1[2], _tx2[2], _tz2[2];

	/* Load */
	BN_to_XMM_3term(_tx1, x1->d);
	BN_to_XMM_3term(_tz1, z1->d);
	BN_to_XMM_3term(_tz2, z2->d);
	BN_to_XMM_3term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_2term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_nist163(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_nist163(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_3x3_mul(_t2, _x1, _z1);

	XMM_GF2m_add_2term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_nist163(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_3term(_t1, x->d);
	XMM_GF2m_3x3_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_3term(_t3, _t3, _t2);
#ifdef FAST_PCLMUL
	XMM_GF2m_mod_nist163_clmul(_x1, _t3);
#else
	XMM_GF2m_mod_nist163(_x1, _t3);
#endif

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_nist163(_x2, _x2);
	XMM_GF2m_mod_sqr_nist163(_z2, _z2);

	XMM_GF2m_add_2term(_t1, _z2, _x2);

	XMM_GF2m_mod_mul_nist163(_z2, _z2, _x2);
	XMM_GF2m_mod_sqr_nist163(_x2, _t1);

	/* Unveil data */
	XMM_GF2m_veil_2term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_3term(x1->d, _tx1);
	XMM_to_BN_3term(z1->d, _tz1);
	XMM_to_BN_3term(x2->d, _tx2);
	XMM_to_BN_3term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

int BN_GF2m_Maddle_xmm_nist163r(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[2], _t2[3], _t3[3], _x1[2], _z1[2], _x2[2], _z2[2];
	__m128i _tx1[2], _tz1[2], _tx2[2], _tz2[2];

	/* Load */
	BN_to_XMM_3term(_tx1, x1->d);
	BN_to_XMM_3term(_tz1, z1->d);
	BN_to_XMM_3term(_tz2, z2->d);
	BN_to_XMM_3term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_2term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_nist163(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_nist163(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_3x3_mul(_t2, _x1, _z1);

	XMM_GF2m_add_2term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_nist163(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_3term(_t1, x->d);
	XMM_GF2m_3x3_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_3term(_t3, _t3, _t2);
#ifdef FAST_PCLMUL
	XMM_GF2m_mod_nist163_clmul(_x1, _t3);
#else
	XMM_GF2m_mod_nist163(_x1, _t3);
#endif

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_nist163(_x2, _x2);
	XMM_GF2m_mod_sqr_nist163(_z2, _z2);

	BN_to_XMM_3term(_t1, c->d);
	XMM_GF2m_mod_mul_nist163(_t1, _z2, _t1);

	XMM_GF2m_mod_mul_nist163(_z2, _z2, _x2);
	XMM_GF2m_add_2term(_x2, _x2, _t1);
	XMM_GF2m_mod_sqr_nist163(_x2, _x2);

	/* Unveil data */
	XMM_GF2m_veil_2term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_3term(x1->d, _tx1);
	XMM_to_BN_3term(z1->d, _tz1);
	XMM_to_BN_3term(x2->d, _tx2);
	XMM_to_BN_3term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

int BN_GF2m_Maddle_xmm_sect193r(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[2], _t2[4], _t3[4], _x1[2], _z1[2], _x2[2], _z2[2];
	__m128i _tx1[2], _tz1[2], _tx2[2], _tz2[2];

	/* Load */
	BN_to_XMM_4term(_tx1, x1->d);
	BN_to_XMM_4term(_tz1, z1->d);
	BN_to_XMM_4term(_tz2, z2->d);
	BN_to_XMM_4term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_2term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_sect193(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_sect193(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_4x4_mul(_t2, _x1, _z1);

	XMM_GF2m_add_2term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_sect193(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_4term(_t1, x->d);
	XMM_GF2m_4x4_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_4term(_t3, _t3, _t2);
	XMM_GF2m_mod_sect193(_x1, _t3);

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_sect193(_x2, _x2);
	XMM_GF2m_mod_sqr_sect193(_z2, _z2);

	BN_to_XMM_4term(_t1, c->d);
	XMM_GF2m_mod_mul_sect193(_t1, _z2, _t1);

	XMM_GF2m_mod_mul_sect193(_z2, _z2, _x2);
	XMM_GF2m_add_2term(_x2, _x2, _t1);
	XMM_GF2m_mod_sqr_sect193(_x2, _x2);

	/* Unveil data */
	XMM_GF2m_veil_2term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_4term(x1->d, _tx1);
	XMM_to_BN_4term(z1->d, _tz1);
	XMM_to_BN_4term(x2->d, _tx2);
	XMM_to_BN_4term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

int BN_GF2m_Maddle_xmm_nist233k(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[2], _t2[4], _t3[4], _x1[2], _z1[2], _x2[2], _z2[2];
	__m128i _tx1[2], _tz1[2], _tx2[2], _tz2[2];

	/* Load */
	BN_to_XMM_4term(_tx1, x1->d);
	BN_to_XMM_4term(_tz1, z1->d);
	BN_to_XMM_4term(_tz2, z2->d);
	BN_to_XMM_4term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_2term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_nist233(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_nist233(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_4x4_mul(_t2, _x1, _z1);

	XMM_GF2m_add_2term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_nist233(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_4term(_t1, x->d);
	XMM_GF2m_4x4_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_4term(_t3, _t3, _t2);
	XMM_GF2m_mod_nist233(_x1, _t3);

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_nist233(_x2, _x2);
	XMM_GF2m_mod_sqr_nist233(_z2, _z2);

	XMM_GF2m_add_2term(_t1, _z2, _x2);

	XMM_GF2m_mod_mul_nist233(_z2, _z2, _x2);
	XMM_GF2m_mod_sqr_nist233(_x2, _t1);

	/* Unveil data */
	XMM_GF2m_veil_2term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_4term(x1->d, _tx1);
	XMM_to_BN_4term(z1->d, _tz1);
	XMM_to_BN_4term(x2->d, _tx2);
	XMM_to_BN_4term(z2->d, _tz2);

	ret = 1;
	return ret;
	}


int BN_GF2m_Maddle_xmm_nist233r(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[2], _t2[4], _t3[4], _x1[2], _z1[2], _x2[2], _z2[2];
	__m128i _tx1[2], _tz1[2], _tx2[2], _tz2[2];

	/* Load */
	BN_to_XMM_4term(_tx1, x1->d);
	BN_to_XMM_4term(_tz1, z1->d);
	BN_to_XMM_4term(_tz2, z2->d);
	BN_to_XMM_4term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_2term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_nist233(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_nist233(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_4x4_mul(_t2, _x1, _z1);

	XMM_GF2m_add_2term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_nist233(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_4term(_t1, x->d);
	XMM_GF2m_4x4_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_4term(_t3, _t3, _t2);
	XMM_GF2m_mod_nist233(_x1, _t3);

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_nist233(_x2, _x2);
	XMM_GF2m_mod_sqr_nist233(_z2, _z2);

	BN_to_XMM_4term(_t1, c->d);
	XMM_GF2m_mod_mul_nist233(_t1, _z2, _t1);

	XMM_GF2m_mod_mul_nist233(_z2, _z2, _x2);
	XMM_GF2m_add_2term(_x2, _x2, _t1);
	XMM_GF2m_mod_sqr_nist233(_x2, _x2);

	/* Unveil data */
	XMM_GF2m_veil_2term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_4term(x1->d, _tx1);
	XMM_to_BN_4term(z1->d, _tz1);
	XMM_to_BN_4term(x2->d, _tx2);
	XMM_to_BN_4term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

int BN_GF2m_Maddle_xmm_sect239k(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[2], _t2[4], _t3[4], _x1[2], _z1[2], _x2[2], _z2[2];
	__m128i _tx1[2], _tz1[2], _tx2[2], _tz2[2];

	/* Load */
	BN_to_XMM_4term(_tx1, x1->d);
	BN_to_XMM_4term(_tz1, z1->d);
	BN_to_XMM_4term(_tz2, z2->d);
	BN_to_XMM_4term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_2term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_sect239(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_sect239(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_4x4_mul(_t2, _x1, _z1);

	XMM_GF2m_add_2term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_sect239(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_4term(_t1, x->d);
	XMM_GF2m_4x4_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_4term(_t3, _t3, _t2);
	XMM_GF2m_mod_sect239(_x1, _t3);

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_sect239(_x2, _x2);
	XMM_GF2m_mod_sqr_sect239(_z2, _z2);

	XMM_GF2m_add_2term(_t1, _z2, _x2);

	XMM_GF2m_mod_mul_sect239(_z2, _z2, _x2);
	XMM_GF2m_mod_sqr_sect239(_x2, _t1);

	/* Unveil data */
	XMM_GF2m_veil_2term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_4term(x1->d, _tx1);
	XMM_to_BN_4term(z1->d, _tz1);
	XMM_to_BN_4term(x2->d, _tx2);
	XMM_to_BN_4term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

int BN_GF2m_Maddle_xmm_nist283k(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[3], _t2[5], _t3[5], _x1[3], _z1[3], _x2[3], _z2[3];
	__m128i _tx1[3], _tz1[3], _tx2[3], _tz2[3];

	/* Load */
	BN_to_XMM_5term(_tx1, x1->d);
	BN_to_XMM_5term(_tz1, z1->d);
	BN_to_XMM_5term(_tz2, z2->d);
	BN_to_XMM_5term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_3term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_nist283(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_nist283(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_5x5_mul(_t2, _x1, _z1);

	XMM_GF2m_add_3term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_nist283(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_5term(_t1, x->d);
	XMM_GF2m_5x5_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_5term(_t3, _t3, _t2);
#ifdef FAST_PCLMUL
	XMM_GF2m_mod_nist283_clmul(_x1, _t3);
#else
	XMM_GF2m_mod_nist283(_x1, _t3);
#endif

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_nist283(_x2, _x2);
	XMM_GF2m_mod_sqr_nist283(_z2, _z2);

	XMM_GF2m_add_3term(_t1, _z2, _x2);

	XMM_GF2m_mod_mul_nist283(_z2, _z2, _x2);
	XMM_GF2m_mod_sqr_nist283(_x2, _t1);

	/* Unveil data */
	XMM_GF2m_veil_3term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_5term(x1->d, _tx1);
	XMM_to_BN_5term(z1->d, _tz1);
	XMM_to_BN_5term(x2->d, _tx2);
	XMM_to_BN_5term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

int BN_GF2m_Maddle_xmm_nist283r(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[3], _t2[5], _t3[5], _x1[3], _z1[3], _x2[3], _z2[3];
	__m128i _tx1[3], _tz1[3], _tx2[3], _tz2[3];

	/* Load */
	BN_to_XMM_5term(_tx1, x1->d);
	BN_to_XMM_5term(_tz1, z1->d);
	BN_to_XMM_5term(_tz2, z2->d);
	BN_to_XMM_5term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_3term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_nist283(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_nist283(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_5x5_mul(_t2, _x1, _z1);

	XMM_GF2m_add_3term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_nist283(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_5term(_t1, x->d);
	XMM_GF2m_5x5_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_5term(_t3, _t3, _t2);
#ifdef FAST_PCLMUL
	XMM_GF2m_mod_nist283_clmul(_x1, _t3);
#else
	XMM_GF2m_mod_nist283(_x1, _t3);
#endif

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_nist283(_x2, _x2);
	XMM_GF2m_mod_sqr_nist283(_z2, _z2);

	BN_to_XMM_5term(_t1, c->d);
	XMM_GF2m_mod_mul_nist283(_t1, _z2, _t1);

	XMM_GF2m_mod_mul_nist283(_z2, _z2, _x2);
	XMM_GF2m_add_3term(_x2, _x2, _t1);
	XMM_GF2m_mod_sqr_nist283(_x2, _x2);

	/* Unveil data */
	XMM_GF2m_veil_3term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_5term(x1->d, _tx1);
	XMM_to_BN_5term(z1->d, _tz1);
	XMM_to_BN_5term(x2->d, _tx2);
	XMM_to_BN_5term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

int BN_GF2m_Maddle_xmm_nist409k(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[4], _t2[7], _t3[7], _x1[4], _z1[4], _x2[4], _z2[4];
	__m128i _tx1[4], _tz1[4], _tx2[4], _tz2[4];

	/* Load */
	BN_to_XMM_7term(_tx1, x1->d);
	BN_to_XMM_7term(_tz1, z1->d);
	BN_to_XMM_7term(_tz2, z2->d);
	BN_to_XMM_7term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_4term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_nist409(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_nist409(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_7x7_mul(_t2, _x1, _z1);

	XMM_GF2m_add_4term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_nist409(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_7term(_t1, x->d);
	XMM_GF2m_7x7_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_7term(_t3, _t3, _t2);
	XMM_GF2m_mod_nist409(_x1, _t3);

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_nist409(_x2, _x2);
	XMM_GF2m_mod_sqr_nist409(_z2, _z2);

	XMM_GF2m_add_4term(_t1, _z2, _x2);

	XMM_GF2m_mod_mul_nist409(_z2, _z2, _x2);
	XMM_GF2m_mod_sqr_nist409(_x2, _t1);

	/* Unveil data */
	XMM_GF2m_veil_4term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_7term(x1->d, _tx1);
	XMM_to_BN_7term(z1->d, _tz1);
	XMM_to_BN_7term(x2->d, _tx2);
	XMM_to_BN_7term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

int BN_GF2m_Maddle_xmm_nist409r(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[4], _t2[7], _t3[7], _x1[4], _z1[4], _x2[4], _z2[4];
	__m128i _tx1[4], _tz1[4], _tx2[4], _tz2[4];

	/* Load */
	BN_to_XMM_7term(_tx1, x1->d);
	BN_to_XMM_7term(_tz1, z1->d);
	BN_to_XMM_7term(_tz2, z2->d);
	BN_to_XMM_7term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_4term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_nist409(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_nist409(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_7x7_mul(_t2, _x1, _z1);

	XMM_GF2m_add_4term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_nist409(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_7term(_t1, x->d);
	XMM_GF2m_7x7_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_7term(_t3, _t3, _t2);
	XMM_GF2m_mod_nist409(_x1, _t3);

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_nist409(_x2, _x2);
	XMM_GF2m_mod_sqr_nist409(_z2, _z2);

	BN_to_XMM_7term(_t1, c->d);
	XMM_GF2m_mod_mul_nist409(_t1, _z2, _t1);

	XMM_GF2m_mod_mul_nist409(_z2, _z2, _x2);
	XMM_GF2m_add_4term(_x2, _x2, _t1);
	XMM_GF2m_mod_sqr_nist409(_x2, _x2);

	/* Unveil data */
	XMM_GF2m_veil_4term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_7term(x1->d, _tx1);
	XMM_to_BN_7term(z1->d, _tz1);
	XMM_to_BN_7term(x2->d, _tx2);
	XMM_to_BN_7term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

int BN_GF2m_Maddle_xmm_nist571k(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[5], _t2[9], _t3[9], _x1[5], _z1[5], _x2[5], _z2[5];
	__m128i _tx1[5], _tz1[5], _tx2[5], _tz2[5];

	/* Load */
	BN_to_XMM_9term(_tx1, x1->d);
	BN_to_XMM_9term(_tz1, z1->d);
	BN_to_XMM_9term(_tz2, z2->d);
	BN_to_XMM_9term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_5term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_nist571(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_nist571(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_9x9_mul(_t2, _x1, _z1);

	XMM_GF2m_add_5term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_nist571(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_9term(_t1, x->d);
	XMM_GF2m_9x9_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_9term(_t3, _t3, _t2);
#ifdef FAST_PCLMUL
	XMM_GF2m_mod_nist571_clmul(_x1, _t3);
#else
	XMM_GF2m_mod_nist571(_x1, _t3);
#endif

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_nist571(_x2, _x2);
	XMM_GF2m_mod_sqr_nist571(_z2, _z2);

	XMM_GF2m_add_5term(_t1, _z2, _x2);

	XMM_GF2m_mod_mul_nist571(_z2, _z2, _x2);
	XMM_GF2m_mod_sqr_nist571(_x2, _t1);

	/* Unveil data */
	XMM_GF2m_veil_5term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_9term(x1->d, _tx1);
	XMM_to_BN_9term(z1->d, _tz1);
	XMM_to_BN_9term(x2->d, _tx2);
	XMM_to_BN_9term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

int BN_GF2m_Maddle_xmm_nist571r(const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
		const BIGNUM *x2, const BIGNUM *z2, BN_ULONG k, const BIGNUM *c)
	{
	/* Init */
	int ret = 0;
	__m128i _t1[5], _t2[9], _t3[9], _x1[5], _z1[5], _x2[5], _z2[5];
	__m128i _tx1[5], _tz1[5], _tx2[5], _tz2[5];

	/* Load */
	BN_to_XMM_9term(_tx1, x1->d);
	BN_to_XMM_9term(_tz1, z1->d);
	BN_to_XMM_9term(_tz2, z2->d);
	BN_to_XMM_9term(_tx2, x2->d);

	/*  Data veiling */
	XMM_GF2m_veil_5term(_x1, _z1, _x2, _z2, _tx1, _tz1, _tx2, _tz2, k);

	/* MADD */

	XMM_GF2m_mod_mul_nist571(_x1, _x1, _z2);
	XMM_GF2m_mod_mul_nist571(_z1, _z1, _x2);

	/* Multiply w/o reduction */
	XMM_GF2m_9x9_mul(_t2, _x1, _z1);

	XMM_GF2m_add_5term(_z1, _z1, _x1);
	XMM_GF2m_mod_sqr_nist571(_z1, _z1);

	/* Multiply w/o reduction */
	BN_to_XMM_9term(_t1, x->d);
	XMM_GF2m_9x9_mul(_t3, _z1, _t1);

	/* Add the two double-sized numbers and reduce */
	XMM_GF2m_add_9term(_t3, _t3, _t2);
#ifdef FAST_PCLMUL
	XMM_GF2m_mod_nist571_clmul(_x1, _t3);
#else
	XMM_GF2m_mod_nist571(_x1, _t3);
#endif

	/* MDOUBLE */

	XMM_GF2m_mod_sqr_nist571(_x2, _x2);
	XMM_GF2m_mod_sqr_nist571(_z2, _z2);

	BN_to_XMM_9term(_t1, c->d);
	XMM_GF2m_mod_mul_nist571(_t1, _z2, _t1);

	XMM_GF2m_mod_mul_nist571(_z2, _z2, _x2);
	XMM_GF2m_add_5term(_x2, _x2, _t1);
	XMM_GF2m_mod_sqr_nist571(_x2, _x2);

	/* Unveil data */
	XMM_GF2m_veil_5term(_tx1, _tz1, _tx2, _tz2, _x1, _z1, _x2, _z2, k);

	/* Store results */
	XMM_to_BN_9term(x1->d, _tx1);
	XMM_to_BN_9term(z1->d, _tz1);
	XMM_to_BN_9term(x2->d, _tx2);
	XMM_to_BN_9term(z2->d, _tz2);

	ret = 1;
	return ret;
	}

#endif

#endif
