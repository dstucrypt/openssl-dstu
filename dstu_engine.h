/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

#ifndef DSTU_ENGINE_H_
#define DSTU_ENGINE_H_

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>

extern EVP_PKEY_METHOD *dstu_pkey_meth_le, *dstu_pkey_meth_be;
int dstu_pkey_meth_init(void);
void dstu_pkey_meth_finish(void);

extern EVP_PKEY_ASN1_METHOD *dstu_asn1_meth_le, *dstu_asn1_meth_be;
int dstu_asn1_meth_init(void);
void dstu_asn1_meth_finish(void);

int dstu_do_sign(const EC_KEY* key, const unsigned char *tbs, size_t tbslen,
	unsigned char *sig);
int dstu_do_verify(const EC_KEY* key, const unsigned char *tbs, size_t tbslen,
	const unsigned char *sig, size_t siglen);

extern EVP_MD dstu_md;

extern EVP_CIPHER dstu_cipher;

extern RAND_METHOD dstu_rand_meth;

/* This ctrl command to set custom sbox for MD and CIPHER */
/* p2 should point to char array of 64 bytes (packed format, see default_sbox), p1 should be set to size of the array (64) */
#define DSTU_SET_CUSTOM_SBOX (EVP_MD_CTRL_ALG_CTRL + 1)

#define DSTU_SET_CURVE (EVP_PKEY_ALG_CTRL + 2)

#endif /* DSTU_ENGINE_H_ */
