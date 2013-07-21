/*
 * dstu_engine.h
 *
 *  Created on: Mar 4, 2013
 *      Author: ignat
 */

#ifndef DSTU_ENGINE_H_
#define DSTU_ENGINE_H_

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>

/* TODO: Replace this nid for actual one in obj_mac.h */
extern int dstu_nids[2];
extern int DSTU_MD_NID;
extern int DSTU_CIPHER_NID;
extern EVP_PKEY_METHOD *dstu_pkey_meth_le, *dstu_pkey_meth_be;
int dstu_pkey_meth_init(void);
void dstu_pkey_meth_finish(void);

extern EVP_PKEY_ASN1_METHOD *dstu_asn1_meth_le, *dstu_asn1_meth_be;
int dstu_asn1_meth_init(void);
void dstu_asn1_meth_finish(void);

int dstu_do_sign(const EC_KEY* key, const unsigned char *tbs, size_t tbslen, unsigned char *sig);
int dstu_do_verify(const EC_KEY* key, const unsigned char *tbs, size_t tbslen, const unsigned char *sig, size_t siglen);

extern EVP_MD dstu_md;

extern EVP_CIPHER dstu_cipher;
void test_cipher(void);

#endif /* DSTU_ENGINE_H_ */
