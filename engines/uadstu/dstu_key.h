/*
 * dstu_key.h
 *
 *  Created on: May 29, 2013
 *      Author: ignat
 */

#ifndef DSTU_KEY_H_
#define DSTU_KEY_H_

#include <openssl/ec.h>
#include "../ccgost/gost89.h"
#include "dstu_asn1.h"

typedef struct dstu_key_st
    {
	EC_KEY* ec;
	unsigned char* sbox;
    } DSTU_KEY;

typedef struct dstu_key_ctx_st
    {
	int type;
	EC_GROUP* group;
	unsigned char* sbox;
    } DSTU_KEY_CTX;

DSTU_KEY* DSTU_KEY_new(void);
void DSTU_KEY_set(DSTU_KEY* key, EC_KEY* ec, unsigned char *sbox);
DSTU_KEY* key_from_asn1(const DSTU_AlgorithmParameters* params,
	int is_little_endian);
DSTU_AlgorithmParameters* asn1_from_key(const DSTU_KEY* key,
	int is_little_endian);
void DSTU_KEY_free(DSTU_KEY* key);

DSTU_KEY_CTX* DSTU_KEY_CTX_new(void);
void DSTU_KEY_CTX_set(DSTU_KEY_CTX* ctx, EC_GROUP* group, unsigned char *sbox);
DSTU_KEY_CTX* DSTU_KEY_CTX_copy(const DSTU_KEY_CTX* ctx);
void DSTU_KEY_CTX_free(DSTU_KEY_CTX* ctx);

#endif /* DSTU_KEY_H_ */
