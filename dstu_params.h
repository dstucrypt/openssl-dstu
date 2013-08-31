/*
 * dstu_params.h
 *
 *  Created on: Mar 6, 2013
 *      Author: ignat
 */

#ifndef DSTU_PARAMS_H_
#define DSTU_PARAMS_H_

#include <openssl/ec.h>
#include "../ccgost/gost89.h"

#define DEFAULT_CURVE 6
#define get_default_group() group_from_named_curve(DEFAULT_CURVE)

typedef struct dstu_named_curve_st
{
	int nid;
	int poly[6];
	unsigned char* data;
} DSTU_NAMED_CURVE;

extern DSTU_NAMED_CURVE dstu_curves[];
extern unsigned char default_sbox[64];
void unpack_sbox(unsigned char* packed_sbox, gost_subst_block* unpacked_sbox);
int is_default_sbox(unsigned char* sbox);
unsigned char* copy_sbox(unsigned char* sbox);
EC_GROUP* group_from_named_curve(int curve_num);
EC_GROUP* group_from_nid(int nid);
int dstu_generate_key(EC_KEY* key);
int dstu_add_public_key(EC_KEY* key);

void reverse_bytes(void *mem, int size);
void reverse_bytes_copy(void *dst, const void *src, int size);
int bn_encode(const BIGNUM* bn, unsigned char* buffer, int length);
int curve_nid_from_group(const EC_GROUP* group);

#endif /* DSTU_PARAMS_H_ */
