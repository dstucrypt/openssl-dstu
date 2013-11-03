/*
 * dstu_compress.h
 *
 *  Created on: Jun 3, 2013
 *      Author: ignat
 */

#ifndef DSTU_COMPRESS_H_
#define DSTU_COMPRESS_H_

#include <openssl/ec.h>

int dstu_point_compress(const EC_GROUP* group, const EC_POINT* point,
	unsigned char* compressed, int compressed_length);
int dstu_point_expand(const unsigned char* compressed, int compressed_length,
	const EC_GROUP* group, EC_POINT* point);

#endif /* DSTU_COMPRESS_H_ */
