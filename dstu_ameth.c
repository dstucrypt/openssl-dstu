/*
 * dstu_ameth.c
 *
 *  Created on: Mar 5, 2013
 *      Author: ignat
 */
#include "dstu_engine.h"
#include "dstu_asn1.h"
#include "dstu_key.h"
#include "dstu_params.h"
#include <openssl/x509.h>
#include "dstu_compress.h"

#include "e_dstu_err.h"

static int dstu_asn1_param_decode(EVP_PKEY *pkey, const unsigned char **pder,
	int derlen)
    {
    DSTU_AlgorithmParameters* params = d2i_DSTU_AlgorithmParameters(NULL, pder,
	    derlen);
    DSTU_KEY* key = NULL;
    int ret = 0, type;
    if (!params)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PARAM_DECODE, DSTU_R_INVALID_ASN1_PARAMETERS);
	return 0;
	}

    type = EVP_PKEY_id(pkey);

    key = key_from_asn1(params, NID_dstu4145le == type);
    if (!key)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PARAM_DECODE, DSTU_R_INVALID_ASN1_PARAMETERS);
	goto err;
	}

    if (!EVP_PKEY_assign(pkey, type, key))
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PARAM_DECODE, ERR_R_EVP_LIB);
	goto err;
	}

    key = NULL;
    ret = 1;

    err: DSTU_AlgorithmParameters_free(params);

    if (key)
	DSTU_KEY_free(key);

    return ret;
    }

static int dstu_asn1_param_encode(const EVP_PKEY *pkey, unsigned char **pder)
    {
    DSTU_AlgorithmParameters* params = NULL;
    const DSTU_KEY* key = EVP_PKEY_get0((EVP_PKEY *) pkey);
    int bytes_encoded = 0, type = EVP_PKEY_id(pkey);

    if (!key)
	return 0;

    params = asn1_from_key(key, NID_dstu4145le == type);
    if (!params)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PARAM_ENCODE,
		DSTU_R_ASN1_PARAMETER_ENCODE_FAILED);
	return 0;
	}

    bytes_encoded = i2d_DSTU_AlgorithmParameters(params, pder);

    DSTU_AlgorithmParameters_free(params);

    return bytes_encoded;
    }

/*static int dstu_asn1_param_missing(const EVP_PKEY *pk)
 {
 printf("dstu_asn1_param_missing\n");
 return 0;
 }*/

static int dstu_asn1_param_copy(EVP_PKEY *to, const EVP_PKEY *from)
    {
    DSTU_KEY *to_key = EVP_PKEY_get0(to);
    DSTU_KEY *from_key = EVP_PKEY_get0((EVP_PKEY*) from);
    const EC_GROUP *from_group;

    if (from_key)
	{
	from_group = EC_KEY_get0_group(from_key->ec);
	if (!from_group)
	    return 0;

	if (!to_key)
	    {
	    to_key = DSTU_KEY_new();
	    if (!EVP_PKEY_assign(to, EVP_PKEY_id(from), to_key))
		{
		DSTU_KEY_free(to_key);
		DSTUerr(DSTU_F_DSTU_ASN1_PARAM_COPY, ERR_R_EVP_LIB);
		return 0;
		}
	    }

	if (!EC_KEY_set_group(to_key->ec, from_group))
	    {
	    DSTUerr(DSTU_F_DSTU_ASN1_PARAM_COPY, ERR_R_EC_LIB);
	    return 0;
	    }

	if (from_key->sbox)
	    {
	    to_key->sbox = copy_sbox(from_key->sbox);
	    if (!to_key->sbox)
		{
		DSTUerr(DSTU_F_DSTU_ASN1_PARAM_COPY, ERR_R_MALLOC_FAILURE);
		return 0;
		}
	    }

	return 1;
	}

    return 0;
    }

static int dstu_asn1_param_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
    {
    DSTU_KEY *first = EVP_PKEY_get0((EVP_PKEY*) a);
    DSTU_KEY *second = EVP_PKEY_get0((EVP_PKEY*) b);

    if (!first || !second)
	return -2;

    if (first->sbox != second->sbox)
	{
	if (first->sbox && second->sbox)
	    {
	    if (memcmp(first->sbox, second->sbox, sizeof(default_sbox)))
		return 0;
	    }
	else
	    return 0;
	}

    if (EC_GROUP_cmp(EC_KEY_get0_group(first->ec),
	    EC_KEY_get0_group(second->ec), NULL))
	return 0;
    else
	return 1;
    }

static int dstu_asn1_param_print(BIO *out, const EVP_PKEY *pkey, int indent,
	ASN1_PCTX *pctx)
    {
    DSTU_KEY *dstu_key = EVP_PKEY_get0((EVP_PKEY*) pkey);
    EVP_PKEY *pk;
    int ret;

    pk = EVP_PKEY_new();
    if (!pk || !EVP_PKEY_set1_EC_KEY(pk, dstu_key->ec))
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PARAM_PRINT, ERR_R_EVP_LIB);
	return 0;
	}

    ret = EVP_PKEY_print_params(out, pk, indent, NULL);

    EVP_PKEY_free(pk);
    return ret;
    }

static int dstu_asn1_priv_decode(EVP_PKEY *pk, PKCS8_PRIV_KEY_INFO *p8)
    {
    ASN1_OBJECT* algoid = NULL;
    X509_ALGOR* alg = NULL;
    const unsigned char* prk_encoded = NULL;
    unsigned char* params_encoded = NULL;
    ASN1_STRING* params = NULL;
    DSTU_KEY* key = NULL;
    BIGNUM* prk = NULL;
    ASN1_INTEGER* asn1key = NULL;
    int prk_encoded_bytes = 0, params_type = 0, algnid;

    if (!PKCS8_pkey_get0(&algoid, &prk_encoded, &prk_encoded_bytes, &alg, p8))
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_DECODE, ERR_R_X509_LIB);
	return 0;
	}

    algnid = OBJ_obj2nid(algoid);

    if ((algnid == NID_dstu4145le) || (algnid == NID_dstu4145be))
	{
	if (!EVP_PKEY_set_type(pk, algnid))
	    {
	    DSTUerr(DSTU_F_DSTU_ASN1_PRIV_DECODE, ERR_R_EVP_LIB);
	    return 0;
	    }
	}
    else
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_DECODE, DSTU_R_NOT_DSTU_KEY);
	return 0;
	}

    X509_ALGOR_get0(NULL, &params_type, (void**) &params, alg);
    if (V_ASN1_SEQUENCE != params_type)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_DECODE, ERR_R_EXPECTING_AN_ASN1_SEQUENCE);
	return 0;
	}

    params_encoded = ASN1_STRING_data(params);
    if (!params_encoded)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_DECODE, DSTU_R_NOT_DSTU_KEY);
	return 0;
	}

    if (!dstu_asn1_param_decode(pk, (const unsigned char**) &params_encoded,
	    ASN1_STRING_length(params)))
	return 0;

    asn1key = d2i_ASN1_INTEGER(NULL, &prk_encoded, prk_encoded_bytes);
    if (!asn1key)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_DECODE, ERR_R_ASN1_LIB);
	return 0;
	}
    prk = ASN1_INTEGER_to_BN(asn1key, NULL);
    if (!prk)
	{
	ASN1_INTEGER_free(asn1key);
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_DECODE, ERR_R_ASN1_LIB);
	return 0;
	}

    key = EVP_PKEY_get0((EVP_PKEY*) pk);
    if (!EC_KEY_set_private_key(key->ec, prk))
	{
	BN_free(prk);
	ASN1_INTEGER_free(asn1key);
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_DECODE, ERR_R_EC_LIB);
	return 0;
	}

    if (!dstu_add_public_key(key->ec))
	{
	BN_free(prk);
	ASN1_INTEGER_free(asn1key);
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_DECODE, ERR_R_EC_LIB);
	return 0;
	}

    BN_free(prk);
    ASN1_INTEGER_free(asn1key);

    return 1;
    }

static int dstu_asn1_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk)
    {
    unsigned char* encoded_params = NULL;
    int encoded_params_bytes = 0;
    ASN1_INTEGER* asn1key = NULL;
    unsigned char* prk_encoded = NULL;
    int prk_encoded_bytes = 0;
    int ret = 0, algnid = EVP_PKEY_id(pk);
    DSTU_KEY* key;
    const BIGNUM *d;
    ASN1_STRING *params;

    if ((algnid != NID_dstu4145le) && (algnid != NID_dstu4145be))
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_ENCODE, DSTU_R_NOT_DSTU_KEY);
	return 0;
	}

    params = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
    if (!params)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_ENCODE, ERR_R_ASN1_LIB);
	return 0;
	}

    encoded_params_bytes = dstu_asn1_param_encode(pk, &encoded_params);
    if (!encoded_params_bytes)
	goto err;

    key = EVP_PKEY_get0((EVP_PKEY*) pk);
    if (!key)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_ENCODE, DSTU_R_NOT_DSTU_KEY);
	goto err;
	}

    d = EC_KEY_get0_private_key(key->ec);
    if (!d)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_ENCODE, DSTU_R_NOT_DSTU_KEY);
	goto err;
	}

    asn1key = BN_to_ASN1_INTEGER(d, NULL);
    if (!asn1key)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_ENCODE, ERR_R_ASN1_LIB);
	goto err;
	}

    prk_encoded_bytes = i2d_ASN1_INTEGER(asn1key, &prk_encoded);
    if (!prk_encoded)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_ENCODE, ERR_R_ASN1_LIB);
	goto err;
	}

    ASN1_STRING_set0(params, encoded_params, encoded_params_bytes);

    if (PKCS8_pkey_set0(p8, OBJ_nid2obj(algnid), 0, V_ASN1_SEQUENCE, params,
	    prk_encoded, prk_encoded_bytes))
	{
	prk_encoded = NULL;
	params = NULL;
	ret = 1;
	}
    else
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PRIV_ENCODE, ERR_R_ASN1_LIB);
	}

    err: if (prk_encoded)
	OPENSSL_free(prk_encoded);
    if (asn1key)
	ASN1_INTEGER_free(asn1key);
    if (params)
	ASN1_STRING_free(params);

    return ret;
    }

static int dstu_asn1_pkey_bits(const EVP_PKEY *pk)
    {
    DSTU_KEY* key = EVP_PKEY_get0((EVP_PKEY *) pk);
    const EC_GROUP* group;

    if (key)
	{
	group = EC_KEY_get0_group(key->ec);
	if (group)
	    return EC_GROUP_get_degree(group);
	}
    return 0;
    }

static int dstu_asn1_pkey_size(const EVP_PKEY *pk)
    {
    return ASN1_object_size(0, ((dstu_asn1_pkey_bits(pk) + 7) / 8) * 2,
	    V_ASN1_OCTET_STRING);
    }

void dstu_asn1_pkey_free(EVP_PKEY *pkey)
    {
    DSTU_KEY* key = EVP_PKEY_get0(pkey);

    if (key)
	DSTU_KEY_free(key);
    }

static int dstu_asn1_pub_decode(EVP_PKEY *pk, X509_PUBKEY *pub)
    {
    ASN1_OBJECT* algoid = NULL;
    const unsigned char *pbk_buf = NULL;
    unsigned char *compressed = NULL;
    int pbk_buf_len, param_type, algnid;
    unsigned char *params_encoded = NULL, *public_key_data;
    ASN1_STRING* params = NULL;
    ASN1_OCTET_STRING* public_key = NULL;
    X509_ALGOR* algid;
    DSTU_KEY* key = NULL;
    EC_POINT* point = NULL;
    int ret = 0;

    if (!X509_PUBKEY_get0_param(&algoid, &pbk_buf, &pbk_buf_len, &algid, pub))
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE, ERR_R_X509_LIB);
	return 0;
	}

    X509_ALGOR_get0(&algoid, &param_type, (void**) &params, algid);
    if (V_ASN1_SEQUENCE != param_type)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE, ERR_R_EXPECTING_AN_ASN1_SEQUENCE);
	return 0;
	}

    algnid = OBJ_obj2nid(algoid);

    if ((algnid == NID_dstu4145le) || (algnid == NID_dstu4145be))
	{
	if (!EVP_PKEY_set_type(pk, algnid))
	    {
	    DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE, ERR_R_EVP_LIB);
	    return 0;
	    }
	}
    else
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE, DSTU_R_NOT_DSTU_KEY);
	return 0;
	}

    params_encoded = ASN1_STRING_data(params);
    if (!params_encoded)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE, DSTU_R_NOT_DSTU_KEY);
	return 0;
	}

    if (!dstu_asn1_param_decode(pk, (const unsigned char**) &params_encoded,
	    ASN1_STRING_length(params)))
	return 0;

    key = EVP_PKEY_get0(pk);
    if (!key)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE, DSTU_R_NOT_DSTU_KEY);
	return 0;
	}

    point = EC_POINT_new(EC_KEY_get0_group(key->ec));
    if (!point)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE, ERR_R_EC_LIB);
	return 0;
	}

    public_key_data = ASN1_STRING_data(pub->public_key);
    if (!d2i_ASN1_OCTET_STRING(&public_key,
	    (const unsigned char **) &public_key_data,
	    ASN1_STRING_length(pub->public_key)))
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE, ERR_R_ASN1_LIB);
	goto err;
	}

    if (algnid == NID_dstu4145le)
	{
	compressed = OPENSSL_malloc(ASN1_STRING_length(public_key));
	if (!compressed)
	    {
	    DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE, ERR_R_MALLOC_FAILURE);
	    goto err;
	    }

	reverse_bytes_copy(compressed, ASN1_STRING_data(public_key),
		ASN1_STRING_length(public_key));
	if (!dstu_point_expand(compressed, ASN1_STRING_length(public_key),
		EC_KEY_get0_group(key->ec), point))
	    {
	    OPENSSL_free(compressed);
	    DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE,
		    DSTU_R_POINT_UNCOMPRESS_FAILED);
	    goto err;
	    }
	OPENSSL_free(compressed);
	}
    else
	{
	if (!dstu_point_expand(ASN1_STRING_data(public_key),
		ASN1_STRING_length(public_key), EC_KEY_get0_group(key->ec),
		point))
	    {
	    DSTUerr(DSTU_F_DSTU_ASN1_PUB_DECODE,
		    DSTU_R_POINT_UNCOMPRESS_FAILED);
	    goto err;
	    }
	}

    if (EC_KEY_set_public_key(key->ec, point))
	ret = 1;

    err: if (public_key)
	ASN1_OCTET_STRING_free(public_key);

    if (point)
	EC_POINT_free(point);

    return ret;
    }

static int dstu_asn1_pub_encode(X509_PUBKEY *pub, const EVP_PKEY *pk)
    {
    unsigned char /* *encoded_params = NULL,*/*compressed = NULL, *pbk_encoded =
	    NULL;
    /*int encoded_params_bytes = 0;*/
    ASN1_OCTET_STRING* public_key = NULL;
    int ret = 0, algnid = EVP_PKEY_id(pk), field_size, pbk_encoded_bytes;
    DSTU_KEY* key;
    const EC_GROUP* group;
    ASN1_STRING *params;
    const EC_POINT* point = NULL;

    if ((algnid != NID_dstu4145le) && (algnid != NID_dstu4145be))
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_ENCODE, DSTU_R_NOT_DSTU_KEY);
	return 0;
	}

    params = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
    if (!params)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_ENCODE, ERR_R_ASN1_LIB);
	return 0;
	}

    params->length = dstu_asn1_param_encode(pk, &(params->data));
    if (params->length <= 0)
	goto err;

    /*encoded_params_bytes = dstu_asn1_param_encode(pk, &encoded_params);
     if (!encoded_params_bytes)
     goto err;

     ASN1_STRING_set0(params, encoded_params, encoded_params_bytes);*/

    key = EVP_PKEY_get0((EVP_PKEY*) pk);
    if (!key)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_ENCODE, DSTU_R_NOT_DSTU_KEY);
	goto err;
	}

    group = EC_KEY_get0_group(key->ec);
    if (!group)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_ENCODE, ERR_R_EC_LIB);
	goto err;
	}

    field_size = (EC_GROUP_get_degree(group) + 7) / 8;

    point = EC_KEY_get0_public_key(key->ec);
    if (!point)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_ENCODE, DSTU_R_NOT_DSTU_KEY);
	goto err;
	}

    compressed = OPENSSL_malloc(field_size);
    if (!compressed)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
	goto err;
	}

    if (!dstu_point_compress(group, point, compressed, field_size))
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_ENCODE, DSTU_R_POINT_COMPRESS_FAILED);
	goto err;
	}

    if (algnid == NID_dstu4145le)
	reverse_bytes(compressed, field_size);

    public_key = ASN1_OCTET_STRING_new();
    if (!public_key)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_ENCODE, ERR_R_ASN1_LIB);
	goto err;
	}

    ASN1_STRING_set0((ASN1_STRING*) public_key, compressed, field_size);
    compressed = NULL;

    pbk_encoded_bytes = i2d_ASN1_OCTET_STRING(public_key, &pbk_encoded);
    if (!pbk_encoded)
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_ENCODE, ERR_R_ASN1_LIB);
	goto err;
	}

    if (X509_PUBKEY_set0_param(pub, OBJ_nid2obj(algnid), V_ASN1_SEQUENCE,
	    params, pbk_encoded, pbk_encoded_bytes))
	{
	pbk_encoded = NULL;
	params = NULL;
	ret = 1;
	}
    else
	{
	DSTUerr(DSTU_F_DSTU_ASN1_PUB_ENCODE, ERR_R_X509_LIB);
	}

    err: if (pbk_encoded)
	OPENSSL_free(pbk_encoded);

    if (public_key)
	ASN1_OCTET_STRING_free(public_key);

    if (compressed)
	OPENSSL_free(compressed);

    if (params)
	ASN1_STRING_free(params);

    return ret;
    }

static int dstu_asn1_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
    {
    DSTU_KEY *first = EVP_PKEY_get0((EVP_PKEY*) a);
    DSTU_KEY *second = EVP_PKEY_get0((EVP_PKEY*) b);

    if (!first || !second)
	return -2;

    /* We do not compare sboxes here because it will be done in params_cmp by EVP API */

    if (EC_POINT_cmp(EC_KEY_get0_group(first->ec),
	    EC_KEY_get0_public_key(first->ec),
	    EC_KEY_get0_public_key(second->ec), NULL))
	return 0;
    else
	return 1;
    }

static int dstu_asn1_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
    {
    switch (op)
	{
    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
	*((int *) arg2) = NID_dstu34311;
	return 2;
	}

    return 0;
    }

static int dstu_asn1_priv_print(BIO *out, const EVP_PKEY *pkey, int indent,
	ASN1_PCTX *pctx)
    {
    /* Reusing basic EC keys printing */
    DSTU_KEY *dstu_key = EVP_PKEY_get0((EVP_PKEY*) pkey);
    EVP_PKEY *pk;
    int ret;

    pk = EVP_PKEY_new();
    if (!pk || !EVP_PKEY_set1_EC_KEY(pk, dstu_key->ec))
	return 0;

    ret = EVP_PKEY_print_private(out, pk, indent, pctx);

    EVP_PKEY_free(pk);
    return ret;
    }

static int dstu_asn1_pub_print(BIO *out, const EVP_PKEY *pkey, int indent,
	ASN1_PCTX *pctx)
    {
    /* Reusing basic EC keys printing */
    DSTU_KEY *dstu_key = EVP_PKEY_get0((EVP_PKEY*) pkey);
    EVP_PKEY *pk;
    int ret;

    pk = EVP_PKEY_new();
    if (!pk || !EVP_PKEY_set1_EC_KEY(pk, dstu_key->ec))
	return 0;

    ret = EVP_PKEY_print_public(out, pk, indent, pctx);

    EVP_PKEY_free(pk);
    return ret;
    }

EVP_PKEY_ASN1_METHOD *dstu_asn1_meth_le = NULL, *dstu_asn1_meth_be = NULL;

int dstu_asn1_meth_init(void)
    {
    dstu_asn1_meth_le = EVP_PKEY_asn1_new(NID_dstu4145le, 0, SN_dstu4145le,
	    LN_dstu4145le);
    if (!dstu_asn1_meth_le)
	return 0;

    dstu_asn1_meth_be = EVP_PKEY_asn1_new(NID_dstu4145be, 0, SN_dstu4145be,
	    LN_dstu4145be);
    if (!dstu_asn1_meth_be)
	{
	EVP_PKEY_asn1_free(dstu_asn1_meth_le);
	dstu_asn1_meth_le = NULL;
	return 0;
	}

    /*if (!OBJ_add_sigid(dstu_nids[0], DSTU_MD_NID, dstu_nids[0]))
     {
     EVP_PKEY_asn1_free(dstu_asn1_meth_le);
     EVP_PKEY_asn1_free(dstu_asn1_meth_be);
     return 0;
     }

     if (!OBJ_add_sigid(dstu_nids[1], DSTU_MD_NID, dstu_nids[1]))
     {
     EVP_PKEY_asn1_free(dstu_asn1_meth_le);
     EVP_PKEY_asn1_free(dstu_asn1_meth_be);
     return 0;
     }*/

    EVP_PKEY_asn1_set_param(dstu_asn1_meth_le, dstu_asn1_param_decode,
	    dstu_asn1_param_encode, /*dstu_asn1_param_missing*/NULL,
	    dstu_asn1_param_copy, dstu_asn1_param_cmp, dstu_asn1_param_print);
    EVP_PKEY_asn1_set_private(dstu_asn1_meth_le, dstu_asn1_priv_decode,
	    dstu_asn1_priv_encode, dstu_asn1_priv_print);
    EVP_PKEY_asn1_set_public(dstu_asn1_meth_le, dstu_asn1_pub_decode,
	    dstu_asn1_pub_encode, dstu_asn1_pub_cmp, dstu_asn1_pub_print,
	    dstu_asn1_pkey_size, dstu_asn1_pkey_bits);
    EVP_PKEY_asn1_set_free(dstu_asn1_meth_le, dstu_asn1_pkey_free);
    EVP_PKEY_asn1_set_ctrl(dstu_asn1_meth_le, dstu_asn1_pkey_ctrl);

    EVP_PKEY_asn1_set_param(dstu_asn1_meth_be, dstu_asn1_param_decode,
	    dstu_asn1_param_encode, /*dstu_asn1_param_missing*/NULL,
	    dstu_asn1_param_copy, dstu_asn1_param_cmp, dstu_asn1_param_print);
    EVP_PKEY_asn1_set_private(dstu_asn1_meth_be, dstu_asn1_priv_decode,
	    dstu_asn1_priv_encode, dstu_asn1_priv_print);
    EVP_PKEY_asn1_set_public(dstu_asn1_meth_be, dstu_asn1_pub_decode,
	    dstu_asn1_pub_encode, dstu_asn1_pub_cmp, dstu_asn1_pub_print,
	    dstu_asn1_pkey_size, dstu_asn1_pkey_bits);
    EVP_PKEY_asn1_set_free(dstu_asn1_meth_be, dstu_asn1_pkey_free);
    EVP_PKEY_asn1_set_ctrl(dstu_asn1_meth_be, dstu_asn1_pkey_ctrl);

    return 1;
    }

void dstu_asn1_meth_finish(void)
    {
    if (dstu_asn1_meth_le)
	EVP_PKEY_asn1_free(dstu_asn1_meth_le);

    if (dstu_asn1_meth_be)
	EVP_PKEY_asn1_free(dstu_asn1_meth_be);
    }
