/*
 * dstu_engine.c
 *
 *  Created on: Mar 4, 2013
 *      Author: ignat
 */

#include "dstu_engine.h"
#include "dstu_params.h"
#include <openssl/objects.h>

#include "e_dstu_err.h"

static const char *engine_dstu_id = "dstu";
static const char *engine_dstu_name = "Reference implementation of DSTU engine";

/* First is little-endian DSTU and second is big-endian DSTU*/
/*int dstu_nids[2];
 int DSTU_MD_NID = 0;
 int DSTU_CIPHER_NID = 0;

 static int create_dstu_nid()
 {
 int i;
 char curve_nid[] = "1.2.804.2.1.1.1.1.3.1.1.2.x";
 char curve_sn[] = "uacurvex";
 char curve_ln[] = "DSTU curve x";
 dstu_nids[0] = OBJ_create("1.2.804.2.1.1.1.1.3.1.1", "dstu4145le", "dstu4145 little endian");
 dstu_nids[1] = OBJ_create("1.2.804.2.1.1.1.1.3.1.1.1.1", "dstu4145be", "dstu4145 big endian");
 DSTU_MD_NID = OBJ_create("1.2.804.2.1.1.1.1.2.1", "gost34311", "GOST 34311-95");
 DSTU_CIPHER_NID = OBJ_create("1.2.804.2.1.1.1.1.1.1", "dstu28147", "DSTU GOST 28147:2009");

 for (i = 0; i < 10; i++)
 {
 curve_nid[sizeof(curve_nid) - 2] = (i + 0x30);
 curve_sn[sizeof(curve_sn) - 2] = (i + 0x30);
 curve_ln[sizeof(curve_ln) - 2] = (i + 0x30);

 dstu_curves[i].nid = OBJ_create(curve_nid, curve_sn, curve_ln);
 if (!dstu_curves[i].nid)
 return 0;
 }

 return dstu_nids[0] && dstu_nids[1] && DSTU_MD_NID && DSTU_CIPHER_NID;
 }*/

static int dstu_nids[] =
    {
    NID_dstu4145le, NID_dstu4145be
    };
static int digest_nids[] =
    {
    NID_dstu34311
    };
static int cipher_nids[] =
    {
    NID_dstu28147_cfb
    };

static const int DSTU_ENGINE_FLAGS = ENGINE_METHOD_PKEY_METHS
	| ENGINE_METHOD_PKEY_ASN1_METHS | ENGINE_METHOD_DIGESTS
	| ENGINE_METHOD_CIPHERS | ENGINE_METHOD_RAND;

static int dstu_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids,
	int nid)
    {
    if (!pmeth)
	{
	*nids = dstu_nids;
	return sizeof(dstu_nids) / sizeof(int);
	}

    if (dstu_nids[0] == nid)
	{
	*pmeth = dstu_pkey_meth_le;
	return 1;
	}

    if (dstu_nids[1] == nid)
	{
	*pmeth = dstu_pkey_meth_be;
	return 1;
	}

    *pmeth = NULL;
    return 0;
    }

static int dstu_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
	const int **nids, int nid)
    {
    if (!ameth)
	{
	*nids = dstu_nids;
	return sizeof(dstu_nids) / sizeof(int);
	}

    if (dstu_nids[0] == nid)
	{
	*ameth = dstu_asn1_meth_le;
	return 1;
	}

    if (dstu_nids[1] == nid)
	{
	*ameth = dstu_asn1_meth_be;
	return 1;
	}

    *ameth = NULL;
    return 0;
    }

static int dstu_engine_init(ENGINE *e)
    {
    return 1;
    }

static int dstu_engine_finish(ENGINE *e)
    {
    return 1;
    }

static int dstu_digests(ENGINE *e, const EVP_MD **digest, const int **nids,
	int nid)
    {
    if (digest && nid)
	{
	if (NID_dstu34311 == nid)
	    {
	    *digest = &dstu_md;
	    return 1;
	    }
	else
	    return 0;
	}
    else
	{
	if (!nids)
	    return -1;
	*nids = digest_nids;
	return 1;
	}
    }

static int dstu_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
	int nid)
    {
    if (cipher && nid)
	{
	if (NID_dstu28147_cfb == nid)
	    {
	    *cipher = &dstu_cipher;
	    return 1;
	    }
	else
	    return 0;
	}
    else
	{
	if (!nids)
	    return -1;
	*nids = cipher_nids;
	return 1;
	}
    }

static int bind_dstu(ENGINE *e, const char *id)
    {
    if (id && strcmp(id, engine_dstu_id))
	return 0;

    if (!ENGINE_set_id(e, engine_dstu_id))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	return 0;
	}
    if (!ENGINE_set_name(e, engine_dstu_name))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	return 0;
	}

    if (!ENGINE_set_init_function(e, dstu_engine_init))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	return 0;
	}
    if (!ENGINE_set_finish_function(e, dstu_engine_finish))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	return 0;
	}
    /* TODO: this will be useless for built-in engine */
    /*if (!create_dstu_nid())
     {
     printf("create_dstu_nid failed\n");
     return 0;
     }*/
    /* TODO: Move this to MD declaration, when we are built-in engine */
    //dstu_md.type = DSTU_MD_NID;
    //dstu_cipher.nid = DSTU_CIPHER_NID;
    //dstu_md.pkey_type = dstu_nids[0];
    if (!ENGINE_set_digests(e, dstu_digests))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	return 0;
	}
    if (!ENGINE_set_ciphers(e, dstu_ciphers))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	return 0;
	}
    if (!ENGINE_set_RAND(e, &dstu_rand_meth))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	return 0;
	}
    if (!dstu_pkey_meth_init())
	{
	DSTUerr(DSTU_F_BIND_DSTU, DSTU_R_PMETH_INIT_FAILED);
	return 0;
	}
    if (!dstu_asn1_meth_init())
	{
	DSTUerr(DSTU_F_BIND_DSTU, DSTU_R_AMETH_INIT_FAILED);
	dstu_pkey_meth_finish();
	return 0;
	}
    if (!ENGINE_set_pkey_meths(e, dstu_pkey_meths))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	dstu_asn1_meth_finish();
	dstu_pkey_meth_finish();
	return 0;
	}
    if (!ENGINE_set_pkey_asn1_meths(e, dstu_asn1_meths))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	dstu_asn1_meth_finish();
	dstu_pkey_meth_finish();
	return 0;
	}
    if (!ENGINE_set_flags(e, DSTU_ENGINE_FLAGS))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	dstu_asn1_meth_finish();
	dstu_pkey_meth_finish();
	return 0;
	}
    if (!ENGINE_register_pkey_meths(e))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	dstu_asn1_meth_finish();
	dstu_pkey_meth_finish();
	return 0;
	}
    if (!ENGINE_register_pkey_asn1_meths(e))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	dstu_asn1_meth_finish();
	dstu_pkey_meth_finish();
	return 0;
	}
    if (!ENGINE_register_digests(e))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	dstu_asn1_meth_finish();
	dstu_pkey_meth_finish();
	return 0;
	}
    if (!ENGINE_register_ciphers(e))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_ENGINE_LIB);
	dstu_asn1_meth_finish();
	dstu_pkey_meth_finish();
	return 0;
	}
    if (!EVP_add_digest(&dstu_md))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_EVP_LIB);
	dstu_asn1_meth_finish();
	dstu_pkey_meth_finish();
	return 0;
	}
    if (!EVP_add_cipher(&dstu_cipher))
	{
	DSTUerr(DSTU_F_BIND_DSTU, ERR_R_EVP_LIB);
	dstu_asn1_meth_finish();
	dstu_pkey_meth_finish();
	return 0;
	}

    ERR_load_DSTU_strings();
    return 1;
    }

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_BIND_FN(bind_dstu)
IMPLEMENT_DYNAMIC_CHECK_FN()
#endif  /* ndef OPENSSL_NO_DYNAMIC_ENGINE */

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_dstu(void)
    {
    ENGINE *ret = ENGINE_new();
    if (!ret)
	return NULL;
    if (!bind_dstu(ret, engine_dstu_id))
	{
	ENGINE_free(ret);
	return NULL;
	}
    return ret;
    }

void ENGINE_load_dstu(void)
    {
    ENGINE *toadd = engine_dstu();
    if (!toadd)
	return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
    }
#endif

