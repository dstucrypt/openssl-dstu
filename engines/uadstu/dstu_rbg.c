/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

#include "dstu_engine.h"
#include "dstu_params.h"
#include "../ccgost/gost89.h"
#include <time.h>

static u4 I[2];
static u4 s[2];
static gost_ctx cryptor;
static int initialized = 0;

/* DSTU RGB needs at least 40 bytes of seed to work properly */
#define DSTU_RGB_SEED_SIZE 40

/* We will reuse OPENSSL's default seeding logic and entropy collecting and will use its default RNG as a seeder */
static int dstu_rbg_add(const void *buf, int num, double entropy)
    {
    return RAND_SSLeay()->add(buf, num, entropy);
    }

static int dstu_rbg_seed(const void *buf, int num)
    {
    return RAND_SSLeay()->seed(buf, num);
    }

static int dstu_rbg_init(void)
    {
    /* Since time can be 32-bit or 64-bit we will use byte array for time which is always 64-bit */
    /* For 32-bit time "garbage" in rest of the bytes will even help with seeding */
    byte curr[8];
    gost_subst_block sbox;
    unsigned char seed[DSTU_RGB_SEED_SIZE];

    if (!RAND_SSLeay()->bytes(seed, DSTU_RGB_SEED_SIZE))
	return 0;

    time((time_t*) curr);
    unpack_sbox(default_sbox, &sbox);

    gost_init(&cryptor, &sbox);
    gost_key(&cryptor, seed);
    memcpy(s, seed + 32, 8);
    gostcrypt(&cryptor, curr, (byte*) I);
    initialized = 1;

    OPENSSL_cleanse(seed, sizeof(seed));
    return 1;
    }

/* DSTU RBG is bit oriented. It gives one bit at a time */
static byte dstu_rbg_get_bit(void)
    {
    u4 x[2];

    x[0] = I[0] ^ s[0];
    x[1] = I[1] ^ s[1];
    gostcrypt(&cryptor, (byte*) x, (byte*) x);

    s[0] = x[0] ^ I[0];
    s[1] = x[1] ^ I[1];
    gostcrypt(&cryptor, (byte*) s, (byte*) s);

    return (byte) (x[0] & 1);
    }

static int dstu_rbg_status(void)
    {
    int status = RAND_SSLeay()->status();

    CRYPTO_w_lock(CRYPTO_LOCK_RAND);

    if (status && !initialized)
	{
	if (dstu_rbg_init())
	    {
	    initialized = 1;
	    status = initialized;
	    }
	else
	    status = 0;
	}

    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

    return status;
    }

static int dstu_rbg_bytes(unsigned char *buf, int num)
    {
    u4 i;
    byte j;
    int rv = 1;

    CRYPTO_w_lock(CRYPTO_LOCK_RAND);

    if (!initialized)
	{
	if (!dstu_rbg_status())
	    rv = 0;
	}

    for (i = 0; i < num; i++)
	{
	*(buf + i) = 0;
	for (j = 0; j < 8; j++)
	    {
	    *(buf + i) |= dstu_rbg_get_bit() << j;
	    }
	}

    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

    return rv;
    }

static void dstu_rbg_cleanup(void)
    {
    CRYPTO_w_lock(CRYPTO_LOCK_RAND);

    OPENSSL_cleanse(I, sizeof(I));
    OPENSSL_cleanse(s, sizeof(s));
    OPENSSL_cleanse(&cryptor, sizeof(gost_ctx));
    initialized = 0;

    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
    }

RAND_METHOD dstu_rand_meth =
    {
	    dstu_rbg_seed,
	    dstu_rbg_bytes,
	    dstu_rbg_cleanup,
	    dstu_rbg_add,
	    dstu_rbg_bytes,
	    dstu_rbg_status,
    };
