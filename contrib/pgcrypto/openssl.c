/*
 * openssl.c
 *		Wrapper for OpenSSL library.
 *
 * Copyright (c) 2001 Marko Kreen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $PostgreSQL: pgsql/contrib/pgcrypto/openssl.c,v 1.33 2009/06/11 14:48:52 momjian Exp $
 */

#include "postgres.h"

#include "px.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif

/*
 * Max lengths we might want to handle.
 */
#define MAX_KEY		(512/8)
#define MAX_IV		(128/8)

/*
 * Compatibility with OpenSSL 0.9.6
 *
 * It needs AES and newer DES and digest API.
 */
#if OPENSSL_VERSION_NUMBER >= 0x00907000L

/*
 * Nothing needed for OpenSSL 0.9.7+
 */

#include <openssl/aes.h>
#else							/* old OPENSSL */

/*
 * Emulate OpenSSL AES.
 */

#include "rijndael.c"

#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#define AES_KEY		rijndael_ctx

/*
 * Emulate DES_* API
 */

#define DES_key_schedule des_key_schedule
#define DES_cblock des_cblock
#define DES_set_key(k, ks) \
		des_set_key((k), *(ks))
#define DES_ecb_encrypt(i, o, k, e) \
		des_ecb_encrypt((i), (o), *(k), (e))
#define DES_ncbc_encrypt(i, o, l, k, iv, e) \
		des_ncbc_encrypt((i), (o), (l), *(k), (iv), (e))
#define DES_ecb3_encrypt(i, o, k1, k2, k3, e) \
		des_ecb3_encrypt((des_cblock *)(i), (des_cblock *)(o), \
				*(k1), *(k2), *(k3), (e))
#define DES_ede3_cbc_encrypt(i, o, l, k1, k2, k3, iv, e) \
		des_ede3_cbc_encrypt((i), (o), \
				(l), *(k1), *(k2), *(k3), (iv), (e))

/*
 * Emulate newer digest API.
 */

static void
EVP_MD_CTX_init(EVP_MD_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

static int
EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx)
{
	px_memset(ctx, 0, sizeof(*ctx));
	return 1;
}

static int
EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *md, void *engine)
{
	EVP_DigestInit(ctx, md);
	return 1;
}

static int
EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *res, unsigned int *len)
{
	EVP_DigestFinal(ctx, res, len);
	return 1;
}
#endif   /* old OpenSSL */

/*
 * Provide SHA2 for older OpenSSL < 0.9.8
 */
#if OPENSSL_VERSION_NUMBER < 0x00908000L

#include "sha2.c"
#include "internal-sha2.c"

typedef void (*init_f) (PX_MD *md);

static int
compat_find_digest(const char *name, PX_MD **res)
{
	init_f		init = NULL;

	if (pg_strcasecmp(name, "sha224") == 0)
		init = init_sha224;
	else if (pg_strcasecmp(name, "sha256") == 0)
		init = init_sha256;
	else if (pg_strcasecmp(name, "sha384") == 0)
		init = init_sha384;
	else if (pg_strcasecmp(name, "sha512") == 0)
		init = init_sha512;
	else
		return PXE_NO_HASH;

	*res = px_alloc(sizeof(PX_MD));
	init(*res);
	return 0;
}
#else
#define compat_find_digest(name, res)  (PXE_NO_HASH)
#endif

/*
 * Fips mode
 */
static bool fips = false;

#define NOT_FIPS_CERTIFIED \
	if (fips) \
		ereport(ERROR, \
				(errmsg("requested functionality not allowed in FIPS mode")));

/*
 * Hashes
 */

typedef struct OSSLDigest
{
	const EVP_MD *algo;
	EVP_MD_CTX	ctx;
} OSSLDigest;

static unsigned
digest_result_size(PX_MD *h)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	return EVP_MD_CTX_size(&digest->ctx);
}

static unsigned
digest_block_size(PX_MD *h)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	return EVP_MD_CTX_block_size(&digest->ctx);
}

static void
digest_reset(PX_MD *h)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	EVP_DigestInit_ex(&digest->ctx, digest->algo, NULL);
}

static void
digest_update(PX_MD *h, const uint8 *data, unsigned dlen)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	EVP_DigestUpdate(&digest->ctx, data, dlen);
}

static void
digest_finish(PX_MD *h, uint8 *dst)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	EVP_DigestFinal_ex(&digest->ctx, dst, NULL);
}

static void
digest_free(PX_MD *h)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	EVP_MD_CTX_cleanup(&digest->ctx);

	px_free(digest);
	px_free(h);
}

static int	px_openssl_initialized = 0;

/* PUBLIC functions */

int
px_find_digest(const char *name, PX_MD **res)
{
	const EVP_MD *md;
	PX_MD	   *h;
	OSSLDigest *digest;

	if (!px_openssl_initialized)
	{
		px_openssl_initialized = 1;
		OpenSSL_add_all_algorithms();
	}

	md = EVP_get_digestbyname(name);
	if (md == NULL)
		return compat_find_digest(name, res);

	digest = px_alloc(sizeof(*digest));
	digest->algo = md;

	EVP_MD_CTX_init(&digest->ctx);
	if (EVP_DigestInit_ex(&digest->ctx, digest->algo, NULL) == 0)
		return -1;

	h = px_alloc(sizeof(*h));
	h->result_size = digest_result_size;
	h->block_size = digest_block_size;
	h->reset = digest_reset;
	h->update = digest_update;
	h->finish = digest_finish;
	h->free = digest_free;
	h->p.ptr = (void *) digest;

	*res = h;
	return 0;
}

/*
 * Ciphers
 *
 * We use OpenSSL's EVP* family of functions for these.
 */

/*
 * prototype for the EVP functions that return an algorithm, e.g.
 * EVP_aes_128_cbc().
 */
typedef const EVP_CIPHER *(*ossl_EVP_cipher_func)(void);

struct ossl_cipher
{
	int			(*init) (PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv);
	ossl_EVP_cipher_func cipher_func;
	int			block_size;
	int			max_key_size;
};

typedef struct
{
	EVP_CIPHER_CTX	evp_ctx;
	const EVP_CIPHER *evp_ciph;
	uint8		key[MAX_KEY];
	uint8		iv[MAX_IV];
	unsigned	klen;
	unsigned	init;
	const struct ossl_cipher *ciph;
} ossldata;

/* Common routines for all algorithms */

static unsigned
gen_ossl_block_size(PX_Cipher *c)
{
	ossldata   *od = (ossldata *) c->ptr;

	return od->ciph->block_size;
}

static unsigned
gen_ossl_key_size(PX_Cipher *c)
{
	ossldata   *od = (ossldata *) c->ptr;

	return od->ciph->max_key_size;
}

static unsigned
gen_ossl_iv_size(PX_Cipher *c)
{
	unsigned	ivlen;
	ossldata   *od = (ossldata *) c->ptr;

	ivlen = od->ciph->block_size;
	return ivlen;
}

static void
gen_ossl_free(PX_Cipher *c)
{
	ossldata   *od = (ossldata *) c->ptr;

	EVP_CIPHER_CTX_cleanup(&od->evp_ctx);
	px_memset(od, 0, sizeof(*od));
	px_free(od);
	px_free(c);
}

static int
gen_ossl_decrypt(PX_Cipher *c, const uint8 *data, unsigned dlen,
				 uint8 *res)
{
	ossldata   *od = c->ptr;
	int			outlen;

	if (!od->init)
	{
		EVP_CIPHER_CTX_init(&od->evp_ctx);
		if (!EVP_DecryptInit_ex(&od->evp_ctx, od->evp_ciph, NULL, NULL, NULL))
			return PXE_CIPHER_INIT;
		if (!EVP_CIPHER_CTX_set_key_length(&od->evp_ctx, od->klen))
			return PXE_CIPHER_INIT;
		if (!EVP_DecryptInit_ex(&od->evp_ctx, NULL, NULL, od->key, od->iv))
			return PXE_CIPHER_INIT;
		od->init = true;
	}

	if (!EVP_DecryptUpdate(&od->evp_ctx, res, &outlen, data, dlen))
		return PXE_DECRYPT_FAILED;

	return 0;
}

static int
gen_ossl_encrypt(PX_Cipher *c, const uint8 *data, unsigned dlen,
				 uint8 *res)
{
	ossldata   *od = c->ptr;
	int			outlen;

	if (!od->init)
	{
		EVP_CIPHER_CTX_init(&od->evp_ctx);
		if (!EVP_EncryptInit_ex(&od->evp_ctx, od->evp_ciph, NULL, NULL, NULL))
			return PXE_CIPHER_INIT;
		if (!EVP_CIPHER_CTX_set_key_length(&od->evp_ctx, od->klen))
			return PXE_CIPHER_INIT;
		if (!EVP_EncryptInit_ex(&od->evp_ctx, NULL, NULL, od->key, od->iv))
			return PXE_CIPHER_INIT;
		od->init = true;
	}

	if (!EVP_EncryptUpdate(&od->evp_ctx, res, &outlen, data, dlen))
		return PXE_ERR_GENERIC;

	return 0;
}

/* Blowfish */

/*
 * Check if strong crypto is supported. Some openssl installations
 * support only short keys and unfortunately BF_set_key does not return any
 * error value. This function tests if is possible to use strong key.
 */
static int
bf_check_supported_key_len(void)
{
	static const uint8 key[56] = {
		0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69,
		0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f, 0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77, 0x04, 0x68, 0x91, 0x04, 0xc2, 0xfd,
		0x3b, 0x2f, 0x58, 0x40, 0x23, 0x64, 0x1a, 0xba, 0x61, 0x76,
		0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	static const uint8 data[8] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	static const uint8 res[8] = {0xc0, 0x45, 0x04, 0x01, 0x2e, 0x4e, 0x1f, 0x53};
	uint8		out[8];
	EVP_CIPHER_CTX	evp_ctx;
	int			outlen;

	/* encrypt with 448bits key and verify output */
	EVP_CIPHER_CTX_init(&evp_ctx);
	if (!EVP_EncryptInit_ex(&evp_ctx, EVP_bf_ecb(), NULL, NULL, NULL))
		return 0;
	if (!EVP_CIPHER_CTX_set_key_length(&evp_ctx, 56))
		return 0;
	if (!EVP_EncryptInit_ex(&evp_ctx, NULL, NULL, key, NULL))
		return 0;

	if (!EVP_EncryptUpdate(&evp_ctx, out, &outlen, data, 8))
		return 0;

	if (memcmp(out, res, 8) != 0)
		return 0;				/* Output does not match -> strong cipher is
								 * not supported */
	return 1;
}

static int
bf_init(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv)
{
	ossldata   *od = c->ptr;
	unsigned	bs = gen_ossl_block_size(c);
	static int	bf_is_strong = -1;

	/*
	 * Test if key len is supported. BF_set_key silently cut large keys and it
	 * could be be a problem when user transfer crypted data from one server
	 * to another.
	 */

	if (bf_is_strong == -1)
		bf_is_strong = bf_check_supported_key_len();

	if (!bf_is_strong && klen > 16)
		return PXE_KEY_TOO_BIG;

	/* Key len is supported. We can use it. */
	od->klen = klen;
	memcpy(od->key, key, klen);

	if (iv)
		memcpy(od->iv, iv, bs);
	else
		memset(od->iv, 0, bs);
	return 0;
}

/* DES */

static int
ossl_des_init(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv)
{
	ossldata   *od = c->ptr;
	unsigned	bs = gen_ossl_block_size(c);

	od->klen = 8;
	memset(od->key, 0, 8);
	memcpy(od->key, key, klen > 8 ? 8 : klen);

	if (iv)
		memcpy(od->iv, iv, bs);
	else
		memset(od->iv, 0, bs);
	return 0;
}

/* DES3 */

static int
ossl_des3_init(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv)
{
	ossldata   *od = c->ptr;
	unsigned	bs = gen_ossl_block_size(c);

	od->klen = 24;
	memset(od->key, 0, 24);
	memcpy(od->key, key, klen > 24 ? 24 : klen);

	if (iv)
		memcpy(od->iv, iv, bs);
	else
		memset(od->iv, 0, bs);
	return 0;
}

/* CAST5 */

static int
ossl_cast_init(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv)
{
	ossldata   *od = c->ptr;
	unsigned	bs = gen_ossl_block_size(c);

	od->klen = klen;
	memcpy(od->key, key, klen);

	if (iv)
		memcpy(od->iv, iv, bs);
	else
		memset(od->iv, 0, bs);
	return 0;
}

/* AES */

static int
ossl_aes_init(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv)
{
	ossldata   *od = c->ptr;
	unsigned	bs = gen_ossl_block_size(c);

	if (klen <= 128 / 8)
		od->klen = 128 / 8;
	else if (klen <= 192 / 8)
		od->klen = 192 / 8;
	else if (klen <= 256 / 8)
		od->klen = 256 / 8;
	else
		return PXE_KEY_TOO_BIG;

	memcpy(od->key, key, klen);

	if (iv)
		memcpy(od->iv, iv, bs);
	else
		memset(od->iv, 0, bs);

	return 0;
}

static int
ossl_aes_ecb_init(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv)
{
	ossldata   *od = c->ptr;
	int			err;

	err = ossl_aes_init(c, key, klen, iv);
	if (err)
		return err;

	switch (od->klen)
	{
		case 128 / 8:
			od->evp_ciph = EVP_aes_128_ecb();
			break;
		case 192 / 8:
			od->evp_ciph = EVP_aes_192_ecb();
			break;
		case 256 / 8:
			od->evp_ciph = EVP_aes_256_ecb();
			break;
		default:
			/* shouldn't happen */
			err = PXE_CIPHER_INIT;
			break;
	}

	return err;
}

static int
ossl_aes_cbc_init(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv)
{
	ossldata   *od = c->ptr;
	int			err;

	err = ossl_aes_init(c, key, klen, iv);
	if (err)
		return err;

	switch (od->klen)
	{
		case 128 / 8:
			od->evp_ciph = EVP_aes_128_cbc();
			break;
		case 192 / 8:
			od->evp_ciph = EVP_aes_192_cbc();
			break;
		case 256 / 8:
			od->evp_ciph = EVP_aes_256_cbc();
			break;
		default:
			/* shouldn't happen */
			err = PXE_CIPHER_INIT;
			break;
	}

	return err;
}

/*
 * aliases
 */

static PX_Alias ossl_aliases_all[] = {
	{"bf", "bf-cbc"},
	{"blowfish", "bf-cbc"},
	{"blowfish-cbc", "bf-cbc"},
	{"blowfish-ecb", "bf-ecb"},
	{"blowfish-cfb", "bf-cfb"},
	{"des", "des-cbc"},
	{"3des", "des3-cbc"},
	{"3des-ecb", "des3-ecb"},
	{"3des-cbc", "des3-cbc"},
	{"cast5", "cast5-cbc"},
	{"aes", "aes-cbc"},
	{"rijndael", "aes-cbc"},
	{"rijndael-cbc", "aes-cbc"},
	{"rijndael-ecb", "aes-ecb"},
	{NULL}
};

static PX_Alias ossl_aliases_fips[] = {
	{"des", "des-cbc"},
	{"3des", "des3-cbc"},
	{"3des-ecb", "des3-ecb"},
	{"3des-cbc", "des3-cbc"},
	{"aes", "aes-cbc"},
	{NULL}
};

static PX_Alias *ossl_aliases = ossl_aliases_all;

static const struct ossl_cipher ossl_bf_cbc = {
	bf_init,
	EVP_bf_cbc,
	64 / 8, 448 / 8
};

static const struct ossl_cipher ossl_bf_ecb = {
	bf_init,
	EVP_bf_ecb,
	64 / 8, 448 / 8
};

static const struct ossl_cipher ossl_bf_cfb = {
	bf_init,
	EVP_bf_cfb,
	64 / 8, 448 / 8
};

static const struct ossl_cipher ossl_des_ecb = {
	ossl_des_init,
	EVP_des_ecb,
	64 / 8, 64 / 8
};

static const struct ossl_cipher ossl_des_cbc = {
	ossl_des_init,
	EVP_des_cbc,
	64 / 8, 64 / 8
};

static const struct ossl_cipher ossl_des3_ecb = {
	ossl_des3_init,
	EVP_des_ede3_ecb,
	64 / 8, 192 / 8
};

static const struct ossl_cipher ossl_des3_cbc = {
	ossl_des3_init,
	EVP_des_ede3_cbc,
	64 / 8, 192 / 8
};

static const struct ossl_cipher ossl_cast_ecb = {
	ossl_cast_init,
	EVP_cast5_ecb,
	64 / 8, 128 / 8
};

static const struct ossl_cipher ossl_cast_cbc = {
	ossl_cast_init,
	EVP_cast5_cbc,
	64 / 8, 128 / 8
};

static const struct ossl_cipher ossl_aes_ecb = {
	ossl_aes_ecb_init,
	NULL, /* EVP_aes_XXX_ecb(), determined in init function */
	128 / 8, 256 / 8
};

static const struct ossl_cipher ossl_aes_cbc = {
	ossl_aes_cbc_init,
	NULL, /* EVP_aes_XXX_cbc(), determined in init function */
	128 / 8, 256 / 8
};

/*
 * Special handlers
 */
struct ossl_cipher_lookup
{
	const char *name;
	const struct ossl_cipher *ciph;
};

static const struct ossl_cipher_lookup ossl_cipher_types_all[] = {
	{"bf-cbc", &ossl_bf_cbc},
	{"bf-ecb", &ossl_bf_ecb},
	{"bf-cfb", &ossl_bf_cfb},
	{"des-ecb", &ossl_des_ecb},
	{"des-cbc", &ossl_des_cbc},
	{"des3-ecb", &ossl_des3_ecb},
	{"des3-cbc", &ossl_des3_cbc},
	{"cast5-ecb", &ossl_cast_ecb},
	{"cast5-cbc", &ossl_cast_cbc},
	{"aes-ecb", &ossl_aes_ecb},
	{"aes-cbc", &ossl_aes_cbc},
	{NULL}
};

static const struct ossl_cipher_lookup ossl_cipher_types_fips[] = {
	{"des-ecb", &ossl_des_ecb},
	{"des-cbc", &ossl_des_cbc},
	{"des3-ecb", &ossl_des3_ecb},
	{"des3-cbc", &ossl_des3_cbc},
	{"aes-ecb", &ossl_aes_ecb},
	{"aes-cbc", &ossl_aes_cbc},
	{NULL}
};

static const struct ossl_cipher_lookup *ossl_cipher_types = ossl_cipher_types_all;

/* PUBLIC functions */

int
px_find_cipher(const char *name, PX_Cipher **res)
{
	const struct ossl_cipher_lookup *i;
	PX_Cipher  *c = NULL;
	ossldata   *od;

	name = px_resolve_alias(ossl_aliases, name);
	for (i = ossl_cipher_types; i->name; i++)
		if (!strcmp(i->name, name))
			break;
	if (i->name == NULL)
		NOT_FIPS_CERTIFIED
	if (i->name == NULL)
		return PXE_NO_CIPHER;

	od = px_alloc(sizeof(*od));
	memset(od, 0, sizeof(*od));
	od->ciph = i->ciph;

	if (i->ciph->cipher_func)
		od->evp_ciph = i->ciph->cipher_func();

	c = px_alloc(sizeof(*c));
	c->block_size = gen_ossl_block_size;
	c->key_size = gen_ossl_key_size;
	c->iv_size = gen_ossl_iv_size;
	c->free = gen_ossl_free;
	c->init = od->ciph->init;
	c->encrypt = gen_ossl_encrypt;
	c->decrypt = gen_ossl_decrypt;
	c->ptr = od;

	*res = c;
	return 0;
}


static int	openssl_random_init = 0;

/*
 * OpenSSL random should re-feeded occasionally. From /dev/urandom
 * preferably.
 */
static void
init_openssl_rand(void)
{
	if (RAND_get_rand_method() == NULL)
		RAND_set_rand_method(RAND_SSLeay());
	openssl_random_init = 1;
}

int
px_get_random_bytes(uint8 *dst, unsigned count)
{
	int			res;

	if (!openssl_random_init)
		init_openssl_rand();

	res = RAND_bytes(dst, count);
	if (res == 1)
		return count;

	return PXE_OSSL_RAND_ERROR;
}

int
px_get_pseudo_random_bytes(uint8 *dst, unsigned count)
{
	int			res;

	if (!openssl_random_init)
		init_openssl_rand();

	res = RAND_pseudo_bytes(dst, count);
	if (res == 0 || res == 1)
		return count;

	return PXE_OSSL_RAND_ERROR;
}

int
px_add_entropy(const uint8 *data, unsigned count)
{
	/*
	 * estimate 0 bits
	 */
	RAND_add(data, count, 0);
	return 0;
}

void
px_disable_fipsmode(void)
{
#ifndef OPENSSL_FIPS
	/*
	 * If this build doesn't support FIPS mode at all, we shouldn't be able
	 * to reach this point, so Assert that and return to handle production
	 * builds gracefully.
	 */
	Assert(!fips);
#else
	ossl_aliases = ossl_aliases_all;
	ossl_cipher_types = ossl_cipher_types_all;
	fips = false;

	if (!FIPS_mode_set)
		return;

	FIPS_mode_set(0);
#endif

	return;
}

void
px_enable_fipsmode(void)
{
#ifndef OPENSSL_FIPS
	ereport(ERROR,
			(errmsg("FIPS enabled OpenSSL is required for strict FIPS mode"),
			 errhint("Recompile OpenSSL with the FIPS module, or install a FIPS enabled OpenSSL distribution.")));
#else

	ossl_aliases = ossl_aliases_fips;
	ossl_cipher_types = ossl_cipher_types_fips;

	/* Make sure that we are linked against a FIPS enabled OpenSSL */
	if (!FIPS_mode_set)
	{
		ereport(ERROR,
				(errmsg("FIPS enabled OpenSSL is required for strict FIPS mode"),
				 errhint("Recompile OpenSSL with the FIPS module, or install a FIPS enabled OpenSSL distribution.")));
	}

	/*
	 * A non-zero return value means that FIPS mode was enabled, but the
	 * full range of possible non-zero return values is not documented so
	 * rather than checking for success we check for failure.
	 */
	if (FIPS_mode_set(1) == 0)
	{
		char		errbuf[128];

		ERR_load_crypto_strings();
		ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
		ERR_free_strings();

		ereport(ERROR,
				(errmsg("unable to enable FIPS mode: %lx, %s",
						ERR_get_error(), errbuf)));
	}

	fips = true;
#endif
}
