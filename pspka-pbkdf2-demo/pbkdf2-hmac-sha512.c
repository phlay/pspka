/* This module implements pbkdf2-hmac-sha512.
 *
 * Written by Philipp Lay <philipp.lay@illunis.net>
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <endian.h>

#include "utils.h"
#include "sha512.h"
#include "pbkdf2-hmac-sha512.h"



/* length of our hash function */
#define HLEN	SHA512_HASH_LENGTH

/* block size of the hash */
#define BS	SHA512_BLOCK_SIZE


/* padding */
#define IPAD	0x36
#define OPAD	0x5c


void
hmac_sha512_init(sha512ctx *ctx, const uint8_t key[BS])
{
	uint8_t pad[BS];
	int i;

	/* apply inner padding */
	for (i = 0; i < BS; i++)
		pad[i] = key[i] ^ IPAD;

	sha512_init(ctx);
	sha512_update(ctx, pad, BS);
}


void
hmac_sha512_done(sha512ctx *ctx, const uint8_t key[BS], uint8_t result[HLEN])
{
	uint8_t pad[BS];
	uint8_t ihash[HLEN];
	int i;

	/* construct outer padding */
	for (i = 0; i < BS; i++)
		pad[i] = key[i] ^ OPAD;

	/* finalize inner hash */
	sha512_done(ctx, ihash);

	sha512_init(ctx);
	sha512_update(ctx, pad, BS);
	sha512_update(ctx, ihash, HLEN);
	sha512_done(ctx, result);
}


void
pbkdf2_hmac_sha512(uint8_t *out, size_t outlen,
		   const uint8_t *passwd, size_t passlen,
		   const uint8_t *salt, size_t saltlen,
		   uint64_t iter)
{
	sha512ctx hmac, hmac_template;
	uint32_t i, be32i;
	uint64_t j;
	int k;

	uint8_t key[BS];
	uint8_t	F[HLEN], U[HLEN];
	size_t need;

	/*
	 * vartime code to handle password hmac-style
	 */
	if (passlen < BS) {
		memcpy(key, passwd, passlen);
		memset(key + passlen, 0, BS-passlen);
	} else {
		sha512_init(&hmac);
		sha512_update(&hmac, passwd, passlen);
		sha512_done(&hmac, key);
		memset(key + HLEN, 0, BS-HLEN);
	}

	hmac_sha512_init(&hmac_template, key);
	sha512_update(&hmac_template, salt, saltlen);

	for (i = 1; outlen > 0; i++) {
		memcpy(&hmac, &hmac_template, sizeof(sha512ctx));

		be32i = htobe32(i);
		sha512_update(&hmac, &be32i, sizeof(be32i));
		hmac_sha512_done(&hmac, key, U);
		memcpy(F, U, HLEN);

		for (j = 2; j <= iter; j++) {
			hmac_sha512_init(&hmac, key);
			sha512_update(&hmac, U, HLEN);
			hmac_sha512_done(&hmac, key, U);

			for (k = 0; k < HLEN; k++)
				F[k] ^= U[k];
		}

		need = MIN(HLEN, outlen);

		memcpy(out, F, need);
		out += need;
		outlen -= need;
	}
}
