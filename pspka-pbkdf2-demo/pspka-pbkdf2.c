#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <eddsa.h>

#include "pbkdf2-hmac-sha512.h"
#include "burn.h"

void
pspka_pbkdf2_gen(uint8_t edp[56], const char *ident, const uint8_t *passwd, size_t passlen, uint64_t iter)
{
	/* copy ident + '\0' + passwd to buffer */
	const size_t idlen = strlen(ident);
	uint8_t idpass[idlen + 1 + passlen];
	memcpy(idpass, ident, idlen+1);
	memcpy(idpass+idlen+1, passwd, passlen);

	/* derive secret key with pbkdf2, first 16byte of edp are random used as salt */
	uint8_t sk[32];
	pbkdf2_hmac_sha512(sk, sizeof(sk), idpass, sizeof(idpass), edp, 16, iter);

	/* write iter as uint64-le to edp[16..23] */
	for (int i = 0; i < 8; i++) {
		edp[16+i] = iter & 0xff;
		iter >>= 8;
	}

	/* write public key to edp[24..55] */
	eddsa_genpub(edp+24, sk);

	/* cleanup */
	burn(idpass, sizeof(idpass));
	burn(sk, 32);
}

void
pspka_pbkdf2_chal(uint8_t chal[40], const uint8_t edp[56])
{
	/* copy salt & iter from edp to challenge */
	memcpy(chal+16, edp, 16+8);
}

void
pspka_pbkdf2_sign(uint8_t sig[80],
	  const uint8_t chal[40], const uint8_t *ctx, size_t ctxlen,
	  const char *ident, const uint8_t *passwd, size_t passlen)
{
	/* read iter from chal[32..39] encoded in litle-endian */
	uint64_t iter = 0;
	for (int i = 7; i >= 0; i--) {
		iter <<= 8;
		iter |= chal[32+i];
	}

	/* derive secret key from identity + '\0' + password */
	const size_t idlen = strlen(ident);
	uint8_t idpass[idlen + 1 + passlen];
	memcpy(idpass, ident, idlen+1);
	memcpy(idpass+idlen+1, passwd, passlen);

	uint8_t sk[32];
	pbkdf2_hmac_sha512(sk, sizeof(sk), idpass, sizeof(idpass), chal+16, 16, iter);

	/* derive public key */
	uint8_t pk[32];
	eddsa_genpub(pk, sk);

	/* prepare buffer with stuff to sign */
	uint8_t buf[16 + 16 + ctxlen];
	
	/* copy rA from challenge */
	memcpy(buf, chal, 16);
	/* copy rB from signature */
	memcpy(buf+16, sig, 16);
	/* copy context */
	memcpy(buf+32, ctx, ctxlen);

	/* create signature */
	eddsa_sign(sig+16, sk, pk, buf, sizeof(buf));

	/* cleanup */
	burn(idpass, sizeof(idpass));
	burn(sk, 32);
}

bool
pspka_pbkdf2_check(const uint8_t sig[80],
	   const uint8_t chal[40], const uint8_t *ctx, size_t ctxlen,
	   const uint8_t edp[48])
{
	uint8_t buf[16+16+ctxlen];

	/* copy rA from challenge */
	memcpy(buf, chal, 16);
	/* copy rB from signature */
	memcpy(buf+16, sig, 16);
	/* copy context */
	memcpy(buf+32, ctx, ctxlen);

	/* verify signature */
	return eddsa_verify(sig+16, edp+24, buf, sizeof(buf));
}
