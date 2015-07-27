#ifndef ECPV_H
#define ECPV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void	pspka_pbkdf2_gen(uint8_t edp[56], const char *ident,
			 const uint8_t *passwd, size_t passlen, uint64_t iter);

void	pspka_pbkdf2_chal(uint8_t chal[40], const uint8_t edp[56]);

void	pspka_pbkdf2_sign(uint8_t sig[80],
			  const uint8_t chal[40], const uint8_t *ctx, size_t ctxlen,
			  const char *ident, const uint8_t *passwd, size_t passlen);

bool	pspka_pbkdf2_check(const uint8_t sig[80],
			   const uint8_t chal[40], const uint8_t *ctx, size_t ctxlen,
			   const uint8_t edp[48]);

#endif
