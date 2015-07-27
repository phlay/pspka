#ifndef READPASS_H
#define READPASS_H

#include <stdio.h>
#include <stdint.h>

int	read_pass(FILE *fp, uint8_t *passwd, size_t max, const char *promptA,
		  const char *promptB);
int	read_pass_fn(const char *fn, uint8_t *passwd, size_t max,
		const char *promptA, const char *promptB);

#endif
