#include <stdint.h>
#include <stddef.h>

#include "burn.h"

/*
 * burn - simple function to zero a buffer, used to cover our tracks
 */
NOINLINE void
burn(void *s, size_t n)
{
	uint8_t *p = (uint8_t *)s;
	uint8_t *end = p+n;

	while (p < end) *p++ = 0;
}
