#ifndef BURN_H
#define BURN_H

#include <stddef.h>

#define NOINLINE	__attribute__((noinline))

NOINLINE void	burn(void *s, size_t n);

#endif
