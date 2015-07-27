#ifndef CLEANUP_H
#define CLEANUP_H

#include <stdio.h>

#define do_cleanup(x)	__attribute__((cleanup(x)))

#define cu_free		do_cleanup(cleanup_free)
#define cu_fclose	do_cleanup(cleanup_fclose)

void	cleanup_free(void **ptr);
void	cleanup_fclose(FILE **stream);

#endif
