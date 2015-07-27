#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <err.h>

#include "utils.h"
#include "pspka-pbkdf2.h"

char	*myname;

void
printusage()
{
	fprintf(stderr, "usage: %s -g <hash>\n", myname);
	fprintf(stderr, "usage: %s <context> <chal> <sig> <hash>\n", myname);
}


int main(int argc, char *argv[])
{
	bool	 opt_generate = false;
	int	 opt_verbose = 0;

	int n;

	myname = strdup(basename(argv[0]));

	while ((n = getopt(argc, argv, "hvg")) != -1) {
		switch (n) {
		case 'h':
			printusage();
			exit(0);
			break;
		case 'v':
			opt_verbose++;
			break;
		case 'g':
			opt_generate = true;
			break;

		default:
			printusage();
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (opt_generate) {
		uint8_t chal[40], edp[56];
		char b64chal[B64LEN(sizeof(chal))];

		if (argc < 1) {
			printusage();
			exit(1);
		}
		char *b64edp = argv[0];


		if (base64dec(edp, sizeof(edp), b64edp) != sizeof(edp))
			errx(1, "edp hash has incorrect size");

		/* generate random for challenge */
		if (!secrand(chal, 16))
			err(1, "can't read random for challenge");

		if (opt_verbose > 0) {
			fprintf(stderr, "edp: ");
			printhex(stderr, edp, sizeof(edp));

			fprintf(stderr, "rA: ");
			printhex(stderr, chal, 16);
		}

		pspka_pbkdf2_chal(chal, edp);

		if (opt_verbose > 1) {
			fprintf(stderr, "challenge: ");
			printhex(stderr, chal, sizeof(chal));
		}

		base64enc(b64chal, chal, sizeof(chal));
		fputs(b64chal, stdout);
		fputc('\n', stdout);

	} else {
		uint8_t sig[80], chal[40], edp[56];

		if (argc < 4) {
			printusage();
			exit(1);
		}
		char *context = argv[0];
		char *b64chal = argv[1];
		char *b64sig = argv[2];
		char *b64edp = argv[3];


		if (base64dec(sig, sizeof(sig), b64sig) != sizeof(sig))
			errx(1, "signature has incorrect size");

		if (base64dec(edp, sizeof(edp), b64edp) != sizeof(edp))
			errx(1, "edp hash has incorrect size");

		if (base64dec(chal, sizeof(chal), b64chal) != sizeof(chal))
			errx(1, "challenge has incorrect size");

		if (opt_verbose > 0) {
			fprintf(stderr, "sig: ");
			printhex(stderr, sig, sizeof(sig));

			fprintf(stderr, "chal: ");
			printhex(stderr, chal, sizeof(chal));

			fprintf(stderr, "edp: ");
			printhex(stderr, edp, sizeof(edp));

			fprintf(stderr, "context: %s\n", context);
		}


		if (pspka_pbkdf2_check(sig, chal, (uint8_t*)context, strlen(context), edp))
			printf("ok\n");
		else {
			printf("FAIL\n");
			exit(1);
		}
	}


	return 0;
}
