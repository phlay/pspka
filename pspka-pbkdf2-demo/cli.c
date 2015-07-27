#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <err.h>

#include "utils.h"
#include "readpass.h"
#include "pspka-pbkdf2.h"

#define ITERATIONS	128000
#define PASSWD_SRC	"/dev/tty"
#define PASSWD_LEN	512
#define SALT_LEN	16


char	*myname;


void
printusage()
{
	fprintf(stderr, "usage: %s -g [-i <iter>] [-s <salt>] <ident>\n", myname);
	fprintf(stderr, "usage: %s <ident> <context> <challenge>\n", myname);
}

int main(int argc, char *argv[])
{
	int		 opt_verbose = 0;
	bool		 opt_generate = false;
	uint64_t	 opt_iter = ITERATIONS;
	char		*opt_salt = NULL;

	uint8_t		 passwd[PASSWD_LEN];
	int		 passlen;

	int n;

	myname = strdup(basename(argv[0]));

	while ((n = getopt(argc, argv, "vgi:s:h")) != -1) {
		switch (n) {
		case 'v':
			opt_verbose++;
			break;
		case 'g':
			opt_generate = true;
			break;

		case 'i':
			opt_iter = atoll(optarg);
			break;

		case 's':
			opt_salt = optarg;
			break;

		case 'h':
			printusage();
			exit(0);
			break;

		default:
			printusage();
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;


	if (opt_generate) {
		uint8_t edp[56];
		char edphash[B64LEN(sizeof(edp))];

		if (argc < 1) {
			printusage();
			exit(1);
		}
		char *ident = argv[0];


		if (opt_salt) {
			size_t m = fromhex(edp, SALT_LEN, opt_salt);
			if (m == SIZE_MAX)
				errx(1, "can't read salt: illegal hex string: %s",
						opt_salt);
			if (m > SALT_LEN)
				warnx("given salt too long, truncating to first %d bytes",
						SALT_LEN);
			if (m < SALT_LEN) {
				warnx("salt too short, will be filled with zeros");
				memset(edp+m, 0, SALT_LEN-m);
			}

		} else if (!secrand(edp, SALT_LEN))
			err(1, "can't read random data for salt");


		passlen = read_pass_fn(PASSWD_SRC, passwd, sizeof(passwd),
				"Password: ", "Confirm: ");
		if (passlen == -1)
			exit(1);


		if (opt_verbose > 0) {
			fprintf(stderr, "identity: %s\n", ident);
			fprintf(stderr, "iter: %lu\n", opt_iter);	/* XXX */
			fprintf(stderr, "salt: ");
			printhex(stderr, edp, SALT_LEN);
		}

		pspka_pbkdf2_gen(edp, ident, passwd, passlen, opt_iter);

		if (opt_verbose > 1) {
			fprintf(stderr, "edp: ");
			printhex(stderr, edp, sizeof(edp));
		}

		/* convert to base64 and print */
		base64enc(edphash, edp, sizeof(edp));
		fputs(edphash, stdout);
		fputc('\n', stdout);

	} else {
		uint8_t sig[80];
		char b64sig[B64LEN(sizeof(sig))];
		uint8_t chal[40];

		
		if (argc < 3) {
			printusage();
			exit(1);
		}

		char *ident = argv[0];
		char *context = argv[1];
		char *b64chal = argv[2];


		if (base64dec(chal, sizeof(chal), b64chal) != sizeof(chal))
			errx(1, "incorrect challenge size");

		if (!secrand(sig, 16))
			err(1, "can't read random data");

		if (opt_verbose > 0) {
			fprintf(stderr, "identity: %s\n", ident);

			fprintf(stderr, "context: %s\n", context);

			fprintf(stderr, "challenge: ");
			printhex(stderr, chal, sizeof(chal));

			fprintf(stderr, "rB: ");
			printhex(stderr, sig, 16);
		}


		passlen = read_pass_fn(PASSWD_SRC, passwd, sizeof(passwd),
				"Password: ", NULL);
		if (passlen == -1)
			exit(1);

		pspka_pbkdf2_sign(sig, chal, (uint8_t*)context, strlen(context), ident, passwd, passlen);

		if (opt_verbose > 1) {
			fprintf(stderr, "sig: ");
			printhex(stderr, sig, sizeof(sig));
		}

		/* print signature as base64 */
		base64enc(b64sig, sig, sizeof(sig));
		fputs(b64sig, stdout);
		fputc('\n', stdout);
	}

	return 0;
}
