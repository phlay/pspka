#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include <err.h>

#include "utils.h"
#include "cleanup.h"


/*
 * terminal code for read_pass
 */

struct terminal {
	int		 fd;
	int		 istty;
	struct termios	 orig_setup;
};

#define cu_resetterm	do_cleanup(reset_terminal)

static int
setup_terminal(struct terminal *term, FILE *stream)
{
	struct termios setup;

	term->fd = fileno(stream);
	term->istty = isatty(term->fd);

	if (term->istty) {
		if (tcgetattr(term->fd, &setup) == -1) {
			warn("can't read terminal attributes");
			return -1;
		}

		memcpy(&term->orig_setup, &setup, sizeof(struct termios));

		setup.c_lflag &= ~ECHO;
		setup.c_lflag |= ECHONL;

		if (tcsetattr(term->fd, TCSANOW, &setup) == -1) {
			warn("can't write terminal attributes");
			return -1;
		}
	}

	return 0;
}

static void
reset_terminal(struct terminal *term)
{
	/* just restore terminal setup if it is a tty */
	if (term->istty)
		tcsetattr(term->fd, TCSANOW, &term->orig_setup);
	/* XXX better use TCSAFLUSH? */
}



/*
 * read_line - reads a hole line (i.e until '\n' or EOF is reached)
 * and stores the first max bytes of it into the line buffer. the
 * newline itself is not stored.
 *
 * the line buffer is NOT zero terminated, but instead padded to max
 * bytes with one binary 1 and as much zeros as needed.
 *
 * the length of the original line (without padding but including the
 * cut-off part) is returned, so the caller can check for truncation.
 */
static int
read_line(uint8_t *out, size_t max, FILE *stream)
{
	int count, ch;

	for (count = 0; ; count++) {
		ch = fgetc(stream);
		if (ch == EOF || ch == '\n')
			break;

		if (count < max)
			out[count] = ch;
	}
	if (ferror(stream))
		return -1;

	/* pad, if needed */
	if (count < max) {
		out[count] = 0x80;
		memset(out+count+1, 0, max-count-1);
	}

	return count;
}


/*
 * read_pass - read a password from file or user.
 *
 * If input stream fp is a terminal (like /dev/tty) and promptA and promptB are
 * are not NULL they are used to prompt the user for a password and a password 
 * confirmation. This is repeated until both entries are equal.
 *
 * If fp is not a terminal, the password is read just one time (even if
 * promptB is given).
 *
 * Instead of zero-terminating the password it's length will be returned.
 * But the password will be padded to max bytes, by attaching one binary zero
 * and as much zeros as needed. This could be used to work with constant-length
 * passwords.
 */
int
read_pass(FILE *fp, uint8_t *passwd, size_t max, const char *promptA, const char *promptB)
{
	cu_resetterm struct terminal	term;

	uint8_t	 confirm[max];

	int	 passlen;
	int	 rc;

	if (setup_terminal(&term, fp) == -1)
		return -1;

	for (;;) {
		do {
			if (term.istty && promptA)
				fprintf(stderr, "%s", promptA);

			passlen = read_line(passwd, max, fp);
			if (passlen == -1) {
				warn("can't read password");
				return -1;
			}
			if (passlen > max) {
				/* without a tty this is fatal */
				if (!term.istty) {
					warnx("password to long");
					return -1;
				}
				fprintf(stderr, "password to long - please try again\n");
			}
		} while (passlen > max);


		/* need a confirmation? */
		if (promptB == NULL || !term.istty)
			break;

		if (term.istty)
			fprintf(stderr, "%s", promptB);

		rc = read_line(confirm, max, fp);
		if (rc == -1) {
			warn("can't read confirmation");
			return -1;
		}

		if (memcmp(passwd, confirm, max) == 0)
			break;

		fprintf(stderr, "Passwords do not match, please try again\n");
	}

	return passlen;
}

int
read_pass_fn(const char *fn, uint8_t *passwd, size_t max, const char *promptA, const char *promptB)
{
	FILE *passfile;
	int rval;

	if (strcmp(fn, "-") == 0)
		passfile = stdin;
	else {
		passfile = fopen(fn, "r");
		if (passfile == NULL) {
			warn("can't open password source: %s", fn);
			return -1;
		}
	}

	rval = read_pass(passfile, passwd, max, promptA, promptB);

	fclose(passfile);
	return rval;
}
