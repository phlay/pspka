# see config.mk for configuration options
#

include config.mk

CC = gcc
CFLAGS = -std=gnu99 -Wall -pedantic -O2 -mtune=$(MTUNE)
LDFLAGS = 


CLIOBJ = utils.o burn.o readpass.o sha512.o pbkdf2-hmac-sha512.o pspka-pbkdf2.o cli.o
SRVOBJ = utils.o burn.o sha512.o pbkdf2-hmac-sha512.o pspka-pbkdf2.o srv.o
LDFLAGS = -leddsa

ifeq ($(HAVE_GETRANDOM), yes)
	CFLAGS += -DHAVE_GETRANDOM
endif

ifeq ($(USE_DEV_RANDOM), yes)
	CFLAGS += -DUSE_DEV_RANDOM
endif


.PHONY: clean all

all: cli srv

${SRVOBJ}: config.mk
${CLIOBJ}: config.mk

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

print-%:
	@echo $*=$($*)

cli: $(CLIOBJ)
	$(CC) $(LDFLAGS) -o $@ $(CLIOBJ)

srv: $(SRVOBJ)
	$(CC) $(LDFLAGS) -o $@ $(SRVOBJ)

clean:
	rm -f *~ *.o cli srv
