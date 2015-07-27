PSPKA-PBKDF2 demo
-----------------

This is a demo application for the PSPKA protocol using
[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) as KDF and
[ed25519](https://en.wikipedia.org/wiki/EdDSA) for signatures.

Please note that *cli* and *srv* are for demonstration purpose only and not meant to
be used in a production environment. Moreover the PSPKA protocol is pretty new
and there maybe unknown security flaws.

While PBKDF2 is a standard KDF for password hashing and key stretching i don't
recommend it. The [Password Hashing Competion](https://password-hashing.net)
has chosen Argon2 as winner and i will write a PSPKA-Argon2i demo soonish.


Compile
-------

Before you compile make sure to install [libeddsa](https://github.com/phlay/libeddsa).

Compile by just typing:
```
make
```

After compiling with make two test-programs *cli* and *srv* are created: *cli*
simulates the client and *srv* the server. You can experiment with these directly
or use (the extremly simple and unsecure) demo scripts in the demo-scripts folder.



client: generate new hash
------------------------
To generate a new hash, use: 
```
./cli -g <ident>
```

where *ident* is your identity (login name, email address, ...).
You will be asked for your password and the resulting hash
will depend on your identity *ident* and your password.

The salt for PBKDF2 will be read from /dev/urandom, but could also
be given as hex-string with the '-s *salt*' parameter.
  
The iteration count for PBKDF2 is 128000 per default and could be changed
with the '-i *iter*' option.
  

client: sign a challenge
------------------------
To sign a challenge use:

```
./cli <ident> <context> <challenge>
```

where *ident* is the same identity you used to generate your hash,
*context* is a string describing the service to login and challenge is 
the server-challenge itself (encoded in base64). 




server: generate challenge
---------------------------
To generate a challenge:

```
./srv -g <hash>
```

where <hash> is the hash of the client to verify.


server: verify a response
-------------------------
To verify a client response use

```
./srv <context> <chal> <response> <hash>
```

where *context* is the login context (must be the same one the client side),
*chal* is the challenge send to client, *response* the client's answer and
*hash* the clients hash.
