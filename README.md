WARNING
-------

This is a new protocol and may have severe security flaws rendering it
completly useless. Use the demo programs only for security analysis and not for
any productive environment.


PSPKA 
-----

Let's face it: Passwords suck! And they do in a number of ways

1. people do forget them
2. people choose weak ones (low entropy)
3. companies do lose them
4. the company or service potentialy knows your password

While some problems are intrinsic (like (1)) and can't be helped, there are
well known technices to attack (2) and (3): Passwords are not stored in clear
text but instead a password hash (or
[KDF](http://en.wikipedia.org/wiki/Key_derivation_function)) is used to
scramble them. By using a 'salt' a KDF makes it difficult for an attacker to
use precalculated password lists and the heavy cpu demand of a KDF makes them
time consuming to brute force (modern KDFs also need a significant amount of
fast memory to defeat fast custom hardware).

But this feature makes them also unattractive on a server with many users, since
the server is usually the one calculating the password hash. But the big problem
in letting the server calculate the hash is actually (4): If you don't trust the
server (either it's security or it's maintainers) you are forced to use an
unique password for it.

The idea is to let the user calculate the KDF and change password verification
to a challenge-response protocol. But we don't want to give the server the
password hash either, because if that gets stolen it could be used to login to
the server without even needing the original password.

To solve these problems i recommend to use a combination of classical password
hashes (or KDF) and a modern elliptic curve signature scheme: The PSPKA scheme
uses a KDF, like [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2), to derive a
256bit [EdDSA](https://en.wikipedia.org/wiki/EdDSA) secret key from the users
identity and password and then calculates the corresponding EdDSA public key.
This public key together with the KDF parameters (like salt and iteration
count) are used as password hash.

If the user wants to authorize later a public-key challenge-response method is
used: The server sends a random challenge (including KDF parameters) and the
user uses her secret key (again derived from her identity and password, using
the salt and KDF parameters from the challenge) to sign the challenge together
with a random nonce and a context field describing this login. The response
constists of the random nonce together with the signature. This way our user can
login as usual with identity and password without any saved state, although it
is recommended to store the KDF parameters.

The PSPKA protocol could also be used to protect a [Diffie-Hellman
(DH)](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
connection between user and server from a [man-in-the-middle
attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack), by using the
shared DH secret as context in the response. (The context is normaly used to
defend against a server, trying to reuse a user-response to login as this user
on a different service.)

Problem (2) and limitation of damage are the only reasons to not reuse the same
password for different services, with this scheme. But if a password is really
strong and a good KDF is used, there is no security problem in publishing the
corresponding PSPKA-hash.
