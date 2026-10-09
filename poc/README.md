# Proof of concept

This directory contains a reference implementation of the protocols in
draft-vos-cfrg-pqpake, written in Python 3 (version 3.8 or later) using only
the standard library. It is slow, does not run in constant time, and is not
suitable for production use.

- `make test` runs the self-tests of the modules.
- `make check` checks ML-KEM, X-Wing, CPace, HKDF, and scrypt against their
  published test vectors, downloading those of ML-KEM, X-Wing, and CPace once
  into `.cache/`.
- `make vectors` generates the test vectors of the specification into
  `vectors/`: one JSON file per configuration with vectors, `ml-bua-skem.json`,
  and a Markdown rendering of each vector, which the specification includes. It
  then checks that each vector can be reproduced from the randomness it lists.

In the test vectors, byte strings are encoded in hexadecimal, and the Kemeleon
randomness `kemeleon_m` of each polynomial is an integer in decimal.

`mlkem.py`, `x25519.py`, and `xwing.py` are taken from the reference
specifications of FIPS 203 (https://github.com/bwesterb/draft-schwabe-cfrg-kyber)
and draft-connolly-cfrg-xwing-kem. Their headers list any modifications.
