# Proof of concept

This directory contains a reference implementation of the protocols in
draft-vos-cfrg-pqpake, written in Python 3 (version 3.8 or later) using only
the standard library. It is slow, does not run in constant time, and is not
suitable for production use.

- `make test` runs the self-tests of the modules.
- `make check` checks ML-KEM, X-Wing, and CPace against their published test
  vectors, which it downloads once into `.cache/`.

`mlkem.py`, `x25519.py`, and `xwing.py` are taken from the reference
specifications of FIPS 203 (https://github.com/bwesterb/draft-schwabe-cfrg-kyber)
and draft-connolly-cfrg-xwing-kem. Their headers list any modifications.
