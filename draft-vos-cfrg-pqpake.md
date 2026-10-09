---
title: "Hybrid Post-Quantum Password Authenticated Key Exchange"
abbrev: "Hybrid PQ-PAKE"
category: info

docname: draft-vos-cfrg-pqpake-latest
submissiontype: IRTF
v: 3
number:
date:
venue:
  group: CFRG
  type: Crypto Forum Research Group
  mail: cfrg@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/cfrg/
  github: chris-wood/draft-pqpake

author:
 -
    ins: J. Vos
    name: Jelle Vos
    organization: Apple, Inc.
    email: jelle_v_vos@apple.com
 -
    ins: S. Jarecki
    name: Stanislaw Jarecki
    organization: University of California, Irvine
    email: sjarecki@ics.uci.edu
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    organization: Apple, Inc.
    email: caw@heapingbits.net


normative:
  FIPS202:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    date: Aug, 2015
    author:
      -
        org: National Institute of Standards and Technology (NIST)
  FIPS203:
    title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard"
    target: https://csrc.nist.gov/pubs/fips/203/final
    date: Aug, 2024
    author:
      -
        org: National Institute of Standards and Technology (NIST)

informative:
  Gu24:
    title: "New Paradigms For Efficient Password Authentication Protocols"
    target: https://www.escholarship.org/uc/item/7qm0220s
    author:
      -
        name: Yanqi Gu
  LLH24:
    title: "Efficient Asymmetric PAKE Compiler from KEM and AE"
    target: https://eprint.iacr.org/2024/1400
    author:
      -
        name: You Lyu
      -
        name: Shengli Liu
      -
        name: Shuai Han
  LL24:
    title: "Hybrid Password Authentication Key Exchange in the UC Framework"
    target: https://eprint.iacr.org/2024/1630
    author:
      -
        name: You Lyu
      -
        name: Shengli Liu
  HR24:
    title: "PAKE Combiners and Efficient Post-Quantum Instantiations"
    target: https://eprint.iacr.org/2024/1621
    author:
      -
        name: Julia Hesse
      -
        name: Michael Rosenberg
  ABJ25:
    title: "NoIC: PAKE from KEM without Ideal Ciphers"
    target: https://eprint.iacr.org/2025/231
    author:
      -
        name: Afonso Arriaga
      -
        name: Manuel Barbosa
      -
        name: Stanislaw Jarecki
  TEMPO:
    title: "Tempo: ML-KEM to PAKE Compiler Resilient to Timing Attacks"
    target: https://eprint.iacr.org/2025/1399
    author:
      -
        name: Afonso Arriaga
      -
        name: Manuel Barbosa
      -
        name: Stanislaw Jarecki
  VJWYMS25:
    title: A Hybrid Asymmetric Password-Authenticated Key Exchange in the Random Oracle Model
    target: https://eprint.iacr.org/2025/1343
    author:
      -
        name: Jelle Vos
      -
        name: Stanislaw Jarecki
      -
        name: Christopher A. Wood
      -
        name: Cathie Yun
      -
        name: Steve Myers
      -
        name: Yannick Sierra
  GRSV25:
    title: "Hybrid Obfuscated Key Exchange and KEMs"
    target: https://eprint.iacr.org/2025/408
    author:
      -
        name: Felix Günther
      -
        name: Michael Rosenberg
      -
        name: Douglas Stebila
      -
        name: Shannon Veitch
  AHH21:
    title: "Security Analysis of CPace"
    target: https://eprint.iacr.org/2021/114
    author:
      -
        name: Michel Abdalla
      -
        name: Björn Haase
      -
        name: Julia Hesse
  AS22:
    title: "Quantum Augmented Dual Attack"
    target: https://eprint.iacr.org/2022/656
    author:
      -
        name: Martin R. Albrecht
      -
        name: Yixin Shen
  CMST25:
    title: "Assessing the Impact of a Variant of MATZOV's Dual Attack on Kyber"
    target: https://eprint.iacr.org/2022/1750
    author:
      -
        name: Kevin Carrier
      -
        name: Charles Meyer-Hilfiger
      -
        name: Yixin Shen
      -
        name: Jean-Pierre Tillich
  Kopis26:
    title: "Kopis: A KEM for Obfuscation"
    target: https://eprint.iacr.org/2026/2268
    author:
      -
        name: Andrea Basso
      -
        name: Michael Rosenberg
  Ogilvie26:
    title: "On the Concrete Hardness Gap Between MLWE and LWE"
    target: https://eprint.iacr.org/2026/279
    author:
      -
        name: Tabitha Ogilvie
  ADPS16:
    title: "Post-quantum key exchange - A new hope"
    target: https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/alkim
    author:
      -
        name: Erdem Alkim
      -
        name: Léo Ducas
      -
        name: Thomas Pöppelmann
      -
        name: Peter Schwabe
  Grover96:
    title: "A fast quantum mechanical algorithm for database search"
    target: https://doi.org/10.1145/237814.237866
    author:
      -
        name: Lov K. Grover
  Bernstein09:
    title: "Cost analysis of hash collisions: Will quantum computers make SHARCS obsolete?"
    target: https://cr.yp.to/papers.html#collisioncost
    author:
      -
        name: Daniel J. Bernstein


--- abstract

This document describes four post-quantum password authenticated key
exchange (PAKE) protocols: OQUAKE, OQUAKE+, CPaceOQUAKE, and CPaceOQUAKE+.
OQUAKE and OQUAKE+ are standalone PAKEs that both offer security against
a quantum-capable attacker. OQUAKE is a symmetric PAKE, suitable for use
cases where both parties share a view of the password. OQUAKE+ is an
augmented version of OQUAKE suitable for client-server settings where only
one party (the client) knows the password. CPaceOQUAKE is a hybrid PAKE
that runs a classical PAKE (CPace) and OQUAKE sequentially, and CPaceOQUAKE+
is its augmented version. This document
also provides recommended configurations for each protocol.

--- middle

# Introduction

Asymmetric (or Augmented) Password Authenticated Key Exchange (aPAKE)
protocols are designed to provide password authentication and
mutually authenticated key exchange in a client-server setting without
relying on a public key infrastructure (PKI) and without
disclosing passwords to servers or other entities other than the client
machine. The only stage where PKI is required is during a client's registration.

In the asymmetric PAKE setting, the client first registers a password
verifier with the server. A verifier is a value that is derived from the
password and which the server will later use to verify the client
knowledge of the password. After registration, the client uses its password
and the server uses the corresponding verifier to establish an authenticated
shared secret such that the server learns nothing of the client's password.

OPAQUE-3DH {{?OPAQUE=I-D.irtf-cfrg-opaque}} and SPAKE2+ {{?SPAKE2PLUS=RFC9383}}
are two examples of specified aPAKE protocols. These protocols provide
security in classical threat models. However, in the presence
of a quantum-capable attacker, both OPAQUE and SPAKE2+ fail to provide the
desired level of security. Both protocols are vulnerable to a Harvest Now, Decrypt
Later (HNDL) attack executed by a quantum-capable attacker, in which the attacker learns the shared secret and uses it
to compromise application traffic. For a password-authenticated protocol, this HNDL threat is
more severe than for plain (unauthenticated) key exchange: breaking underlying classical
assumption of a PAKE that is not unconditionally password hiding does not merely
disclose the traffic of one harvested session, but can retroactively recover the password itself
from the harvested transcript. Since passwords are long-lived credentials, this grants a
quantum-capable attacker indefinite impersonation capability rather than a one-time confidentiality
loss; see {{retroactive-recovery}} for a detailed treatment of this attack.
Upgrading both protocols to provide post-quantum security is non-trivial, especially as
there are no known efficient constructions for certain building blocks used in these
protocols (such as the OPRF used in OPAQUE-3DH). As the threat of quantum-capable
attackers looms, the viability of existing aPAKE protocols in practice diminishes in time.

This document addresses that gap. It specifies a post-quantum symmetric PAKE,
OQUAKE; a hybrid symmetric PAKE, CPaceOQUAKE, which runs the classical PAKE CPace
and OQUAKE sequentially; and augmented versions of both, OQUAKE+ and
CPaceOQUAKE+. The
sequential composition is what yields the hybrid guarantee: the resulting
protocol remains secure as long as either the classical or the post-quantum
component does, so an attacker must break both to recover the password. The
design securely composes multiple existing primitives {{VJWYMS25}}.

CPaceOQUAKE+ is the protocol intended for the common client-server deployment,
and is the primary focus of this document. {{use-cases}} describes the
deployments these protocols are and are not meant to serve, and
{{configurations}} provides recommended configurations for each.

# PAKE Use Cases {#use-cases}

PAKE deployments vary along two largely independent dimensions: how long a password is used
for, and what role the PAKE plays in the surrounding protocol. A password can be an ephemeral,
high-entropy, one-time secret (e.g., a pairing code shown on a screen), or a long-lived,
human-memorable credential that is reused across many protocol runs. Independently, the PAKE can
be the mechanism that establishes the resulting secure channel, or it can run over a channel that
is already secure for other reasons, in which case the PAKE serves only to confirm knowledge of
the password over that channel. Crossing these two dimensions gives four cases, which helps
clarify which deployments motivate a post-quantum aPAKE such as CPaceOQUAKE+, and which do not.

1. Device pairing (ephemeral password; PAKE establishes the channel). Two devices bootstrap a
   secure channel using a short-lived, high-entropy, one-time password or PIN, e.g., displayed on
   one device and typed into the other. A quantum-capable attacker is only relevant here if a
   post-quantum threat model is assumed at all, and even then this is a comparatively weak
   motivating example for a PQ-PAKE: because the password is used exactly once, retroactively
   recovering it (see {{retroactive-recovery}}) has little value to an attacker, as there is no
   future session to impersonate. HNDL against the resulting channel's *traffic* remains a
   legitimate concern, but that concern is the same one that motivates post-quantum key exchange
   generally and is not specific to the PAKE.
2. Password confirmation over an already-secure channel (long-lived password; PAKE does not
   establish the channel). The channel's confidentiality and post-quantum security come from
   elsewhere, e.g., a hybrid KEM used in the surrounding transport protocol, and the PAKE is used
   only to bind knowledge of a long-lived password to that channel. The full machinery of a
   PQ aPAKE is not required to realize this case in isolation.
3. Long-lived-password pairing (long-lived password; PAKE establishes the channel). This is
   the classic aPAKE deployment, e.g., a client authenticating to a server with an account
   password. It is also the case where retroactive password recovery is most damaging. Specifically,
   because the password is reused indefinitely, recovering it does not merely disclose one
   harvested session's traffic, it lets the attacker impersonate the client in every future
   session until the password is changed. This is the primary use case targeted by CPaceOQUAKE+.
4. Degenerate case (ephemeral password; PAKE does not establish the channel). Included only
   for completeness of the taxonomy above; it is not a motivating use case since there is little
   reason to spend a one-time password confirming a channel that the password neither secures nor
   will be reused for.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Notation and Terminology

The following functions and operators are used throughout the document.

- The function `random(n)` generates a cryptographically secure pseudorandom
  byte string of length `n` bytes.
- The associative binary operator `||` denotes concatenation of two byte strings.
- The binary function `XOR(a, b)` denotes an element-wise XOR operation between
  two byte strings `a` and `b` of the same length.
- The functions `bytes_to_int` and `int_to_bytes` convert
  byte strings to and from non-negative integers. bytes_to_int and int_to_bytes
  are implemented as OS2IP and I2OSP as described in {{!RFC8017}}, respectively.
- The function `lv_encode` encodes a byte string with a two-byte, big-endian
  length prefix. For example, lv_encode((0x00, 0x01, 0x02)) = (0x00, 0x03, 0x00, 0x01, 0x02).
  The function `lv_decode` parses a byte string that is expected to be encoded
  with a two-byte length preceding the remaining bytes, e.g.,
  `lv_decode((0x00, 0x03, 0x00, 0x01, 0x02)) = (0x00, 0x01, 0x02)`. Note that `lv_decode`
  can fail when the length of the actual bytes does not match that encoded in the
  prefix. For example, `lv_decode((0xFF, 0xFF, 0x00))` will fail.
- The notation `bytes[l..h]` refers to the slice of byte array `bytes` starting
  at index `l` and ending at index `h-1`. For example, given `bytes = (0x00, 0x01, 0x02)`, then `bytes[0..1] = 0x00` and `bytes[0..3] = (0x00, 0x01, 0x02)`. Similarly, the notation `bytes[l..]` refers to the slice of the byte
  array `bytes` starting at `l` until the end of `bytes`, i.e., `bytes[l..] = bytes[l..len(bytes)]`.
- The value `None` denotes an optional input that is not provided. Wherever such an
  input is used as a byte string, e.g., in a concatenation, it is equivalent to the
  empty string `b""`.

All algorithms and procedures described in this document are laid out
in a Python-like pseudocode. Each function takes a set of inputs and parameters
and produces a set of output values. Parameters become constant values once
the protocol variant and the configuration are fixed.

# Cryptographic Dependencies {#crypto-deps}

The protocols in this document have four primary dependencies:

- Key Encapsulation Mechanism (KEM); {{deps-kem}}
- Splittable Binary Key Encapsulation Mechanism with specific uniformity properties (binary UPK-ANO-KEM, or BUA-sKEM); {{deps-BUA-sKEM}}
- Key Derivation Function (KDF); {{deps-symmetric}}
- Key Stretching Function (KSF); {{deps-ksf}}

{{configurations}} specifies different combinations of each of these dependencies
that are suitable for implementation.

## Key Encapsulation Mechanism {#deps-kem}

A Key Encapsulation Mechanism (KEM) is an algorithm that is used for exchanging
a secret from one party to another. We require an IND-CCA-secure KEM with key
derivation from a seed. It consists of the following syntax.

- DeriveKeyPair(seed): Deterministic algorithm to derive a key pair
  `(sk, pk)` from the byte string `seed`, where `seed` MUST have `Nseed` bytes.
- Encaps(pk): Randomized algorithm to generate an ephemeral,
  fixed-length symmetric key (the KEM shared secret) and
  a fixed-length encapsulation of that key that can be decapsulated
  by the holder of the secret key corresponding to `pk`. This function
  can raise an `EncapsError` on encapsulation failure.
- Decaps(ct, sk): Deterministic algorithm using the secret key `sk`
  to recover the ephemeral symmetric key (the KEM shared secret) from
  its encapsulated representation `ct`. This function can raise a
  `DecapsError` on decapsulation failure.
- Nseed: The length in bytes of the seed used to derive a key pair.
- Nct: The length in bytes of an encapsulated key produced by this KEM.
- Npk: The length in bytes of a public key for this KEM.

This KEM is used for password confirmation in OQUAKE+ and CPaceOQUAKE+. The configurations
in this specification ({{configurations}}) use ML-KEM-768 and ML-KEM-1024 {{FIPS203}} for
OQUAKE+, and the hybrid KEMs X-Wing {{!XWING=I-D.connolly-cfrg-xwing-kem}} and MLKEM1024-P384
{{!CONCRETE-HYBRID-KEMS=I-D.irtf-cfrg-concrete-hybrid-kems}} for CPaceOQUAKE+.
For these KEMs, DeriveKeyPair uses the seed directly, as specified in {{CONCRETE-HYBRID-KEMS}}:
for ML-KEM, it is `KeyGen_internal(seed[0:32], seed[32:64])` {{FIPS203}}, and for X-Wing, it is
`GenerateKeyPairDerand(seed)` {{XWING}}. Implementations MUST NOT use the HPKE-style
`DeriveKeyPair(ikm)` of {{XWING}} instead, which first hashes its input and therefore derives a
different key pair.

## Splittable binary KEM {#deps-BUA-sKEM}

A KEM is binary if every byte string of length Npk is a valid public key, i.e.,
Encaps accepts any such string.

A binary KEM with uniform public keys and anonymous ciphertexts, denoted
a binary UPK-ANO-KEM, supports the same functions as defined above for
a KEM, except that it generates key pairs with a randomized function
`KeyGen() -> (sk, pk)` instead of DeriveKeyPair. Besides being IND-CCA
secure, it must also achieve two additional security properties.
A binary UPK-ANO-KEM is IND-CCA secure and it requires that:

1. Public keys are indistinguishable from random strings of bytes (of
the same length), i.e. uniform public keys (UPK); and

2. Ciphertexts are anonymous in the presence of chosen ciphertext
attack (ANO-CCA), i.e. anonymous ciphertexts (ANO).

These additional properties are crucial for the security of OQUAKE. In
other words, one MUST NOT use a KEM that has no uniform public keys
and/or no anonymous ciphertexts in place of a UPK-ANO-KEM.

In this specification, we also require a third property: the KEM must be splittable. A splittable KEM (sKEM) implements the `Split(pk) -> (ut, ⍴)` function and its inverse, which takes a public key and splits it into a part `⍴` that is independent of the KEM's secret key and can therefore be made public, and a part `ut` that does depend on the secret key. This property allows parties to perform variable-time operations on `⍴` without revealing information about the secret key. We use N⍴ to denote the byte-length of ⍴ and Nt to denote the byte-length of ut. We use `Combine(ut, ⍴) -> pk` to refer to the inverse operation of `Split`.

In the remainder of this specification, we abbreviate 'splittable binary UPK-ANO-KEM' as BUA-sKEM.
This specification uses variants of ML-KEM-768 and ML-KEM-1024 {{FIPS203}}, which we denote by
ML-BUA-sKEM-768 and ML-BUA-sKEM-1024. They are specified in {{ML-BUA-sKEM}}, using the Kemeleon
encoding of ML-KEM encapsulation keys {{!KEMELEON=I-D.irtf-cfrg-kemeleon}}. Note that, while
Kemeleon provides uniform encoding for KEM ciphertexts and public keys, we only
require uniform encoding for public keys. Future specifications can replace ML-BUA-sKEM
with another splittable binary UPK-ANO-KEM that is more efficient if one becomes available.

### ML-BUA-sKEM {#ML-BUA-sKEM}

The design of ML-BUA-sKEM is such that it does not change the internals of ML-KEM.
To ensure that the public key generated by ML-BUA-sKEM.KeyGen is binary and
uniform, it uses Kemeleon {{KEMELEON}} to (re-)encode ML-KEM's
public keys via `Kemeleon.EncodeEk` and `Kemeleon.DecodeEk`.

In the PAKEs described in this specification, it is crucial that this happens in
constant time. For this reason, ML-BUA-sKEM uses `Kemeleon.EncodeEk`, which performs
no rejection sampling and cannot fail, rather than the rejection-sampling variant
`Kemeleon.EncodeEkR`. `Kemeleon.EncodeEk` is randomized, and its randomness MUST be
kept secret {{KEMELEON}}. ML-BUA-sKEM sets Kemeleon's statistical distance parameter
Kemeleon.t to 132, which bounds the statistical distance between an encoded public key
and a uniform byte string as required in {{params-oquake}}.
Because `Kemeleon.EncodeEk` leaves the final 32 bytes (⍴) of the encoding untouched,
the resulting uniform public key remains splittable in the same way as the
underlying ML-KEM public key.

This document uses the following parameter sets.

| Parameter set    | ML-KEM      | Kemeleon.t |  Npk |  Nt  | N⍴ |  Nct |
|------------------|-------------|------------|------|------|----|------|
| ML-BUA-sKEM-768  | ML-KEM-768  |     132    | 1205 | 1173 | 32 | 1088 |
| ML-BUA-sKEM-1024 | ML-KEM-1024 |     132    | 1596 | 1564 | 32 | 1568 |
{: #tab-ml-bua-skem title="ML-BUA-sKEM parameter sets"}

ML-BUA-sKEM is defined as follows.
ML-KEM.KeyGen is specified in {{FIPS203}}, which generates encapsulation key ek and decapsulation key dk.

~~~
ML-BUA-sKEM.KeyGen

Output:
- sk, a secret decapsulation key, a byte string
- upk, a uniform public key for encapsulation, a byte string of ML-BUA-sKEM.Npk bytes

Parameters:
- ML-KEM, the ML-KEM parameter set
- Kemeleon, A parameterized instance of Kemeleon with statistical distance parameter Kemeleon.t

def KeyGen():
  (ek, dk) = ML-KEM.KeyGen()
  upk = Kemeleon.EncodeEk(ek)
  return dk, upk
~~~

With Kemeleon.t = 132, Kemeleon encodes each polynomial of an ML-KEM encapsulation key in 391 bytes instead of 384, so the uniform public keys produced by ML-BUA-sKEM are longer than those produced by ML-KEM.
ML-BUA-sKEM encodes each integer output by Kemeleon's VectorEncode as a little-endian byte string of 391 bytes, and Kemeleon.DecodeEk decodes it in the same way.
The final 32 bytes of the public key still represent the part that does not depend on the secret key.
For this reason, N⍴ = 32 and Nt = ML-BUA-sKEM.Npk - 32.

For ML-BUA-sKEM, the split operation is defined as follows.

~~~
ML-BUA-sKEM.Split

Input:
- upk, an ML-BUA-sKEM public key, a byte string of ML-BUA-sKEM.Npk bytes

Output:
- ut, part of the uniform public key that depends on the secret key
- ⍴, part of the uniform public key that does NOT depend on the secret key

def Split(upk):
  ut = upk[0 : ML-BUA-sKEM.Nt]
  ⍴ = upk[ML-BUA-sKEM.Nt : ML-BUA-sKEM.Npk]
  return ut, ⍴
~~~

For ML-BUA-sKEM, the inverse of the split operation is concatenation.

~~~
ML-BUA-sKEM.Combine

Input:
- ut, part of the uniform public key that depends on the secret key
- ⍴, part of the uniform public key that does NOT depend on the secret key

Output:
- upk, an ML-BUA-sKEM public key, a byte string of ML-BUA-sKEM.Npk bytes

def Combine(ut, ⍴):
  return ut || ⍴
~~~

ML-BUA-sKEM encapsulation undoes the uniform encoding performed during key generation before calling ML-KEM.Encaps on the non-uniform public key.

~~~
ML-BUA-sKEM.Encaps

Input:
- upk, an ML-BUA-sKEM public key

Output:
- k, a symmetric shared secret, a byte string
- ct, an anonymous ciphertext encapsulating k, a byte string

Parameters:
- ML-KEM, the ML-KEM parameter set
- Kemeleon, A parameterized instance of Kemeleon with statistical distance parameter Kemeleon.t

def Encaps(upk):
  pk = Kemeleon.DecodeEk(upk)
  return ML-KEM.Encaps(pk)
~~~

The decapsulation procedure for ML-BUA-sKEM is exactly the same as for ML-KEM.

~~~
ML-BUA-sKEM.Decaps

Input:
- ct, an anonymous ciphertext encapsulating k, a byte string
- sk, a secret decapsulation key, a byte string

Output:
- k, a symmetric shared secret, a byte string

def Decaps(ct, sk):
  return ML-KEM.Decaps(ct, sk)
~~~

## Key Derivation Function {#deps-symmetric}

A Key Derivation Function (KDF) is a function that takes some source of initial
keying material and uses it to derive one or more cryptographically strong keys.
This specification uses a KDF with the following API and parameters:

- Extract(salt, ikm): Extract a pseudorandom key of fixed length `Nx` bytes from
  input keying material `ikm` and an optional byte string `salt`.
- Expand(prk, info, L): Expand a pseudorandom key `prk` using the optional string `info`
  into `L` bytes of output keying material.
- Nx: The output size of the `Extract()` function in bytes.

Where an input to a KDF or KSF concatenates several fields, each variable-length field is encoded with `lv_encode`, so that distinct field values always yield distinct inputs.

The security analysis of the protocols in this document models the KDF as a random
oracle. The KDF MUST therefore be one that is reasonably modeled as a random oracle,
such as HKDF {{!RFC5869}} instantiated with SHA-256.


## Key Stretching Function {#deps-ksf}

This specification makes use of a Key Stretching Function (KSF), which is a slow
and expensive cryptographic hash function with the following API:

- Stretch(msg, salt, L): Apply a key stretching function to stretch the input `msg`
and salt `salt`, hardening it against offline dictionary attacks. This function also
needs to satisfy collision resistance. The output is a string of L bytes.

# Overview {#overview}

This document specifies four PAKE protocols:

- **OQUAKE**: A post-quantum symmetric PAKE built from a BUA-sKEM; see {{oquake}}.
- **CPaceOQUAKE**: A hybrid symmetric PAKE combining CPace and OQUAKE; see {{CPaceOQUAKE}}.
- **OQUAKE+** and **CPaceOQUAKE+**: Augmented PAKEs obtained by applying a
  PAKE-to-aPAKE transformation to OQUAKE and CPaceOQUAKE, respectively; see
  {{augmented-pakes}}.

All PAKEs in this document share a common interface. Each takes as input a
password-related string PRS (or a verifier derived from it), a public_context,
and a secret_context. The augmented PAKEs additionally take the registration
inputs described in {{apake-transform}}. The public_context binds public session information that
both parties agree on, such as an optional session identifier sid and optional
client and server identifiers U and S (e.g., a device identifier, an IP address,
or a URL). The secret_context binds confidential information shared by both
parties, such as the session key of a preceding protocol stage; it is never sent
on the wire. Both the public_context and the secret_context are optional; a party
that does not use one passes the empty string b"" (equivalently, None). Two parties
obtain matching session keys only if their PRS, public_context, and secret_context
match. See {{identities}} for more discussion about the identities and how they are
chosen in practice.

The public_context is constructed from the optional sid, U, and S using the
`EncodePublicContext` utility function. Each of sid, U, and S is optional and
defaults to the empty string b"". Applications MAY include additional public
information by prepending or appending it to the returned value. The byte-level
encoding produced by `EncodePublicContext`, along with the encodings of all
protocol messages, is specified in {{encodings}}; the main body of this document
describes protocol messages abstractly as tuples of named fields.

Along with its session key, each PAKE outputs a transcript hash th, computed with the TH function below.
The th publicly binds to the public_context and to all protocol messages of
the session.
When a protocol in this document sequentially composes two sub-protocols, the later protocol uses the preceding's th as its public_context, binding them together.
Applications can also use th to bind a higher-level protocol to a PAKE session.
An implementation does not need to expose th to its callers.

~~~
TH

Input:
- label, a byte string identifying the protocol
- f_1, ..., f_n, the fields to hash, byte strings

Output:
- th, a transcript hash of KDF.Nx bytes

Parameters:
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def TH(label, f_1, ..., f_n):
  return KDF.Extract(DST || "TH-" || label,
                     lv_encode(f_1) || ... || lv_encode(f_n))
~~~

# Post-Quantum PAKE: OQUAKE {#oquake}

OQUAKE is a post-quantum symmetric PAKE built on a BUA-sKEM and KDF, using 2
rounds of a Feistel network to password-encrypt the BUA-sKEM public key. The
OQUAKE protocol is based on the "NoIC" protocol analyzed in {{ABJ25}}. If the
BUA-sKEM provides security against quantum-enabled attacks, then so does OQUAKE.
OQUAKE implements the common interface described in {{overview}}: it consists of two
messages sent between initiator and responder, produced by
the functions Init, Respond, and Finish, described below. Both parties take as input a password-related
string PRS, a public_context, and a secret_context. Upon completion, both parties obtain matching session keys if
their PRS, public_context, secret_context, and key length (specified by Nkey) match. Otherwise,
they obtain random session keys. Either party can act as the initiator: in OQUAKE+
({{oquakeplus}}) the client initiates, whereas in CPaceOQUAKE ({{CPaceOQUAKE}}) the
server does.

When a secret_context is provided, OQUAKE derives an effective password from (PRS, secret_context) and uses it in place
of PRS throughout the protocol. This allows OQUAKE to be securely composed with a preceding protocol
stage whose output key is provided as the secret_context.

The public_context typically encodes a session identifier sid and client and
server identifiers U and S. It has the following requirements. If a client and server identifier are provided:

- The session identifier must match between the client and server
- This session identifier has not been used before in a session between the client and server

If no client and server identifiers are provided:

- The session identifier must match between the client and server
- This session identifier has not been used before by the client or server in any session with any other party

These requirements originate from the security proof for OQUAKE. If these requirements are not met, the proof
does not apply, but this does not mean that the protocol becomes vulnerable.

The specification follows the design as presented in {{VJWYMS25}}, with the splittable KEM technique described
in {{TEMPO}}, which prevents timing attacks caused by rejection sampling in ML-KEM. See {{timing-and-tempo}}
for more information on the timing attack and this fix.

The byte-level encoding of the OQUAKE protocol messages is specified in {{encodings}}.

## Initiation

Init takes as input the initiator's PRS, a public_context, and a secret_context.
It produces a state for the initiator to store, as well as a
protocol message that is sent to the responder. Its implementation is as follows.
In the comments, H denotes the random oracle of the protocol's security analysis,
which this document instantiates with the KDF ({{deps-symmetric}}).

~~~
OQUAKE.Init

Input:
- PRS, password-related string, a byte string
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string

Output:
- state, opaque state for the initiator to store
- msg, a protocol message for the initiator to send to the responder

Parameters:
- BUA-sKEM, a BUA-sKEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def Init(PRS, public_context, secret_context):
  prk_ePRS = KDF.Extract(PRS, DST || "OQUAKE-context" ||
                         lv_encode(public_context) || lv_encode(secret_context))
  effective_PRS = KDF.Expand(prk_ePRS, DST || "effective_PRS", Nkey)

  (sk, pk) = BUA-sKEM.KeyGen()
  (ut, ⍴) = BUA-sKEM.Split(pk)

  r = random(Nr)

  // T = XOR(ut, H(public_context, effective_PRS, ⍴, r))
  prk_T_pad = KDF.Extract(effective_PRS, DST || "OQUAKE" || lv_encode(public_context) || ⍴ || r)
  T_pad = KDF.Expand(prk_T_pad, DST || "T_pad", BUA-sKEM.Nt)
  T = XOR(ut, T_pad)

  // s = XOR(r, H(public_context, effective_PRS, ⍴, T))
  prk_s_pad = KDF.Extract(effective_PRS, DST || "OQUAKE" || lv_encode(public_context) || ⍴ || T)
  s_pad = KDF.Expand(prk_s_pad, DST || "s_pad", Nr)
  s = XOR(r, s_pad)

  msg = (s, T, ⍴)

  return State(effective_PRS, sk, pk, ⍴, s, T, public_context), msg
~~~

## Response

Respond takes as input the PRS, a public_context, a secret_context, and the initiator's protocol message.
It produces a protocol message intended to be sent to the initiator, an Nkey-byte symmetric key, and a transcript hash.
Its implementation is as follows.

~~~
OQUAKE.Respond

Input:
- PRS, password-related string, a byte string
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string
- init_msg, the initiator's protocol message

Output:
- resp_msg, a protocol message for the responder to send to the initiator
- key, output shared secret, a byte string of Nkey bytes
- th, transcript hash, a byte string of KDF.Nx bytes

Parameters:
- BUA-sKEM, a BUA-sKEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def Respond(PRS, public_context, secret_context, init_msg):
  (s, T, ⍴) = init_msg

  prk_ePRS = KDF.Extract(PRS, DST || "OQUAKE-context" ||
                         lv_encode(public_context) || lv_encode(secret_context))
  effective_PRS = KDF.Expand(prk_ePRS, DST || "effective_PRS", Nkey)

  prk_s_pad = KDF.Extract(effective_PRS, DST || "OQUAKE" || lv_encode(public_context) || ⍴ || T)
  s_pad = KDF.Expand(prk_s_pad, DST || "s_pad", Nr)
  r = XOR(s, s_pad)

  prk_T_pad = KDF.Extract(effective_PRS, DST || "OQUAKE" || lv_encode(public_context) || ⍴ || r)
  T_pad = KDF.Expand(prk_T_pad, DST || "T_pad", BUA-sKEM.Nt)
  ut = XOR(T, T_pad)

  pk = BUA-sKEM.Combine(ut, ⍴)
  (k, ct) = BUA-sKEM.Encaps(pk)

  prk_sk = KDF.Extract(effective_PRS, DST || "OQUAKE" || lv_encode(public_context) ||
                       s || T || pk || ct || k)
  h = KDF.Expand(prk_sk, DST || "confirm", Nkc)
  key = KDF.Expand(prk_sk, DST || "key", Nkey)

  resp_msg = (ct, h)
  th = TH("OQUAKE", public_context, s, T, ⍴, ct, h)

  return resp_msg, key, th
~~~

## Finish {#quake-finish}

Finish takes as input the initiator-created state that is output from Init
as well as the responder's reply message resp\_msg. It produces a symmetric key
and a transcript hash that are output to the initiator.

Finish does not raise an error when key confirmation or decapsulation fails.
Instead, it returns a freshly sampled random key, so that a party that does not
hold the correct PRS obtains an unrelated session key rather than a
distinguishable failure signal. Callers therefore MUST NOT treat the output of
Finish as evidence that the peer knows the password; in the augmented PAKEs, that
evidence comes from password confirmation ({{pwconf}}).

Its implementation is as follows.

~~~
OQUAKE.Finish

Input:
- state, opaque state for the initiator to store
- resp_msg, the responder's protocol message

Output:
- key, output shared secret, a byte string of Nkey bytes
- th, transcript hash, a byte string of KDF.Nx bytes

Parameters:
- BUA-sKEM, a BUA-sKEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def Finish(state, resp_msg):
  (effective_PRS, sk, pk, ⍴, s, T, public_context) = state
  (ct, h) = resp_msg

  th = TH("OQUAKE", public_context, s, T, ⍴, ct, h)

  try:
    k = BUA-sKEM.Decaps(ct, sk)
  catch DecapsError:
    return random(Nkey), th

  prk_sk = KDF.Extract(effective_PRS, DST || "OQUAKE" || lv_encode(public_context) ||
                       s || T || pk || ct || k)
  h_expected = KDF.Expand(prk_sk, DST || "confirm", Nkc)
  if h != h_expected:
    return random(Nkey), th

  key = KDF.Expand(prk_sk, DST || "key", Nkey)
  return key, th
~~~

# Hybrid PAKE: CPaceOQUAKE {#CPaceOQUAKE}

This section specifies the hybrid PAKE called CPaceOQUAKE.
It is built on a sequential combiner that takes two PAKEs, denoted Stage 1 and Stage 2, that both implement the common interface defined in {{overview}}, and composes them into one hybrid PAKE.
This combiner is based on the `Sequential PAKE Combiner' protocol proposed by {{HR24}}.
A close variant was also analyzed in {{LL24}}.
CPaceOQUAKE is the instantiation of this combiner with CPace ({{cpace}}) as Stage 1 and OQUAKE ({{oquake}}) as Stage 2, which assumes that OQUAKE is instantiated with a quantum-resistant BUA-sKEM.
The augmented version, CPaceOQUAKE+, is specified in {{CPaceOQUAKEplus}}.

Whereas running these two PAKEs in parallel realizes a worst-of-both worlds PAKE, this sequential composition realizes a combined PAKE that remains as secure as the strongest of its two component PAKEs.
In other words, it resists attacks that break either sub-PAKE.
For example, it remains secure either if a quantum-capable attacker breaks CPace or if there is a flaw in the implementation of OQUAKE.
The reason a parallel combination of CPace and OQUAKE does not achieve best-of-both-worlds security is that it requires both underlying PAKEs to hide the password unconditionally.
For more information, see {{hybrid-design}}.

The sequential combiner overcomes this limitation: it only requires Stage 1's PAKE to unconditionally hide the password.
The combiner first runs Stage 1, establishing session key SK1 and transcript hash th1, and then runs Stage 2 with secret_context=SK1 and public_context=th1.
Stage 2 derives an effective password from (PRS, th1, SK1) and uses it throughout.
The final session key is derived from Stage 2's session key, SK1, and Stage 2's transcript hash, which covers both stages.
See the diagram below.

~~~ aasvg
            Client                 Server
              |                      |
              |     +---------+      |
              |     | Stage 1 |      |
     PRS ---->+---->|  PAKE   |<-----+<---- PRS
              |     +---------+      |
              |          |           |
              |       SK1, th1       |
              |          |           |
              |     +---------+      |
              |     | Stage 2 |      |
     PRS ---->+---->|  PAKE   |<-----+<---- PRS
                    +---------+
                      |      |
                      |      |
  client_key <--------+      +------> server_key
~~~

We note that this document only specifies the composition above with CPace and OQUAKE.
It is not necessarily true that one can securely compose all PAKEs this way.

At a high level, CPaceOQUAKE is a three-message protocol that runs between client and server wherein, upon completion, both parties share the same session key if they agree on the password-related string (PRS) and public and secret contexts.
Otherwise, they obtain random session keys.

The client initiates CPace.
Upon receiving the client's first message, the server finishes CPace and uses its SK1 to initiate OQUAKE.
The server sends its CPace response along with its first OQUAKE message.
After that, the client finishes CPace and responds to OQUAKE.

Unlike OQUAKE, CPaceOQUAKE does not require a shared session identifier sid, although this is strongly recommended.
The public_context of OQUAKE is CPace's transcript hash, which covers the public_context and the messages Ya and Yb.
Since each party contributes a fresh Ya or Yb, it is unique to the session even if the application provides no sid.

See the diagram below for an overview of the protocol flow.
There are four functions: Init and InitiatorFinish are intended to be called by the client, and Respond and ResponderFinish are intended to be called by the server.
The byte-level encoding of the protocol messages is specified in {{encodings}}.

~~~aasvg
Client: PRS,pub_ctx,sec_ctx        Server: PRS,pub_ctx,sec_ctx
        -----------------------------------------
     ctx, msg1 =                           |
CPaceOQUAKE.Init(PRS,pub_ctx,sec_ctx)      |
             |                             |
             |           msg1              |
             |---------------------------->|
             |                             |
             |                  ctx, msg2 =
             |   CPaceOQUAKE.Respond(PRS,pub_ctx,sec_ctx,msg1)
             |                             |
             |           msg2              |
             |<----------------------------|
             |                             |
     client_key, msg3, th =                |
CPaceOQUAKE.InitiatorFinish(               |
  PRS,pub_ctx,sec_ctx,ctx,msg2)            |
             |                             |
             |           msg3              |
             |---------------------------->|
             |                             |
             |              server_key, th =
             |     CPaceOQUAKE.ResponderFinish(ctx,msg3)
             |                             |
        -----------------------------------------
     output client_key              output server_key
~~~

## Client Initiation

The client initiates CPace (Stage 1).

~~~
CPaceOQUAKE.Init

Input:
- PRS, password-related string, a byte string
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string

Output:
- state, opaque state for the initiator to store
- msg, a protocol message for the initiator to send to the responder

Parameters:
- CPace, parameterized instance of CPace

def Init(PRS, public_context, secret_context):
  ctx1, Ya = CPace.Init(PRS, public_context, secret_context)
  return ctx1, Ya
~~~

## Server Response

The server finishes CPace and initiates OQUAKE (Stage 2), using the CPace session key as OQUAKE's
secret_context and the CPace transcript hash as OQUAKE's public_context.
The server MUST abort if its received message does not have the correct length.

~~~
CPaceOQUAKE.Respond

Input:
- PRS, password-related string, a byte string
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string
- init_msg, the message received from the client

Output:
- state, opaque state for the responder to store
- msg, a protocol message for the responder to send to the initiator

Parameters:
- CPace, parameterized instance of CPace
- OQUAKE, parameterized instance of OQUAKE

def Respond(PRS, public_context, secret_context, init_msg):
  Ya = init_msg

  key1, Yb, th1 = CPace.Respond(PRS, public_context, secret_context, Ya)
  ctx2, oquake_init = OQUAKE.Init(PRS, th1, key1)

  resp_msg = (Yb, oquake_init)

  return State(ctx2, key1), resp_msg
~~~

## Client Finish

The client finishes CPace and responds to OQUAKE.
It derives the session key from OQUAKE's session key, the CPace session key, and OQUAKE's transcript hash,
which is also the CPaceOQUAKE transcript hash.
The client MUST abort if its received message does not have the correct length.

~~~
CPaceOQUAKE.InitiatorFinish

Input:
- PRS, password-related string, a byte string
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string
- state, the state generated by CPaceOQUAKE.Init
- resp_msg, the message received from the server

Output:
- key, a shared secret of Nkey bytes
- msg, a protocol message for the initiator to send to the responder
- th, transcript hash, a byte string of KDF.Nx bytes

Parameters:
- CPace, parameterized instance of CPace
- OQUAKE, parameterized instance of OQUAKE
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def InitiatorFinish(PRS, public_context, secret_context, state, resp_msg):
  ctx1 = state
  (Yb, oquake_init) = resp_msg

  key1, th1 = CPace.Finish(ctx1, public_context, Yb)
  msg, key2, th2 = OQUAKE.Respond(PRS, th1, key1, oquake_init)

  prk = KDF.Extract(key2, DST || "CPaceOQUAKE" || th2 || key1)
  client_key = KDF.Expand(prk, DST || "key", Nkey)

  return client_key, msg, th2
~~~

## Server Finish

The server finishes OQUAKE and derives the session key in the same way as the client.
The server MUST abort if its received message does not have the correct length.

~~~
CPaceOQUAKE.ResponderFinish

Input:
- state, the state generated by CPaceOQUAKE.Respond
- msg3, the message received from the client

Output:
- key, a shared secret of Nkey bytes
- th, transcript hash, a byte string of KDF.Nx bytes

Parameters:
- OQUAKE, parameterized instance of OQUAKE
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def ResponderFinish(state, msg3):
  (ctx2, key1) = state
  key2, th2 = OQUAKE.Finish(ctx2, msg3)

  prk = KDF.Extract(key2, DST || "CPaceOQUAKE" || th2 || key1)
  server_key = KDF.Expand(prk, DST || "key", Nkey)

  return server_key, th2
~~~


# Augmented PAKEs {#augmented-pakes}

This section specifies the augmented PAKEs OQUAKE+ and CPaceOQUAKE+.
Both are obtained by applying the same PAKE-to-aPAKE transformation ({{apake-transform}}) to
a symmetric PAKE:
OQUAKE+ ({{oquakeplus}}) applies it to OQUAKE, and CPaceOQUAKE+ ({{CPaceOQUAKEplus}}) applies it to CPaceOQUAKE.

## PAKE-to-aPAKE Transformation {#apake-transform}

The transformation transforms a symmetric PAKE into an asymmetric (augmented) PAKE, in which the
server stores a verifier for the client's password, instead of the password itself.
It is a close variant of the `augmented PAKE' constructions presented in {{LLH24}} and in {{Gu24}}.

The verifier consists of three parts, derived from the output of a key stretching function on the client's password and a random secret.
The first Nv bytes of the KSF output are denoted v, which makes up the first part of the verifier.
The remaining KEM.Nseed bytes, which we call the seed, are combined with kem_blind, a secret random blinding value, to derive a KEM key pair.
The public key of this key pair and kem_blind are the second and third parts of the verifier.
This KEM does not have to be a BUA-sKEM.

In each session, the client and server first run the symmetric PAKE with v instead of the PRS, yielding session key SK and transcript hash th.
The server then uses SK, th, the KEM public key pk, and kem_blind to challenge the client to prove knowledge of the seed ({{pwconf}}).
Password confirmation relies on SK for confidentiality, so it cannot be used as a standalone protocol and SHOULD NOT be used outside of this transformation.

~~~ aasvg
            Client                      Server
              |                           |
              |     +--------------+      |
              |     |  Symmetric   |      |
       v ---->+---->|     PAKE     |<-----+<---- v
              |     +--------------+      |
              |            |              |
              |          SK, th           |
              |            |              |
              |     +--------------+      |
              |     |   Password   |      |
    seed ---->+---->| confirmation |<-----+<---- pk, kem_blind
              |     +--------------+      |
                       |        |
  client_key <---------+        +-------> server_key
~~~

### Offline Registration

This subsection specifies functions for generating a verifier and
a protocol for registering clients.

#### Generating Verifiers {#gen-verifiers}

Verifiers are random-looking values derived from password-related strings from which it is computationally impractical to derive the password-related string.
To make verifiers unique between different users with the same password or servers that they interact with, we employ a salt, a user account identifier, and an optional server identifier.
These identifiers identify the registration and do not have to be equal to any identifiers in the public_context; see {{asymmetric-identities}}.
The material required for the verifier is generated as follows:

~~~
GenVerifierMaterial

Input:
- PRS, password-related string, a byte string
- salt, client-specific salt, a byte string
- U and S, client and server identifiers

Output:
- v, the first part of the verifier, a byte string of Nv bytes
- seed, a KEM key-derivation seed, a byte string of KEM.Nseed bytes

Parameters:
- KEM, a KEM instance
- KSF, a parameterized KSF instance
- DST, domain separation tag, a byte string

def GenVerifierMaterial(PRS, salt, U, S):
  material = KSF.Stretch(DST || lv_encode(PRS) || lv_encode(U) || lv_encode(S),
                         salt, Nv + KEM.Nseed)
  v = material[0:Nv]
  seed = material[Nv:Nv + KEM.Nseed]
  return v, seed
~~~

The KEM key pair is derived from the seed and kem_blind as follows:

~~~
DeriveKEMSeed

Input:
- seed, a KEM key derivation seed, a byte string of KEM.Nseed bytes
- kem_blind, a secret blinding value of 32 bytes

Output:
- kem_seed, the seed for KEM.DeriveKeyPair, a byte string of KEM.Nseed bytes

Parameters:
- KEM, a KEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def DeriveKEMSeed(seed, kem_blind):
  prk = KDF.Extract(seed, DST || "KEMSeed" || kem_blind)
  return KDF.Expand(prk, DST || "kem_seed", KEM.Nseed)
~~~

To derive the verifier (v, pk, kem_blind), we use the following function:

~~~
GenVerifier

Input:
- PRS, password-related string, a byte string
- salt, client-specific salt, a byte string
- U and S, client and server identifiers

Output:
- v, the first part of the verifier, a byte string of Nv bytes
- pk, the second part of the verifier, a KEM public key
- kem_blind, the third part of the verifier, a secret blinding value of 32 bytes

Parameters:
- KEM, a KEM instance

def GenVerifier(PRS, salt, U, S):
  v, seed = GenVerifierMaterial(PRS, salt, U, S)
  kem_blind = random(32)
  (sk, pk) = KEM.DeriveKeyPair(DeriveKEMSeed(seed, kem_blind))
  return v, pk, kem_blind
~~~

The server MUST store pk and kem_blind; it MUST NOT store seed.
A fresh kem_blind MUST be generated for each registration.
The server sends kem_blind to the client only in encrypted form during password confirmation ({{pwconf}}), so the client does not need to store it.

Because the KSF is deliberately expensive, a client MAY compute (v, seed) once and store it in place of PRS, and use the stored values instead of calling GenVerifierMaterial when initiating the protocol.
The stored (v, seed) SHOULD be protected in the same way as PRS, since it allows authenticating as the client to that server.

#### Client Registration

The registration phase consists of one message sent from the client to the server. This message
contains the verifier (v, pk, kem_blind) and a 32-byte salt.
The server stores this information corresponding to the client for future use in the verification flow.
This phase requires a secure channel from client to server in order to transfer the verifier.
The salt can be sent in plain text.
In some cases, there may not be a secure channel, but the server may already know the password.
In such cases, the server MAY instead choose the salt, compute the verifier on behalf of the client using GenVerifier, store it, and erase the password and the seed.

We recommend that the salt is a random byte string: `salt = random(32)`.
The client needs the salt before it sends its first protocol message, since the symmetric PAKE already runs over v.
It can store the salt, or derive it from some client-specific value that it knows and can retain locally.
Otherwise, it obtains the salt from the server, which can send it in plain text, in an additional round trip before the protocol starts.
That round trip requires the client to first identify its registration to the server.

A high level flow overview of the registration flow is below.

~~~aasvg
Client: PRS, salt, U, S              Server: N/A
       ---------------------------------------
 (v, pk, kem_blind) = GenVerifier(PRS, salt, U, S)
            |                           |
            | salt,v,pk,kem_blind,U,S   |
            |-------------------------->|
            |                           |
            |                Store (salt, v, pk, kem_blind, U, S)
            |                           |
       ---------------------------------------
~~~

### Password Confirmation {#pwconf}

Password confirmation is a challenge-response exchange after the symmetric PAKE finishes.
Both parties input the key SK and the transcript hash th output by the symmetric PAKE.
The server must also input the client's registered public key pk and kem_blind, while the client inputs the corresponding seed.
The server creates a challenge in the form of a KEM ciphertext encapsulated for that pk, which it encrypts together with kem_blind using SK.
The client decrypts both using SK and proves that it can decapsulate the ciphertext.
It does so by deriving the KEM's secret decapsulation key from the seed and kem_blind.
Since kem_blind reaches the client in encrypted form, the time the client takes to derive the KEM key pair does not help an attacker that does not know the verifier to perform offline password guessing ({{timing-and-tempo}}).
The challenge also contains client_confirm, which depends on SK and on the encapsulated key.
It lets the client check that the server knows both, which requires the full verifier (v, pk, kem_blind) or the password.

The state returned by Challenge holds the server's candidate session key.
Unless server_confirm is omitted as described in {{omit-confirmation}}, this key MUST NOT be released to the calling application, used to protect traffic, or otherwise acted upon before Verify has confirmed the client's response, and implementations SHOULD keep the state opaque so that server_key is reachable only as the return value of Verify.

~~~
PC.Challenge

Input:
- SK, the key output by the symmetric PAKE, a byte string
- th, the transcript hash output by the symmetric PAKE, a byte string
- pk, part of the client's registered verifier, a KEM public key
- kem_blind, part of the client's registered verifier, a byte string of 32 bytes

Output:
- state, opaque state for the server to store
- challenge, a protocol message for the server to send to the client

Parameters:
- KEM, a KEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def Challenge(SK, th, pk, kem_blind):
  (k, c) = KEM.Encaps(pk)
  r = KDF.Expand(SK, DST || "OTP", Nct + 32)
  enc_c = XOR(c || kem_blind, r)

  prk_pc = KDF.Extract(SK, DST || "PC" || th || enc_c || k)
  client_confirm = KDF.Expand(prk_pc, DST || "client_confirm", Nkc)
  server_confirm = KDF.Expand(prk_pc, DST || "server_confirm", Nkc)
  server_key = KDF.Expand(prk_pc, DST || "key", Nkey)

  th_out = TH("PC", th, enc_c, client_confirm, server_confirm)
  challenge = (enc_c, client_confirm)

  return State(server_confirm, server_key, th_out), challenge
~~~

The client decrypts the KEM ciphertext and kem_blind using SK, re-derives the KEM key pair from the seed and kem_blind, and decapsulates the ciphertext to derive the password confirmation values and its session key.
It aborts if the server-provided confirmation value does not match its own.
Otherwise, it returns its session key, its own confirmation value, and the transcript hash.

~~~
PC.Respond

Input:
- SK, the key output by the symmetric PAKE, a byte string
- th, the transcript hash output by the symmetric PAKE, a byte string
- seed, seed used to derive the KEM key pair during registration
- challenge, the server's password confirmation challenge

Output:
- client_key, a byte string of Nkey bytes
- response, a protocol message for the client to send to the server
- th, transcript hash, a byte string of KDF.Nx bytes

Exceptions:
- AuthenticationError, raised when the password confirmation values do not match

Parameters:
- KEM, a KEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def Respond(SK, th, seed, challenge):
  (enc_c, client_confirm_target) = challenge

  r = KDF.Expand(SK, DST || "OTP", Nct + 32)
  c_and_blind = XOR(enc_c, r)
  c = c_and_blind[0:Nct]
  kem_blind = c_and_blind[Nct:Nct + 32]

  (sk, pk) = KEM.DeriveKeyPair(DeriveKEMSeed(seed, kem_blind))

  try:
    k = KEM.Decaps(c, sk)
  catch DecapsError:
    raise AuthenticationError

  prk_pc = KDF.Extract(SK, DST || "PC" || th || enc_c || k)
  client_confirm = KDF.Expand(prk_pc, DST || "client_confirm", Nkc)
  if client_confirm != client_confirm_target:
    raise AuthenticationError

  server_confirm = KDF.Expand(prk_pc, DST || "server_confirm", Nkc)
  client_key = KDF.Expand(prk_pc, DST || "key", Nkey)
  th_out = TH("PC", th, enc_c, client_confirm, server_confirm)

  return client_key, server_confirm, th_out
~~~

Upon receipt of the response, the server validates that the password confirmation
value matches its own value. If the value does not match, the server aborts.
Otherwise, the server outputs its session key and the transcript hash.

~~~
PC.Verify

Input:
- state, opaque state produced by Challenge
- server_confirm_target, the client's response, a byte string

Output:
- server_key, a byte string of Nkey bytes
- th, transcript hash, a byte string of KDF.Nx bytes

Exceptions:
- AuthenticationError, raised when the password confirmation values do not match

def Verify(state, server_confirm_target):
  (server_confirm, server_key, th_out) = state
  if server_confirm != server_confirm_target:
    raise AuthenticationError
  return server_key, th_out
~~~

### Omitting Key Confirmation Values {#omit-confirmation}

Some applications may want to perform session key confirmation themselves, for example, by exchanging messages authenticated with keys derived from it or using message integrity codes.
Such an application MAY omit server_confirm, client_confirm, or both, but then it MUST confirm the session key in the same direction and all of the following conditions MUST hold:

1. The keys used for the application's confirmation are derived from the session key using a KDF, and are distinct from the keys used to protect application data.
2. Neither party treats its peer as authenticated before it has verified the peer's confirmation.
3. The server MUST treat a failed or missing confirmation from the client as a failed password attempt for the purpose of rate limiting password guesses.
4. Which values are omitted is fixed by the application in advance, and this is not negotiated during the protocol.

If server_confirm is omitted, the client does not send it, and the server outputs the server_key and th_out held in the state, returned by Challenge instead of calling Verify.
OQUAKE+ then takes two messages, and CPaceOQUAKE+ takes four messages.
If client_confirm is omitted, the challenge consists of enc_c only, and the client does not compare client_confirm with a received value. All other values MUST be derived as specified in {{pwconf}}, and th_out MUST be computed with the empty string in place of each omitted value.
The resulting variant of OQUAKE+ or CPaceOQUAKE+ only achieves implicit key confirmation.

## OQUAKE+ Protocol {#oquakeplus}

OQUAKE+ is the augmented PAKE obtained by applying the transformation of {{apake-transform}} to OQUAKE ({{oquake}}).
The client initiates OQUAKE, and the server sends its password confirmation challenge together with its OQUAKE response, so the protocol consists of three messages.
An application may omit the last message; see {{omit-confirmation}}.

A high level overview of OQUAKE+ is below.

~~~aasvg
Client: PRS,salt,U,S,pub_ctx,sec_ctx   Server: v,pk,kem_blind,
                                               pub_ctx,sec_ctx
          ----------------------------------------
ctx, msg1 = OQUAKE+.Init(                      |
  PRS,salt,U,S,pub_ctx,sec_ctx)                |
            |               msg1               |
            |--------------------------------->|
            |                                  |
            |                 ctx, msg2 = OQUAKE+.Respond(
            |                   v,pub_ctx,sec_ctx,msg1,pk,kem_blind)
            |                                  |
            |               msg2               |
            |<---------------------------------|
            |                                  |
client_key, msg3, th =                         |
  OQUAKE+.Finish(ctx,msg2)                     |
            |                                  |
            |               msg3               |
            |--------------------------------->|
            |                                  |
            |    server_key, th = OQUAKE+.Verify(ctx,msg3)
            |                                  |
          ----------------------------------------
      output client_key                 output server_key
~~~

OQUAKE+ is parameterized by a BUA-sKEM, KEM, KDF, and KSF; see {{config-oquakeplus}} for the RECOMMENDED configurations.
The byte-level encoding of the OQUAKE+ protocol messages is specified in {{encodings}}.

### Initiation

Init derives the verifier material from the client's password ({{gen-verifiers}}) and initiates OQUAKE with v in place of PRS.

~~~
OQUAKE+.Init

Input:
- PRS, password-related string, a byte string
- salt, client-specific salt, a byte string
- U and S, client and server identifiers used at registration
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string

Output:
- state, opaque state for the initiator to store
- msg, a protocol message for the initiator to send to the responder

Parameters:
- OQUAKE, parameterized instance of OQUAKE

def Init(PRS, salt, U, S, public_context, secret_context):
  (v, seed) = GenVerifierMaterial(PRS, salt, U, S)
  ctx, msg = OQUAKE.Init(v, public_context, secret_context)
  return State(ctx, seed), msg
~~~

### Response

The server responds to OQUAKE and challenges the client to confirm its password.
As described in {{pwconf}}, the server_key held in the returned state MUST NOT be used before Verify succeeds, unless server_confirm is omitted ({{omit-confirmation}}).

~~~
OQUAKE+.Respond

Input:
- v, part of the client's registered verifier, a byte string of Nv bytes
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string
- init_msg, the initiator's protocol message
- pk, part of the client's registered verifier, a KEM public key
- kem_blind, part of the client's registered verifier, a byte string of 32 bytes

Output:
- state, opaque state for the server to store values to complete the protocol
- resp_msg, a protocol message for the responder to send to the initiator

Parameters:
- OQUAKE, parameterized instance of OQUAKE
- PC, password confirmation ({{pwconf}})

def Respond(v, public_context, secret_context, init_msg, pk, kem_blind):
  oquake_resp, SK, th = OQUAKE.Respond(v, public_context, secret_context, init_msg)
  state, challenge = PC.Challenge(SK, th, pk, kem_blind)
  resp_msg = (oquake_resp, challenge)
  return state, resp_msg
~~~

### Finish {#oquakeplus-finish}

As part of Finish, the client finishes OQUAKE and responds to the password confirmation challenge.
It raises an AuthenticationError if password confirmation fails.

~~~
OQUAKE+.Finish

Input:
- state, opaque state produced by Init
- resp_msg, the responder's protocol message

Output:
- client_key, a byte string of Nkey bytes
- response, a protocol message for the client to send to the server
- th, transcript hash, a byte string of KDF.Nx bytes

Exceptions:
- AuthenticationError, raised when the password confirmation values do not match

Parameters:
- OQUAKE, parameterized instance of OQUAKE
- PC, password confirmation ({{pwconf}})

def Finish(state, resp_msg):
  (ctx, seed) = state
  (oquake_resp, challenge) = resp_msg

  SK, th = OQUAKE.Finish(ctx, oquake_resp)

  return PC.Respond(SK, th, seed, challenge)
~~~

### Verify {#oquakeplus-verify}

Verify checks the client's password confirmation value and outputs the server's session key and the transcript hash.

~~~
OQUAKE+.Verify

Input:
- state, opaque state produced by Respond
- response, the client's response message, a byte string

Output:
- server_key, a byte string of Nkey bytes
- th, transcript hash, a byte string of KDF.Nx bytes

Exceptions:
- AuthenticationError, raised when the password confirmation values do not match

Parameters:
- PC, password confirmation ({{pwconf}})

def Verify(state, response):
  return PC.Verify(state, response)
~~~

## CPaceOQUAKE+ Protocol {#CPaceOQUAKEplus}

CPaceOQUAKE+ is the hybrid aPAKE obtained by applying the transformation of {{apake-transform}} to CPaceOQUAKE ({{CPaceOQUAKE}}).
It is a five-message aPAKE that provides security against both classical and quantum-capable attackers.
The first three messages are entirely CPaceOQUAKE, while the last two messages are the password confirmation protocol.
An application can omit the last message; see {{omit-confirmation}}.
To ensure hybrid post-quantum security, the KEM used during password confirmation must be a hybrid KEM.

Upon successful completion of the entire protocol, the client and server will share a
symmetric key that was authenticated by knowledge of the password. The protocol
aborts if the password did not match.

A complete protocol flow is shown below. The client needs the salt before the
protocol starts; see {{gen-verifiers}}.

~~~aasvg
Client: PRS,salt,U,S,pub_ctx,sec_ctx   Server: v,pk,kem_blind,
                                               pub_ctx,sec_ctx
          ----------------------------------------
ctx, msg1 = CPaceOQUAKE+.Init(                 |
  PRS,salt,U,S,pub_ctx,sec_ctx)                |
            |               msg1               |
            |--------------------------------->|
            |                                  |
            |                ctx, msg2 = CPaceOQUAKE+.Respond(
            |                   v,pub_ctx,sec_ctx,msg1)
            |                                  |
            |               msg2               |
            |<---------------------------------|
            |                                  |
  ctx, msg3 = CPaceOQUAKE+.InitiatorContinue(  |
     ctx,msg2)                                 |
            |               msg3               |
            |--------------------------------->|
            |                                  |
            |       ctx, msg4 = CPaceOQUAKE+.ResponderContinue(
            |         ctx,msg3,pk,kem_blind)
            |                                  |
            |               msg4               |
            |<---------------------------------|
            |                                  |
  client_key, msg5, th = CPaceOQUAKE+.InitiatorFinish(
     ctx,msg4)                                 |
            |               msg5               |
            |--------------------------------->|
            |                                  |
            |  server_key, th = CPaceOQUAKE+.ResponderFinish(ctx,msg5)
            |                                  |
          ----------------------------------------
      output client_key                 output server_key
~~~

The protocol has six functions. Init, InitiatorContinue, and InitiatorFinish are
intended to be called by the client, and Respond, ResponderContinue, and
ResponderFinish are intended to be called by the server. The byte-level encoding
of the protocol messages is specified in {{encodings}}.

### Client Initiation

Init derives the verifier material from the client's password ({{gen-verifiers}})
and initiates CPaceOQUAKE with the verifier's v instead of PRS.

~~~
CPaceOQUAKE+.Init

Input:
- PRS, password-related string, a byte string
- salt, client-specific salt, a byte string
- U and S, client and server identifiers used at registration
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string

Output:
- state, opaque state for the initiator to store
- msg, a protocol message for the initiator to send to the responder

Parameters:
- CPaceOQUAKE, parameterized instance of CPaceOQUAKE

def Init(PRS, salt, U, S, public_context, secret_context):
  (v, seed) = GenVerifierMaterial(PRS, salt, U, S)
  ctx, msg = CPaceOQUAKE.Init(v, public_context, secret_context)
  return State(ctx, v, seed, public_context, secret_context), msg
~~~

### Server Response

Respond responds to CPaceOQUAKE using the verifier's v instead of PRS.

~~~
CPaceOQUAKE+.Respond

Input:
- v, part of the client's registered verifier, a byte string of Nv bytes
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string
- init_msg, the message received from the client

Output:
- state, opaque state for the responder to store
- msg, a protocol message for the responder to send to the initiator

Parameters:
- CPaceOQUAKE, parameterized instance of CPaceOQUAKE

def Respond(v, public_context, secret_context, init_msg):
  ctx, msg = CPaceOQUAKE.Respond(v, public_context, secret_context, init_msg)
  return ctx, msg
~~~

### Client Continue

InitiatorContinue completes CPaceOQUAKE.
The client retains the resulting key SK and transcript hash th for password confirmation.
SK MUST NOT be used as a session key.

~~~
CPaceOQUAKE+.InitiatorContinue

Input:
- state, the state generated by CPaceOQUAKE+.Init
- msg2, the message received from the server

Output:
- state, opaque state for the initiator to store
- msg, a protocol message for the initiator to send to the responder

Parameters:
- CPaceOQUAKE, parameterized instance of CPaceOQUAKE

def InitiatorContinue(state, msg2):
  (ctx, v, seed, public_context, secret_context) = state
  SK, msg, th = CPaceOQUAKE.InitiatorFinish(v, public_context, secret_context,
                                            ctx, msg2)
  return State(SK, th, seed), msg
~~~

### Server Continue

ResponderContinue completes CPaceOQUAKE and challenges the client to confirm its password, using the password confirmation protocol as described in {{pwconf}}.
The server_key held in the returned state MUST NOT be used before ResponderFinish succeeds, unless server_confirm is omitted ({{omit-confirmation}}).

~~~
CPaceOQUAKE+.ResponderContinue

Input:
- state, the state generated by CPaceOQUAKE+.Respond
- msg3, the message received from the client
- pk, part of the client's registered verifier, a KEM public key
- kem_blind, part of the client's registered verifier, a byte string of 32 bytes

Output:
- state, opaque state for the responder to store
- msg, a protocol message for the responder to send to the initiator

Parameters:
- CPaceOQUAKE, parameterized instance of CPaceOQUAKE
- PC, password confirmation ({{pwconf}})

def ResponderContinue(state, msg3, pk, kem_blind):
  SK, th = CPaceOQUAKE.ResponderFinish(state, msg3)
  return PC.Challenge(SK, th, pk, kem_blind)
~~~

### Client Finish

The client responds to the password confirmation challenge, obtaining the CPaceOQUAKE+ session key, the confirmation value it sends to the server, and the transcript hash.
The client aborts if the server's password confirmation value does not verify.

~~~
CPaceOQUAKE+.InitiatorFinish

Input:
- state, the state generated by CPaceOQUAKE+.InitiatorContinue
- msg4, the message received from the server

Output:
- client_key, a shared secret of Nkey bytes
- msg, a protocol message for the initiator to send to the responder
- th, transcript hash, a byte string of KDF.Nx bytes

Exceptions:
- AuthenticationError, raised when the password confirmation values do not match

Parameters:
- PC, password confirmation ({{pwconf}})

def InitiatorFinish(state, msg4):
  (SK, th, seed) = state
  return PC.Respond(SK, th, seed, msg4)
~~~

### Server Finish

The server finishes the protocol by verifying the client's password confirmation value, and outputs the session key and the transcript hash.

~~~
CPaceOQUAKE+.ResponderFinish

Input:
- state, the state generated by CPaceOQUAKE+.ResponderContinue
- msg5, the message received from the client

Output:
- server_key, a shared secret of Nkey bytes
- th, transcript hash, a byte string of KDF.Nx bytes

Exceptions:
- AuthenticationError, raised when the password confirmation values do not match

Parameters:
- PC, password confirmation ({{pwconf}})

def ResponderFinish(state, msg5):
  return PC.Verify(state, msg5)
~~~

# Configurations {#configurations}

The PAKEs in this document are instantiated by selecting cryptographic components,
such as a KEM, BUA-sKEM, KDF, and KSF. Since the augmented PAKEs may have duplicate components
they are distinguished by "PC-" and "PAKE-" prefixes, e.g., PC-KDF and
PC-KSF belong to the PAKE-to-aPAKE transformation ({{apake-transform}}).

This section gives RECOMMENDED configurations for each of the four protocols specified in this document, in order of preference.
{{test-vectors}} contains test vectors for the first configuration of each protocol.
The preferred configuration of each protocol uses ML-KEM-1024 in OQUAKE, which provides a larger security margin ({{params-oquake}}).
Where CPace is used, it uses X25519, CPace's primary recommended suite, and CPaceOQUAKE+ uses X-Wing as the password confirmation KEM.
The configurations with ML-KEM-768 can be considered when the bandwidth cost would otherwise be too high.
Each configuration has an identifier containing the protocol name, CPace group (if any), BUA-sKEM, and password confirmation KEM (if any), each in lowercase and without punctuation.

The configurations are nested in the same way as the protocols themselves.
Each names only the components the protocol uses, and a protocol that builds on another inherits that protocol's entries.
As a result, each CPaceOQUAKE+ configuration combines the entries of the corresponding CPaceOQUAKE and OQUAKE+ configurations, with a hybrid KEM in place of ML-KEM as the password confirmation KEM.

The parameters in {{config-params}} are common to all configurations.

Each DST below is a randomly generated 32-byte string, given in hexadecimal.
When one protocol builds on another, the DST of the outermost configuration applies
throughout, including within the inner protocols. The DST
values below are therefore alternatives, not values to be combined: an
implementation of CPaceOQUAKE+ uses the CPaceOQUAKE+ DST for CPace, OQUAKE, and
password confirmation alike.

## Common Parameters {#config-params}

The RECOMMENDED parameters, common to all configurations below, are (see
{{params}}):

- Nv = 32 (used only by the augmented protocols, OQUAKE+ and CPaceOQUAKE+)
- Nkc = 32
- Nr = 64
- Nkey = 32

## OQUAKE {#config-oquake}

OQUAKE ({{oquake}}) is a symmetric PAKE, so it requires neither a verifier-deriving
KSF nor the KEM used for password confirmation. Because only one KDF is present,
no prefix is needed.

### OQUAKE with ML-KEM-1024 {#config-oquake-mlbuaskem1024}

This is the preferred configuration ({{params-oquake}}).

- Identifier: `oquake-mlbuaskem1024`
- BUA-sKEM: ML-BUA-sKEM-1024 ({{tab-ml-bua-skem}})
- KDF: HKDF-SHA-256
- DST: 601ed384c5775ddd3021f51a4660fff24bf4eaa7845a958b2cade75289d184cd

### OQUAKE with ML-KEM-768 {#config-oquake-mlbuaskem768}

This configuration can be considered when the bandwidth cost would otherwise be too high.

- Identifier: `oquake-mlbuaskem768`
- BUA-sKEM: ML-BUA-sKEM-768 ({{tab-ml-bua-skem}})
- KDF: HKDF-SHA-256
- DST: ca45261d9fe329b856389ebbf7f37ffa76c0034d8fc356454e1291d7d23e2045

## OQUAKE+ {#config-oquakeplus}

OQUAKE+ ({{oquakeplus}}) applies the PAKE-to-aPAKE transformation to OQUAKE, which
introduces the KEM used to carry the confirmation challenge and the KSF used to
derive v and the seed at registration. It therefore extends
{{config-oquake}} with the "PC-" entries, and the OQUAKE KDF takes the "PAKE-"
prefix to distinguish it from the password confirmation KDF. Both configurations use the
same ML-KEM parameter set in OQUAKE and for password confirmation.

### OQUAKE+ with ML-KEM-1024 {#config-oquakeplus-mlbuaskem1024-mlkem1024}

This is the preferred configuration ({{params-oquake}}).

- Identifier: `oquakeplus-mlbuaskem1024-mlkem1024`
- BUA-sKEM: ML-BUA-sKEM-1024 ({{tab-ml-bua-skem}})
- PAKE-KDF: HKDF-SHA-256
- KEM: ML-KEM-1024 {{FIPS203}}, where Nseed = 64, Nct = 1568, and Npk = 1568.
- PC-KDF: HKDF-SHA-256
- PC-KSF: scrypt(N = 32768, r = 8, p = 1)
- DST: 284e89132c00ba4f49e66d0af9e63c4c8efa701ce4b66bb6fcf1ce9cc5c35be1

### OQUAKE+ with ML-KEM-768 {#config-oquakeplus-mlbuaskem768-mlkem768}

This configuration can be considered when the bandwidth cost would otherwise be too high.

- Identifier: `oquakeplus-mlbuaskem768-mlkem768`
- BUA-sKEM: ML-BUA-sKEM-768 ({{tab-ml-bua-skem}})
- PAKE-KDF: HKDF-SHA-256
- KEM: ML-KEM-768 {{FIPS203}}, where Nseed = 64, Nct = 1088, and Npk = 1184.
- PC-KDF: HKDF-SHA-256
- PC-KSF: scrypt(N = 32768, r = 8, p = 1) {{!SCRYPT=RFC7914}}
- DST: 2a1a96e307871d45a9739c7193eeb04d6f52d17c67a52f762e5aae17df1ee5e6

## CPaceOQUAKE {#config-cpaceoquake}

CPaceOQUAKE ({{CPaceOQUAKE}}) runs CPace as Stage 1 and OQUAKE as Stage 2, so it extends {{config-oquake}} with the CPace group and hash.
The first two configurations use CPace's primary recommended suite.
The third uses P-384, the curve of the hybrid KEM in the corresponding CPaceOQUAKE+ configuration.

### CPaceOQUAKE with X25519 and ML-KEM-1024 {#config-cpaceoquake-x25519-mlbuaskem1024}

This is the preferred configuration: it uses ML-KEM-1024 in OQUAKE ({{params-oquake}}) and CPace's primary recommended suite.
This corresponds to the `oquake-mlbuaskem1024` configuration.

- Identifier: `cpaceoquake-x25519-mlbuaskem1024`
- CPace-Group: CPACE-X25519-SHA512 {{Section 5 of CPACE}}
- CPace-Hash: SHA-512
- BUA-sKEM: ML-BUA-sKEM-1024 ({{tab-ml-bua-skem}})
- PAKE-KDF: HKDF-SHA-256
- DST: 443e3089985f0f8dddfb20cc5e8618f447bdcfe6dd39abb23911cd784c075120

### CPaceOQUAKE with X25519 and ML-KEM-768 {#config-cpaceoquake-x25519-mlbuaskem768}

This configuration can be considered when the bandwidth cost would otherwise be too high.
This corresponds to the `oquake-mlbuaskem768` configuration.

- Identifier: `cpaceoquake-x25519-mlbuaskem768`
- CPace-Group: CPACE-X25519-SHA512 {{Section 5 of CPACE}}
- CPace-Hash: SHA-512
- BUA-sKEM: ML-BUA-sKEM-768 ({{tab-ml-bua-skem}})
- PAKE-KDF: HKDF-SHA-256
- DST: c2ef9d7f73324735ec5614f331fa49c86c05be3430996c46816fca59d778380b

### CPaceOQUAKE with P-384 and ML-KEM-1024 {#config-cpaceoquake-p384-mlbuaskem1024}

This configuration uses P-384, the curve of the hybrid KEM in `cpaceoquakeplus-p384-mlbuaskem1024-mlkem1024p384`.
This corresponds to the `oquake-mlbuaskem1024` configuration.

- Identifier: `cpaceoquake-p384-mlbuaskem1024`
- CPace-Group: CPACE-P384_XMD:SHA-384_SSWU_NU_-SHA384 {{Section 5 of CPACE}}
- CPace-Hash: SHA-384
- BUA-sKEM: ML-BUA-sKEM-1024 ({{tab-ml-bua-skem}})
- PAKE-KDF: HKDF-SHA-256
- DST: 1c8604e01071bc2bee8e4132399ded88a9f83c23ed8ab7130d2d2e0b597c0fb5

## CPaceOQUAKE+ {#config-cpaceoquakeplus}

CPaceOQUAKE+ ({{CPaceOQUAKEplus}}) applies the PAKE-to-aPAKE transformation to CPaceOQUAKE.
Since it targets hybrid security, its password confirmation KEM is a hybrid KEM.

### CPaceOQUAKE+ with X25519, ML-KEM-1024, and X-Wing {#config-cpaceoquakeplus-x25519-mlbuaskem1024-xwing}

This is the preferred configuration: it uses ML-KEM-1024 in OQUAKE ({{params-oquake}}) and CPace's primary recommended suite.
This corresponds to the `cpaceoquake-x25519-mlbuaskem1024` configuration.
Note that it requires both ML-KEM-1024 and ML-KEM-768.
The latter is used by X-Wing.

- Identifier: `cpaceoquakeplus-x25519-mlbuaskem1024-xwing`
- CPace-Group: CPACE-X25519-SHA512 {{Section 5 of CPACE}}
- CPace-Hash: SHA-512
- BUA-sKEM: ML-BUA-sKEM-1024 ({{tab-ml-bua-skem}})
- PAKE-KDF: HKDF-SHA-256
- KEM: X-Wing {{XWING}}, where Nseed = 32, Nct = 1120, and Npk = 1216.
- PC-KDF: HKDF-SHA-256
- PC-KSF: scrypt(N = 32768, r = 8, p = 1)
- DST: 7de162c387ba1bad9c790e7e56bd245d6753d045185cbc3972eba34ddac1a9db

### CPaceOQUAKE+ with P-384, ML-KEM-1024, and MLKEM1024-P384 {#config-cpaceoquakeplus-p384-mlbuaskem1024-mlkem1024p384}

This configuration can be considered when a single ML-KEM parameter set and a single curve are preferred: it uses ML-KEM-1024 and P-384 throughout.
This corresponds to the `cpaceoquake-p384-mlbuaskem1024` configuration.

- Identifier: `cpaceoquakeplus-p384-mlbuaskem1024-mlkem1024p384`
- CPace-Group: CPACE-P384_XMD:SHA-384_SSWU_NU_-SHA384 {{Section 5 of CPACE}}
- CPace-Hash: SHA-384
- BUA-sKEM: ML-BUA-sKEM-1024 ({{tab-ml-bua-skem}})
- PAKE-KDF: HKDF-SHA-256
- KEM: MLKEM1024-P384 {{CONCRETE-HYBRID-KEMS}}, where Nseed = 32, Nct = 1665, and Npk = 1665.
- PC-KDF: HKDF-SHA-256
- PC-KSF: scrypt(N = 32768, r = 8, p = 1)
- DST: d8fcdaf8c2c8c429a2ff93ff658d07050017487dc367d11cabb54f2a7dd2b5fd

### CPaceOQUAKE+ with X25519, ML-KEM-768, and X-Wing {#config-cpaceoquakeplus-x25519-mlbuaskem768-xwing}

This configuration can be considered when the bandwidth cost would otherwise be too high.
This corresponds to the `cpaceoquake-x25519-mlbuaskem768` configuration.

- Identifier: `cpaceoquakeplus-x25519-mlbuaskem768-xwing`
- CPace-Group: CPACE-X25519-SHA512 {{Section 5 of CPACE}}
- CPace-Hash: SHA-512
- BUA-sKEM: ML-BUA-sKEM-768 ({{tab-ml-bua-skem}})
- PAKE-KDF: HKDF-SHA-256
- KEM: X-Wing {{XWING}}, where Nseed = 32, Nct = 1120, and Npk = 1216.
- PC-KDF: HKDF-SHA-256
- PC-KSF: scrypt(N = 32768, r = 8, p = 1)
- DST: 07d746a69c979f51e46d0051f0878a05ac5ec457d93c72ec6b814f528aae46f2


## Defining New Configurations

Other documents can define configurations as needed for their use case, subject to the following requirements:

1. When targeting hybrid security, KEM MUST be a hybrid KEM, i.e., one that achieves both classical and post-quantum security.
2. The parameters must be chosen so they correspond with this KEM. E.g., Nseed must have the correct length.
3. A configuration MUST specify every component used by the protocol it configures,
   as listed in the corresponding subsection above.
4. DST SHOULD be a randomly generated 32-byte string, distinct from the DST of any
   other configuration.
5. A configuration MUST meet the following minimums, which follow from the analysis in {{params}}:
   - The BUA-sKEM and the KEM achieve b >= 128 against both classical and quantum
     attackers ({{params-oquake}}), which excludes ML-KEM-512.
   - Nr >= 64, Nkc >= 32, Nv >= 32, and Nkey >= 32.
   - The CPace hash produces at least 32 bytes.
   - For ML-BUA-sKEM, Kemeleon.t >= 132, or another encoding whose statistical distance
     from uniform is at most 2^-128 per public key ({{params-oquake}}).

It is RECOMMENDED that a configuration of CPaceOQUAKE+ use the same curve in CPace and in the hybrid password confirmation KEM.
Using the same ML-KEM parameter set in OQUAKE and in the password confirmation KEM further reduces code size.

For instance, one possible additional configuration for CPaceOQUAKE+ uses P-256 throughout:

- CPace-Group: CPACE-P256_XMD:SHA-256_SSWU_NU_-SHA256 {{Section 5 of CPACE}}
- CPace-Hash: SHA-256
- BUA-sKEM: ML-BUA-sKEM-768 ({{tab-ml-bua-skem}})
- PAKE-KDF: HKDF-SHA-256
- KEM: MLKEM768-P256 {{CONCRETE-HYBRID-KEMS}}, where Nseed = 32, Nct = 1153, and Npk = 1249.
- PC-KDF: HKDF-SHA-256
- PC-KSF: scrypt(N = 32768, r = 8, p = 1)
- DST: 38a518ec4b20d388f06504e78d6307b000f11e82fa3e5ff575b526129cf70953

# Implementation Considerations

Some functions included in this specification are fallible (as noted by their ability
to raise exceptions). The explicit errors generated
throughout this specification, along with conditions that lead to each error,
are as follows:

- AuthenticationError: Password confirmation fails at the client or server;
  {{pwconf}}
- CPaceError: An invalid value, such as a point that yields the group identity,
  was encountered in the CPace stage; {{cpace}}
- EncapsError: KEM encapsulation failed; {{deps-kem}}
- DecapsError: KEM decapsulation failed; {{deps-kem}}

Note that a decapsulation failure inside OQUAKE.Finish ({{quake-finish}}) is not
surfaced as a DecapsError. As described in {{quake-finish}}, OQUAKE.Finish returns
a random key in that case so that a failure is indistinguishable from a mismatched
password. Implementations SHOULD NOT convert this into a distinguishable error, as
doing so would leak whether the peer holds the correct PRS.

The KEMs in the configurations of this document use implicit rejection: decapsulating a
ciphertext of the correct length does not fail, but yields an unrelated key. A DecapsError
therefore only results from malformed input.

Similarly, ML-BUA-sKEM.Encaps does not fail, because Kemeleon.DecodeEk outputs a valid ML-KEM
encapsulation key for every input of Npk bytes. In password confirmation, KEM.Encaps fails only
if the registered public key pk is not a valid public key, which the server can check when it
stores the verifier.

Beyond these explicit errors, CPaceOQUAKE+ implementations can produce implicit errors.
For example, if protocol messages sent between client and server do not match
their expected size, an implementation should produce an error.

The errors in this document are meant as a guide for implementors. They are not an
exhaustive list of all the errors an implementation might emit. For example, an
implementation might run out of memory.

# Security Considerations

This section discusses security considerations for the protocols specified in
this document.

## Hybrid Design {#hybrid-design}

CPaceOQUAKE and CPaceOQUAKE+ are hybrid PAKE protocols, meaning that the overall
protocol remains secure so long as either the classical assumptions underlying
CPace, i.e., the gap Diffie-Hellman assumption, or the post-quantum assumptions,
i.e., D-MLWE used by OQUAKE, hold. This protects against vulnerabilities in
either the classical or post-quantum components.

Moreover, OQUAKE does not unconditionally hide the password: an attacker that
can break the D-MLWE assumption can distinguish ML-KEM public keys and
ciphertexts from random bitstrings, and can therefore mount an offline
dictionary attack against the OQUAKE transcript. {{retroactive-recovery}} treats
this failure mode, and its consequences for both the password and the session
key, in general terms; the sequential composition described in
{{CPaceOQUAKE}} is what prevents it from applying to the original PRS here,
since OQUAKE receives an effective password derived from (PRS, SK1) rather than
PRS itself.

The benefits of this hybrid protection come at the cost of protocol and round
complexity. From a protocol perspective, beyond two independent PAKEs treated
nearly as black boxes, additional protocol logic is needed to combine the PAKEs
together and produce a shared secret based on both PAKEs. From a round
perspective, the hybrid PAKE introduces additional round trips, complicating
integration into higher-level protocols like TLS. Finally, the hybrid protocol
is comparatively new and has not yet received significant peer review
(compared to the non-hybrid PAKEs). However, the core sequential-composition
design has been independently analyzed by at least three different groups,
improving overall confidence in the design.

## Retroactive Password and Session Key Recovery {#retroactive-recovery}

A PAKE is unconditionally password hiding if its protocol messages remain statistically
independent of the password even when every computational assumption underlying the PAKE fails.
Few efficient PAKEs achieve this: CPace does, but
OQUAKE does not, and this is true of PAKEs generally, not just the ones specified in this document.
This property is what makes CPace safe to use as the first stage of a sequential combiner: its
output key is never subjected to a verification check on its own, so an attacker who breaks the
Diffie-Hellman assumption learns nothing from the CPace messages alone. It does not, by itself,
mean that a session key derived by CPace stays safe once it *is* checked against something -- e.g.,
confirmed directly, or used to encrypt subsequent traffic, as happens in an ordinary standalone
deployment. This section generalizes that latter observation into a broader principle and uses it
to answer two concrete questions: which classical PAKEs allow a quantum-capable attacker to
retroactively recover a session when deployed this ordinary way, and does the same hold for
EKE-style PAKEs.

The general principle is this: for any PAKE that is not unconditionally password hiding, breaking
its underlying computational assumption -- whether that happens contemporaneously or, as with a
future quantum computer, retroactively against a transcript recorded today -- allows an attacker
to mount an offline dictionary attack against that transcript, provided the attacker also has some
way to check a candidate password against it. In practice that check comes for free: an explicit
password-confirmation message, present in most aPAKEs, serves directly as the check, and even
without one, any subsequent application traffic encrypted under the resulting session key serves
the same purpose. Once the attacker recovers the password this way, two consequences follow. First,
the attacker can derive the session key of the harvested session and decrypt its traffic, exactly
as in ordinary Harvest Now, Decrypt Later against unauthenticated key exchange. Second, and unlike
that ordinary case, the attacker also now holds a long-lived credential: they can impersonate the
client in every future session until the password is changed. Retroactive password recovery is
therefore strictly worse for a PAKE than HNDL is for plain key exchange, which is why deploying a
post-quantum KEM only at the transport layer, as discussed in {{related-work}}, does not address
the risk that a classical PAKE poses on its own.

This principle applies directly to classical Diffie-Hellman-based PAKEs, including CPace, SPAKE2,
and SPAKE2+, when deployed in the ordinary way, i.e., with the resulting session key confirmed or
used directly, rather than fed onward as an opaque input to a second PAKE stage as in
{{CPaceOQUAKE}}: their protocol messages are deterministic functions of a
password-derived generator and per-session exponents, so a quantum-capable attacker able to solve
the discrete logarithm or Diffie-Hellman problem can, for each candidate password, recompute the
generator, recompute the candidate shared secret from the recorded messages, and check it against
the verification signal described above. SPAKE2+ is a sharper case:
its password-derived offset is applied to fixed, standardized constant
points (commonly written M and N) shared by every server and session on a given group, rather than
to a fresh per-session generator as in CPace. Solving a single discrete logarithm instance for that
group -- e.g., the discrete log of M or N, using a quantum computer, even a slow one -- therefore
yields a capability reusable against any server using that group: a single live exchange with the
server, plus a confirmation or subsequent-traffic verification signal, is then enough to
brute-force the password offline with classical computation alone.

This principle applies equally to EKE-style PAKEs, including one-encryption (OEKE)
variants such as the KEM-based compiler OQUAKE: the first protocol flow
is a password-encrypted public key, so an attacker who recovers the password by breaking
the KEM's hardness assumption (D-MLWE, for the ML-KEM-based instantiation in this document) can
decrypt that flow and derive the identical session key an honest party would. The password-hiding
failure of OQUAKE described in {{hybrid-design}} is the concrete
instance of this general EKE-style argument for the specific construction used in this document.

This is precisely why the sequential hybrid composition specified in this document is valuable:
an attacker must break both a classical and a post-quantum hard problem simultaneously to
retroactively recover the password protected by CPaceOQUAKE(+), a strictly stronger guarantee than
any single-primitive PAKE, classical or post-quantum alone, can offer.

## Identities {#identities}

Client and server identities are essential to authenticated key exchange protocols,
and PAKEs are no exception. This section discusses the role and importance of
identities in the PAKE protocols specified in this document.

### Symmetric PAKE identities {#symmetric-identities}

PAKEs are often analyzed in the universal composability (UC) framework,
which imposes several requirements on the protocols: (1) the existence
of a globally-unique session identifier associated with each protocol invocation,
and (2) unique party identifiers. Both are considered as inputs to PAKEs, along
with the password itself. In practice, however, computing or agreeing on session
and party identifiers is non-trivial and cumbersome. For example, agreeing on a
globally unique session identifier requires a protocol to run before the PAKE.
Moreover, assigning identifiers to parties -- especially in symmetric PAKE settings --
is problematic as there are rarely pragmatic choices to be made for each party's
identifier. IP addresses are not always unique, PKI or some other registry
mechanism for assigning names may not exist, and so on.

Intuitively, in symmetric settings, passwords are the only secret input to the
PAKE protocol; party identities are assumed to be public. As such, an adversary
is assumed to know these identifiers. Fortunately, there exists a UC
model in which symmetric PAKEs such as CPace are proven secure
without requiring party or session identifiers -- the bare PAKE
model {{?BARE-PAKE=DOI.10.1007/978-3-031-68379-4_6}}.
The UC bare PAKE model, and proof of security for CPace in this model,
demonstrate that PAKEs are universally composable without relying on
unique party or session identifiers. We believe that the current proof
of security of OQUAKE in {{ABJ25}} can be extended to show that NoIC,
the basis of OQUAKE, realizes the Bare PAKE model as well, although
we note that this proof has not been published yet.

As such, for the PAKEs in {{CPaceOQUAKE}}, both the party and session identifier
are optional. Applications are free to choose values for these identifiers
if applicable, but they are not required for security.

[[OPEN ISSUE: adjust the requirements for the identities in OQUAKE on the basis on the bare PAKE analysis]]

### Asymmetric PAKE identities {#asymmetric-identities}

In contrast to the symmetric PAKE setting, party identities in the asymmetric
PAKE setting play a different role. The very nature of the asymmetric PAKE
is that one server, with many different registered passwords, can authenticate
many different clients. Consequently, when the protocol runs, the server
needs some way to determine which password registration to use in the protocol.
Beyond ensuring that the server is authenticating the correct client, the
client's identity is what helps the server make this selection.

However, the server identifier carries a similar burden. Indeed,
the server identifier is used to distinguish distinct server instances
from each other so, for example, a client cannot mistakenly authenticate
with server A when communicating with server B. This is especially
important if the client re-uses their identifier across server instances,
since a password registration for server A would then be valid for server B
if the server identity were not incorporated into the protocol.

Based on this, client and server identities are RECOMMENDED for the asymmetric
PAKEs specified in this document ({{augmented-pakes}}). Both
client and server identities can be long-lived, e.g., a client identity
could be an email address and a server identity could be a domain name.

The identifiers input to GenVerifierMaterial identify the registration. They do not have to be equal to any identifiers in the public_context, which bind an individual session, e.g., to network addresses.

Practically, applications should be mindful of what happens when these
identities change. Since they are both included in the password verifier
(see {{gen-verifiers}}), changing either identifier will require the
verifier to be re-computed and the client to be re-registered. For a single
client, this change is minimal, but for a single server, which can have
many registered clients, this change can be expensive. Applications therefore
ought to consider the longevity and uniqueness of their party identifiers
when instantiating these protocols.

## Verifier Compromise {#verifier-compromise}

An attacker that obtains a client's verifier (v, pk, kem_blind) can perform an offline password guessing attack against it, and it can impersonate the server to that client.
This is inherent to augmented PAKEs.
Such an attacker, however, cannot impersonate the client without first recovering the password, which requires the seed (or a decapsulation key for this pk).
An attacker that knows v but not both pk and kem_blind can complete the symmetric PAKE, but it cannot pass password confirmation in either role:
computing client_confirm requires encapsulating to the key pair that the client derives, which requires pk and kem_blind, and computing server_confirm requires the seed.
Since an attacker that knows v can send the client ciphertexts of its choice, the KEM must be IND-CCA secure ({{deps-kem}}).

## Timing Attacks and Tempo {#timing-and-tempo}

OQUAKE (without the fix from {{TEMPO}}) is subject to a timing attack
due to how the ML-KEM expands the key-generation seed (rho) to a matrix (A).
An internal function — SampleNTT — uses rejection sampling based on the seed
and therefore is variable time. In NoIC / OQUAKE, after a sender password-encrypts
a public key, an attacker can perform an offline dictionary attack based on
this key in the following way:

1. Password-decrypt the authenticated public key using a candidate password.
2. Time the seed-to-matrix expansion step using this candidate public key and
compare it against the known timing target.

The Tempo fix addresses this issue by ensuring that input to SampleNTT is not
secret-dependent.

The PAKE-to-aPAKE transformation ({{apake-transform}}) faces a similar issue.
The client derives its KEM key pair from a seed that is derived from the password, and for the ML-KEM-based KEMs in this document, both key derivation and decapsulation expand a matrix derived from that seed using variable-time rejection sampling.
If the seed depended only on public information and the password, then an attacker that measures this time could perform an offline password guessing attack.
The PAKE-to-aPAKE transformation therefore derives the key pair from the seed and kem_blind, a secret random part of the verifier that the server sends to the client.
To ensure that the attacker does not observe kem_blind, it is encrypted with a key derived from the symmetric PAKE's session key ({{pwconf}}).
An attacker that does not hold the verifier does not know kem_blind and cannot relate the timing to a password guess.
Note that an attacker that knows v can make the client use a kem_blind of its choice, but such an attacker can already perform an offline password guessing attack against v.

## Related Work {#related-work}

This section relates the protocols in this document to existing standardized PAKEs and to the broader post-quantum
PAKE research literature, and addresses why this problem is not already solved, why it remains an
active research problem, and why the state of the art is nonetheless mature enough for CFRG to
engage with it.

### Existing Solutions and Their Gaps

OPAQUE-3DH and SPAKE2+ are standardized aPAKEs, and CPace {{!CPACE=I-D.irtf-cfrg-cpace}} is an
emerging symmetric PAKE, but all three are purely classical constructions: none provide
security against a quantum-capable attacker. NIST's post-quantum cryptography standardization
effort has, to date, produced key encapsulation mechanisms {{FIPS203}} and signature schemes, but
no PAKE. A seemingly obvious fix is to run an existing classical PAKE inside, or alongside, a
post-quantum or hybrid KEM already deployed at the transport layer (e.g., hybrid key exchange in
TLS 1.3). This does not solve the PAKE-specific problem: it protects the resulting session key
against a future quantum-capable attacker, but does nothing for the classical PAKE's own handshake
transcript. If that classical PAKE's underlying hard problem is later broken, the *password*
itself becomes retroactively recoverable from the harvested transcript, as detailed in
{{retroactive-recovery}}, independent of whatever post-quantum protection was applied to the
surrounding transport. This is the concrete gap that simply layering a post-quantum KEM around an
existing classical PAKE does not close, and it is the gap this document addresses directly.

### Ongoing Research

[[EDITOR'S NOTE: remove in the final version of this document]]

The compiler techniques underlying this document's design are recent and remain under active
development. The KEM-to-PAKE compiler underlying OQUAKE {{ABJ25}}, the timing side-channel fix
required to use it safely with ML-KEM {{TEMPO}}, the PAKE combiners used to hybridize it with
CPace {{HR24}}{{LL24}}, and closely related asymmetric PAKE compilers {{Gu24}}{{LLH24}} were all
published in 2024 and 2025. {{GRSV25}} takes a different approach, constructing a hybrid PAKE
from a combiner of obfuscated KEMs; this relies on a non-standard KEM with larger public keys and
ciphertexts. Kopis {{Kopis26}} is a recently proposed KEM based on Module Learning-with-Rounding and
nearly identical to Saber, whose public keys and ciphertexts are pseudorandom byte strings and whose
algorithms are efficient and constant time with respect to all inputs. A BUA-sKEM based on Kopis would not need
the Kemeleon encoding ({{deps-BUA-sKEM}}), but Kopis has not been standardized. The security analysis backing this document's specific composition
{{VJWYMS25}} is similarly new. Concretely, {{TEMPO}} identifies and fixes a timing side channel in
OQUAKE's ML-KEM key-generation step (see {{timing-and-tempo}}) that was only discovered in 2025,
after OQUAKE's core compiler had already been analyzed, illustrating that this design space is
still being hardened rather than settled. Likewise, this document currently carries an open issue
regarding whether OQUAKE's proof of security extends to the UC bare PAKE model without requiring
party or session identifiers (see {{symmetric-identities}}); this extension is believed to hold on
the basis of the existing NoIC/OQUAKE analysis in {{ABJ25}} but has not yet been published. Finally,
no single compiler approach
has yet converged as the preferred solution across the range of use cases in {{use-cases}}: designs
optimized for case 3 (this document's target) make different tradeoffs than designs optimized for,
e.g., case 1 or case 2.

# Readiness for CFRG Engagement

[[EDITOR'S NOTE: remove in the final version of this document]]

Despite being new, the core sequential-composition design in this document has already been
independently analyzed by at least three different groups, as described in {{hybrid-design}}.
This document also includes test vectors for each protocol it specifies, generated by a
reference implementation, to support independent implementation and verification. The
remaining gaps identified above, most notably the unpublished bare-PAKE proof
extension and the open question of identity requirements, are well-scoped and do not call the core
design into question; they are the kind of item best resolved through the scrutiny that CFRG
engagement itself provides, rather than a prerequisite to starting that engagement.

# IANA Considerations

This document has no IANA actions.

--- back

# Deriving parameters {#params}

CPaceOQUAKE+ composes several protocols, each with its own security analysis {{AHH21}} {{ABJ25}} {{TEMPO}} {{HR24}} {{LLH24}} {{VJWYMS25}}. These analyses include security proofs that, under a set of reasonable assumptions, upper-bound an attacker's advantage. The resulting bounds are typically loose and depend on many variables, such as the maximum number of queries that an attacker is allowed to make to each random oracle and the maximum number of PAKE sessions. For these reasons, these bounds are typically unsuitable for describing the concrete cost of an attack. However, with a few additional assumptions, we can obtain tight enough bounds that allow us to select concrete parameters.

Most of the slack in these bounds is introduced in proof steps that require a computational hardness assumption to hold even when an attacker obtains many instances. For example, an attacker may break a certain protocol if it can solve even just one out of q instances of the Diffie-Hellman problem. The question is how much easier that makes the problem for the attacker. Proofs typically bound the advantage of the attacker as `q * advantage_single`, where `advantage_single` is the advantage an attacker obtains in breaking a single isolated instance in a given amount of time. However, this approach does not accurately describe all computational problems: breaking one of q instances may require almost as much effort as breaking an isolated instance. After all, it may be the case that there is a large fixed computational cost associated with breaking any instance, or the problem may be random self-reducible like the Diffie-Hellman problem.

We measure an attacker's resources by its running time t, which models the number of operations it can perform, including queries to random oracles and engaging in protocol sessions. A protocol has security level λ if, for every t, every attacker running in time at most t has an advantage of at most t/2^λ (in distinguishing the protocol from a simulation around the ideal functionality). Note that, for PAKEs, an attacker can always perform one online password guess per session, which does not count against λ. We target a security level λ = 128 against both classical and quantum attackers. For computational problems whose best known attack has an estimated cost of 2^b operations, we assume that an attacker running in time t has advantage at most t/2^b.

For the parameter selection in this specification, we make some additional assumptions that tighten the bounds obtained by the security proofs. We keep all statistical terms unchanged, but we tighten computational terms like `q * advantage` to `1 * advantage` if they satisfy all of the following conditions:

- The advantage describes an attack against a computational hardness assumption. This excludes, e.g., finding a collision in the output of a random oracle.
- The number q only counts the positions in which a proof may place a challenge instance for the attacker, such as sessions or random oracle queries. This excludes, e.g., a square-root loss in the quantum random oracle model.
- The computational hardness assumption is one for which we know that solving one of q instances is not significantly easier than solving an isolated instance. This holds for the Diffie-Hellman problem due to random self-reducibility, and for ML-KEM by the structure of the best known attacks.

Note that the resulting security levels are therefore estimates rather than proven bounds.

It is currently hard to obtain concrete protocol security estimates against quantum attackers, so we choose to be conservative: we use the Q0 quantum core-SVP metric {{AS22}} to estimate the cost 2^b of the best known quantum attack on ML-KEM. For classical attackers, we use the classical equivalent, which is C0 core-SVP {{Ogilvie26}} {{CMST25}}; see {{ADPS16}} for the core-SVP methodology. Given that the security proofs are in the classical random oracle model, we use a heuristic to estimate security against quantum attackers: we consider a quadratic speed-up {{Grover96}} for random oracle terms in which the attacker must find a value matching a target, but we do not consider a speed-up related to collision finding since quantum collision search is not known to be cheaper than classical collision search once the cost of quantum random access memory is taken into account {{Bernstein09}}.

## Conventions {#params-conventions}

In the subsections below, `q_ses` denotes the number of sessions and `q_X` the number of queries to random oracle X.
The sum of all these `q_*` values is at most t.
A term meets the target if it is at most t/2^128 for every t up to 2^128.
Note that we ignore small constant factors.

## Parameters for OQUAKE {#params-oquake}

In the analysis below, we require estimates for the hardness of ML-KEM.
{{tab-mlkem-costs}} lists the costs 2^b of the best known attacks on ML-KEM that we use, from {{Ogilvie26}} (C0) and {{AS22}} (Q0).

| Parameter set | b against classical attackers (C0) | b against quantum attackers (Q0) |
|---|---|---|
| ML-KEM-512 | 120.3 | 99.7 |
| ML-KEM-768 | 172.3 | 150.0 |
| ML-KEM-1024 | 236.7 | 208.4 |
{: #tab-mlkem-costs title="Estimated log2 cost b of the best known attacks on ML-KEM"}

The analysis of NoIC {{ABJ25}}, applied to the split public key of OQUAKE as in {{TEMPO}}, gives a bound with the following terms.

- BUA-sKEM security: the one-wayness, anonymity, and public key uniformity advantages of the BUA-sKEM are multiplied by `q_ses * q_H1 * q_H2`. These factors count positions for a challenge instance, so we tighten these terms as described in {{params}}. The underlying KEM then needs b >= 128 against both classical and quantum attackers. Both ML-KEM-768 and ML-KEM-1024 achieve this, but ML-KEM-512 does not.
- Attacker-chosen seeds: in an active attack, the responder encapsulates to a public key whose seed ρ was chosen by the attacker. The reduction in {{TEMPO}} loses a factor equal to the number of seeds tried by the attacker because they may pick the most favorable of many matrices. We are not aware of any attacks that benefit from this choice, but we choose to be conservative in this regard. As a margin in case such an attack is found, this document prefers configurations that use ML-KEM-1024 ({{configurations}}): without tightening this term, ML-KEM-1024 still achieves approximately 118 bits of security against classical and 104 bits against quantum attackers, compared with 86 and 75 bits for ML-KEM-768, respectively.
- Public key encoding (Kemeleon): the public key uniformity advantage also includes the statistical distance between encoded KEM public keys and uniform bytestrings. An attacker can test this once per password guess, so this distance must be at most 2^-128 per public key. This treats the encoding's statistical distance separately from the public key uniformity of ML-KEM itself. In the paper, this would require an additional game hop that replaces all encoded public keys by uniform byte strings at a cost of at most t times the per-key distance. Kemeleon.EncodeEk meets this when we set Kemeleon's statistical distance parameter (Kemeleon.t) to at least 132 (Kemeleon allows values that match 76 + 8x).
- Decryption failure: the term `q_ses * δ` requires a failure probability δ of at most 2^-128. ML-KEM's failure probability is below 2^-138 for all parameter sets {{FIPS203}}.
- Randomness s: the proof requires that each message (s, T) sent by an attacker corresponds to at most one password guess. This fails when one of the attacker's hash outputs matches one of the roughly t^2 hash values it obtained earlier, which happens with probability approximately t^3 / 2^(8 * Nr), where s has Nr bytes. We treat this as a search for a target value, which a quantum attacker succeeds in with probability approximately t^4 / 2^(8 * Nr). To achieve a security level of 128 against quantum attackers, we need Nr >= 64.
- Tag h: collisions between tags occur with probability `t^2 / 2^(8 * Nkc)`, which requires Nkc >= 32 for a security level of 128. There is no quantum speed-up here.
- The remaining terms are negligible.

[[EDITOR'S NOTE: The bound in {{ABJ25}} includes the encoding's statistical distance in the public key uniformity advantage, which is multiplied by `q_ses * q_H1 * q_H2`. The requirement on the public key encoding above assumes a proof with a separate game hop for this distance, which still needs to be written down.]]

## Parameters for OQUAKE+ {#params-oquakeplus}

In addition to the terms of the symmetric PAKE ({{params-oquake}}), Theorem 3 of
{{VJWYMS25}} bounds the PAKE-to-aPAKE transformation with the following terms.
Here `q_pb` denotes the number of KSF evaluations.

- KEM security: the IND-CCA advantage of the KEM has a factor `q_ses`, which counts positions for a challenge instance, so we tighten this term. The KEM then needs b >= 128. ML-KEM-768, ML-KEM-1024, and the hybrid KEMs X-Wing and MLKEM768-P256 (which use ML-KEM-768) and MLKEM1024-P384 (which uses ML-KEM-1024) achieve this against both classical and quantum attackers. The IND-CCA advantage also covers decryption failures.
- Verifier collisions: `q_pb^2 / 2^(8 * Nv + 1)` requires Nv >= 32. Collision finding does not get a quantum speed-up.
- Guessing: guessing v or a confirmation value contributes `q_ses / 2^(8 * Nv - 2)` and `q_ses / 2^(8 * Nkc - 2)`, which require Nv >= 16 and Nkc >= 16 to achieve a security level of 128.
- Secret kem_blind: an attacker that does not hold the verifier would have to guess kem_blind to relate the timing of the client's key derivation to a password guess ({{timing-and-tempo}}). This is a search for a target value, so a 32-byte kem_blind achieves a security level of 128 against all attackers.

[[EDITOR'S NOTE: The proof of this bound needs to be updated for the password confirmation in this document, which derives client_confirm from the encapsulated key, and derives the KEM key pair from the seed and kem_blind.]]

## Parameters for CPace {#params-cpace}

{{AHH21}} bounds CPace by `l^2 / p + 2 * l^2 * Adv_sSDH + Adv_sCDH`, where l is the number of queries to the hash-to-curve function and p is the group order. Since the factor `l^2` counts positions for a challenge instance and the Diffie-Hellman problem is random self-reducible, we tighten this term. Generic Diffie-Hellman attacks have an advantage of approximately `t^2 / p`, so CPace reaches λ of approximately log2(p)/2, which is roughly 126 for X25519, 128 for P-256, and 192 for P-384.

## Parameters for CPaceOQUAKE {#params-cpaceoquake}

{{VJWYMS25}} gives two bounds, following {{HR24}}: one if CPace is secure, and the other if OQUAKE is secure. Against classical attackers, CPaceOQUAKE reaches the higher of the levels of CPace and OQUAKE, and against quantum attackers it reaches the level of OQUAKE.

Besides the advantage against CPace or OQUAKE, each bound has terms of order `q_H / 2^(8 * n)`, where n is the length of CPace's session key, of effective_PRS, or of the session key. These terms describe guessing a key, so against quantum attackers they become `t^2 / 2^(8 * n)`. To achieve a security level of 128, these keys must be at least 32 bytes, so Nkey >= 32, and we require a CPace hash output of at least 32 bytes.

## Parameters for CPaceOQUAKE+ {#params-cpaceoquakeplus}

CPaceOQUAKE+ applies the PAKE-to-aPAKE transformation to CPaceOQUAKE, so its requirements are those described both in {{params-cpaceoquake}} and {{params-oquakeplus}}.


# CPace Wrapper {#cpace}

CPace is a classical elliptic curve-based PAKE {{CPACE}}. This appendix wraps the CPace specification in a consistent interface, following the common PAKE interface in {{overview}}. It is used as Stage 1 of CPaceOQUAKE ({{CPaceOQUAKE}}) and CPaceOQUAKE+ ({{CPaceOQUAKEplus}}).
We use an interactive version of CPace that takes two rounds, in which there is a designated initiator and responder.
In other words, the responder only starts executing the protocol after it received the first message from the initiator.

The flow of the protocol consists of two messages sent between initiator and responder, produced by the functions
Init, Respond, and Finish, described below. Both parties take as input a password-related
string PRS, a public_context, and a secret_context (see {{overview}}). Upon completion, both parties
obtain matching session keys if their PRS, public_context, secret_context, and key length (specified by Nkey)
match. Otherwise, they obtain random keys. In exceptional cases, the protocol aborts.

CPace derives its generator from PRS, a channel identifier (CI), and a session identifier (sid);
CI may carry confidential information and is never sent on the wire, whereas sid is public and is
additionally bound into the session key. Accordingly, CPace uses the secret_context as its CI and the
public_context as its sid. CPace's sid is therefore the entire public_context, e.g.,
`EncodePublicContext(sid, U, S)` ({{public-context-encoding}}), rather than the session identifier
sid itself.

The functions below are parameterized by a group environment G and a hash function H, both as
specified in {{CPACE}}. From G, they use `G.calculate_generator`, `G.sample_scalar`,
`G.scalar_mult`, and `G.scalar_mult_vfy`, the neutral element `G.I`, and the domain-separation
identifier `G.DSI`. From H, they use `H.hash`.
The transcript hash TH ({{overview}}) uses the KDF and DST of the configuration.

## Initiation

The initiator starts the protocol using its password-related string PRS, binding the session to the
public_context and secret_context.

~~~
CPace.Init

Input:
- PRS, password-related string, a byte string
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string

Output:
- state, opaque state for the initiator to store, comprising the discrete
  logarithm ya, which is kept secret until the protocol finishes, and the public
  point Ya
- Ya, public point, intended to be sent to the responder

Parameters:
- G, a group environment as specified in CPace
- H, a hash function as specified in CPace

def Init(PRS, public_context, secret_context):
  g = G.calculate_generator(H, PRS, secret_context, public_context)
  ya = G.sample_scalar()
  Ya = G.scalar_mult(ya, g)
  return State(ya, Ya), Ya
~~~

The initiator retains Ya in its state because the session key computed by
CPace.Finish binds the full protocol transcript, which includes both Ya and Yb.

## Response

The responder performs the same actions as the initiator.
Since it already received the initiator's message, it can immediately finish its execution of the protocol.
It outputs the shared secret, a message Yb intended to be sent to the initiator, and a transcript hash.

~~~
CPace.Respond

Input:
- PRS, password-related string, a byte string
- public_context, optional public context, a byte string
- secret_context, optional secret context, a byte string
- Ya, public point, received from the initiator

Output:
- ISK, the established shared secret
- Yb, public point, intended to be sent to the initiator
- th, transcript hash, a byte string of KDF.Nx bytes

Parameters:
- G, a group environment as specified in CPace
- H, a hash function as specified in CPace
- KDF, a KDF instance
- DST, domain separation tag, a byte string

Exceptions:
- CPaceError, raised when an invalid value was encountered in CPace

def Respond(PRS, public_context, secret_context, Ya):
  g = G.calculate_generator(H, PRS, secret_context, public_context)
  yb = G.sample_scalar()
  Yb = G.scalar_mult(yb, g)

  K = G.scalar_mult_vfy(yb, Ya)
  If K = G.I, raise CPaceError

  ISK = H.hash(lv_cat(G.DSI || b"_ISK", public_context, K) || transcript_ir(Ya, b"", Yb, b""))
  th = TH("CPace", public_context, Ya, Yb)

  return ISK, Yb, th
~~~

The functions `lv_cat` and `transcript_ir` are defined in {{CPACE}}. This document does not use CPace's associated data, so ADa and ADb are empty.

## Finish

The initiator finishes the protocol by combining the state generated by CPace.Init and the message Yb received from the responder.
It outputs the shared secret and a transcript hash.

~~~
CPace.Finish

Input:
- state, opaque state produced by CPace.Init, comprising (ya, Ya)
- public_context, optional public context, a byte string
- Yb, public point, received from the responder

Output:
- ISK, the established shared secret
- th, transcript hash, a byte string of KDF.Nx bytes

Parameters:
- G, a group environment as specified in CPace
- H, a hash function as specified in CPace
- KDF, a KDF instance
- DST, domain separation tag, a byte string

Exceptions:
- CPaceError, raised when an invalid value was encountered in CPace

def Finish(state, public_context, Yb):
  (ya, Ya) = state

  K = G.scalar_mult_vfy(ya, Yb)
  If K = G.I, raise CPaceError

  ISK = H.hash(lv_cat(G.DSI || b"_ISK", public_context, K) || transcript_ir(Ya, b"", Yb, b""))
  th = TH("CPace", public_context, Ya, Yb)

  return ISK, th
~~~

# Message Encodings {#encodings}

The main body of this document describes the protocols in terms of abstract
protocol messages, represented as tuples of named fields. This appendix specifies
the concrete byte-level encoding of these messages, and of the public context.
This encoding is the default, and is the encoding to which the test vectors in
this document correspond. An implementation that does not define its own mapping
MUST serialize and parse messages exactly as specified here.

A specification that maps these protocols onto a particular transport MAY instead
define its own framing for protocol messages, subject to the requirements in
{{transport-mappings}}. The encoding of the public context is not subject to that
allowance: public_context is an input to key derivation, so it MUST be encoded
exactly as specified in {{public-context-encoding}} regardless of the transport.

The functions `lv_encode` and `lv_decode` are defined in {{notation-and-terminology}}.
Parsing a message MUST fail if the input does not have the expected length or
framing.

## Public Context Encoding {#public-context-encoding}

The `EncodePublicContext` function (see {{overview}}) encodes the optional
session identifier sid and party identifiers U and S into a single byte string,
using four-byte, big-endian length prefixes. Each of sid, U, and S is optional and
defaults to the empty string b"".

~~~
EncodePublicContext

Input:
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- public_context, the encoded public context, a byte string

def EncodePublicContext(sid, U, S):
  public_context =
    int_to_bytes(len(sid), 4) || sid ||
    int_to_bytes(len(U), 4) || U ||
    int_to_bytes(len(S), 4) || S
  return public_context
~~~

Applications MAY include additional public information by prepending or appending
it to the returned value.

## OQUAKE Message Encoding

The OQUAKE initiator message `(s, T, ⍴)`, produced by OQUAKE.Init and consumed by
OQUAKE.Respond ({{oquake}}), is encoded as:

~~~
init_msg = s || T || ⍴
~~~

where `s` has `Nr` bytes, `T` has `BUA-sKEM.Nt` bytes, and `⍴` has `N⍴`
bytes. On receipt, the fields are recovered as
`s = init_msg[0 : Nr]`,
`T = init_msg[Nr : Nr + BUA-sKEM.Nt]`, and
`⍴ = init_msg[Nr + BUA-sKEM.Nt : Nr + BUA-sKEM.Nt + N⍴]`.

The OQUAKE responder message `(ct, h)`, produced by OQUAKE.Respond and consumed by
OQUAKE.Finish, is encoded as:

~~~
resp_msg = ct || h
~~~

where `ct` has `BUA-sKEM.Nct` bytes and `h` has `Nkc` bytes. On receipt,
`ct = resp_msg[0 : BUA-sKEM.Nct]` and `h = resp_msg[BUA-sKEM.Nct :]`.

## OQUAKE+ Message Encoding

The OQUAKE+ initiator message is an OQUAKE initiator message, encoded as above.

The password confirmation challenge `(enc_c, client_confirm)`, produced by
PC.Challenge and consumed by PC.Respond ({{pwconf}}), is encoded as:

~~~
challenge = enc_c || client_confirm
~~~

where `enc_c` has `Nct + 32` bytes (the KEM ciphertext length plus the length of kem_blind)
and `client_confirm` has `Nkc` bytes. On receipt, `enc_c = challenge[0 : Nct + 32]` and
`client_confirm = challenge[Nct + 32 :]`. The password confirmation response is the
`server_confirm` value, a byte string of `Nkc` bytes.

The OQUAKE+ responder message `(oquake_resp, challenge)`, produced by
OQUAKE+.Respond and consumed by OQUAKE+.Finish ({{oquakeplus}}), is encoded
as:

~~~
resp_msg = oquake_resp || challenge
~~~

where `oquake_resp` is an OQUAKE responder message of `BUA-sKEM.Nct + Nkc` bytes
and `challenge` is a password confirmation challenge. On receipt,
`oquake_resp = resp_msg[0 : BUA-sKEM.Nct + Nkc]` and
`challenge = resp_msg[BUA-sKEM.Nct + Nkc :]`.

The OQUAKE+ response message is a password confirmation response.

## CPaceOQUAKE Message Encoding

The CPaceOQUAKE initiator message `Ya`, produced by CPaceOQUAKE.Init ({{CPaceOQUAKE}}), is encoded as:

~~~
init_msg = lv_encode(Ya)
~~~

where `Ya` is a CPace initiator message. On receipt, `Ya = lv_decode(init_msg)`.

The CPaceOQUAKE responder message `(Yb, oquake_init)`, produced by CPaceOQUAKE.Respond, is encoded as:

~~~
resp_msg = lv_encode(Yb) || oquake_init
~~~

where `Yb` is a CPace responder message and `oquake_init` is an OQUAKE initiator
message. On receipt, `L = bytes_to_int(resp_msg[0..2])`, `Yb = resp_msg[2..2+L]`,
and `oquake_init = resp_msg[2+L..]`.

The CPaceOQUAKE message `msg3`, produced by CPaceOQUAKE.InitiatorFinish, is an
OQUAKE responder message, encoded as described in the OQUAKE message encoding
above.

## CPaceOQUAKE+ Message Encoding

The CPaceOQUAKE+ messages `msg1`, `msg2`, and `msg3` are encoded exactly as the
corresponding CPaceOQUAKE messages described above.

The CPaceOQUAKE+ message `msg4`, produced by CPaceOQUAKE+.ResponderContinue, is a
password confirmation challenge, and `msg5`, produced by
CPaceOQUAKE+.InitiatorFinish and consumed by CPaceOQUAKE+.ResponderFinish, is a
password confirmation response; both are encoded as described in the OQUAKE+
message encoding above.

## Registration Message Encoding {#registration-message-encoding}

The registration message described in {{apake-transform}}, carrying the client's salt,
verifier (v, pk, kem_blind), and identifiers, is encoded as:

~~~
reg_msg = salt || v || pk || kem_blind || lv_encode(U) || lv_encode(S)
~~~

where `salt` has 32 bytes, `v` has `Nv` bytes, `pk` has `KEM.Npk` bytes, and `kem_blind`
has 32 bytes. On receipt, the fields are recovered as `salt = reg_msg[0 : 32]`,
`v = reg_msg[32 : 32 + Nv]`,
`pk = reg_msg[32 + Nv : 32 + Nv + KEM.Npk]`,
`kem_blind = reg_msg[32 + Nv + KEM.Npk : 64 + Nv + KEM.Npk]`, and the identifiers by
successive `lv_decode` calls over the remainder.

# Transport Mappings {#transport-mappings}

The encodings in {{encodings}} present each protocol message as a single
contiguous byte string. Some transports cannot carry a message of that size in one
protocol data unit. A specification that maps these protocols onto such a transport
can define its own framing, including carrying the fields of a single protocol message
in more than one transport message or PDU. This is possible because no value derived
by these protocols depends on how a message is framed: every key, confirmation value,
and transcript hash is computed from individual named fields -- `Ya`, `Yb`, `s`, `T`, `⍴`,
`ct`, `h`, `enc_c`, `k`, `client_confirm`, `server_confirm`, the public and secret contexts --
and never from the concatenated message as a whole.
Re-framing a message therefore cannot change any derived value, and does not
affect the security analysis of the protocol.

Such a mapping MUST satisfy the following requirements.

1. The value of every field supplied to and recovered from the protocol functions
   in the main body of this document MUST be identical to the value that the
   encoding in {{encodings}} would have produced or consumed. In particular, the
   mapping MUST NOT reorder, pad, truncate, or otherwise transform field values.
2. A party MUST have received every field of a protocol message before invoking
   the function that consumes that message. An implementation MUST NOT act on a
   partially received message, and in particular MUST NOT begin key confirmation,
   derive an application key, or emit any protocol message in response to one.
3. The mapping MUST detect a message whose fields are missing, duplicated, or of
   incorrect length, and MUST abort in that case, providing the same protection as
   the length and framing checks required by {{encodings}}.
4. The mapping MUST NOT alter the number of protocol messages, the direction in
   which each is sent, or the order in which they are processed, other than by
   omitting confirmation values as described in {{omit-confirmation}}. Only the
   framing of a message is at the mapping's discretion.
5. The public context MUST be encoded as specified in {{public-context-encoding}},
   since it is an input to key derivation.

Splitting a message across PDUs neither reduces the number of round trips nor
reduces the total number of octets sent; it redistributes octets across PDUs so
that each fits within the transport's limit. The number of round trips is a
property of the protocol itself and cannot be changed by a mapping. A mapping that
needs to avoid transport-layer fragmentation should therefore choose split points
that keep each PDU within the limit, rather than expecting a net saving.

## Message Sizes {#message-sizes}

The following table gives the size in octets of each protocol message under the
RECOMMENDED configurations of CPaceOQUAKE+ ({{config-cpaceoquakeplus}}), excluding any
framing added by the transport. The columns correspond to `cpaceoquakeplus-x25519-mlbuaskem1024-xwing`,
`cpaceoquakeplus-p384-mlbuaskem1024-mlkem1024p384`, and `cpaceoquakeplus-x25519-mlbuaskem768-xwing`, respectively.
Messages msg1 to msg3 are also the messages of the corresponding CPaceOQUAKE configurations. Sizes
for the other configurations follow from their respective field lengths.

| Message | Fields                | X25519, 1024 | P-384, 1024 | X25519, 768 |
|---------|-----------------------|--------------|-------------|-------------|
|  msg1   | CPace Ya              |      34      |      99     |      34     |
|  msg2   | CPace Yb, s, T, ⍴     |     1694     |     1759    |     1303    |
|  msg3   | ct, h                 |     1600     |     1600    |     1120    |
|  msg4   | enc_c, client_confirm |     1184     |     1729    |     1184    |
|  msg5   | server_confirm        |      32      |      32     |      32     |

In each configuration, the largest message is msg2.

# Test Vectors {#test-vectors}

This section contains test vectors for ML-BUA-sKEM and for the first configuration of each protocol in {{configurations}}.
Each test vector lists the inputs, the randomness that each step consumes, intermediate values, the protocol messages, and the outputs.
Byte strings are encoded in hexadecimal.
The randomness used to generate these test vectors corresponds to the following labels:

- keygen_seed: the concatenation of the seeds d and z of ML-KEM.KeyGen in BUA-sKEM.KeyGen
- kemeleon_m: the value m in Kemeleon.EncodeEk, added for each polynomial of the encapsulation key in BUA-sKEM.KeyGen (in decimal)
- encaps_m: the randomness m of ML-KEM.Encaps in BUA-sKEM.Encaps
- oquake_r: the value r sampled in OQUAKE.Init
- random_key: the key returned by OQUAKE.Finish when key confirmation fails
- cpace_ya and cpace_yb: the scalars sampled in CPace.Init and CPace.Respond, respectively
- kem_blind: the value sampled in GenVerifier
- kem_encaps_m and kem_encaps_eseed: the randomness of KEM.Encaps in PC.Challenge; m for ML-KEM and eseed for X-Wing

The intermediate values are listed by the following labels:

- v, seed, and pk: the values in GenVerifierMaterial and GenVerifier
- cpace_ISK and cpace_th: the shared secret and transcript hash output by CPace
- oquake_upk: the BUA-sKEM public key generated in OQUAKE.Init
- oquake_k: the BUA-sKEM shared secret in OQUAKE
- oquake_key and oquake_th: the key and transcript hash output by OQUAKE
- cpaceoquake_key: the key output by CPaceOQUAKE, i.e., SK in CPaceOQUAKE+
- pc_k: the KEM shared secret in password confirmation

## ML-BUA-sKEM {#tv-ml-bua-skem}

These test vectors list the randomness of ML-BUA-sKEM.KeyGen and ML-BUA-sKEM.Encaps, the public
key upk output by KeyGen, and the ciphertext ct and shared secret k output by Encaps.

### ML-BUA-sKEM-768

{::include poc/vectors/ml-bua-skem-768.md}

### ML-BUA-sKEM-1024

{::include poc/vectors/ml-bua-skem-1024.md}

## OQUAKE {#tv-oquake}

This test vector uses the configuration `oquake-mlbuaskem1024`.

{::include poc/vectors/oquake-mlbuaskem1024.md}

## OQUAKE+ {#tv-oquakeplus}

This test vector uses the configuration `oquakeplus-mlbuaskem1024-mlkem1024`.
The message reg_msg is the registration message ({{registration-message-encoding}}).

{::include poc/vectors/oquakeplus-mlbuaskem1024-mlkem1024.md}

## CPaceOQUAKE {#tv-cpaceoquake}

This test vector uses the configuration `cpaceoquake-x25519-mlbuaskem1024`.

{::include poc/vectors/cpaceoquake-x25519-mlbuaskem1024.md}

## CPaceOQUAKE+ {#tv-cpaceoquakeplus}

These test vectors use the configuration `cpaceoquakeplus-x25519-mlbuaskem1024-xwing`.
The message reg_msg is the registration message ({{registration-message-encoding}}).

### Successful Run {#tv-cpaceoquakeplus-success}

{::include poc/vectors/cpaceoquakeplus-x25519-mlbuaskem1024-xwing.md}

### Incorrect server_confirm

This test vector uses the inputs, randomness, and messages msg1 to msg4 of {{tv-cpaceoquakeplus-success}}.
A server that receives the following msg5 raises an AuthenticationError.

{::include poc/vectors/cpaceoquakeplus-x25519-mlbuaskem1024-xwing-incorrect-server-confirm.md}

### Wrong Password

In this test vector, the client runs the protocol with client_PRS instead of the registered PRS.
OQUAKE.Finish at the server returns random_key, and the client raises an AuthenticationError on receipt of msg4.

{::include poc/vectors/cpaceoquakeplus-x25519-mlbuaskem1024-xwing-wrong-password.md}

### Neutral Element

A server that receives the following msg1, in which Ya is the neutral element of G_X25519, raises a CPaceError, regardless of its other inputs.
{{CPACE}} lists further points for which CPace must abort.

{::include poc/vectors/cpaceoquakeplus-x25519-mlbuaskem1024-xwing-neutral-element.md}

<!--
# Acknowledgments
{:numbered="false"}

TODO acknowledge.
-->
