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
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

author:
 -
    ins: J. Vos
    name: Jelle Vos
    email: jvos@apple.com
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

--- abstract

This document describes the CPaceOQUAKE+ protocol, a hybrid asymmetric
password-authenticated key exchange (aPAKE) that supports mutual
authentication in a client-server setting secure against
quantum-capable attackers. CPaceOQUAKE+ is the result of a KEM-based
transformation from the hybrid symmetric PAKE protocol called CPaceOQUAKE
that is also described in this document. This document recommends
configurations for CPaceOQUAKE+.

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
Later attack executed by a quantum-capable attacker, in which the attacker learns the shared secret and uses it
to compromise application traffic. Upgrading both protocols to provide
post-quantum security is non-trivial, especially as there are no known efficient
constructions for certain building blocks used in these protocols (such as the OPRF
used in OPAQUE-3DH). As the threat of quantum-capable attackers looms, the
viability of existing aPAKE protocols in practice diminishes in time.

This document describes the CPaceOQUAKE+ protocol, an aPAKE that supports mutual
authentication in a client-server setting secure against
quantum-capable attackers. CPaceOQUAKE+ is the result of a KEM-based transformation
from the hybrid symmetric PAKE protocol called CPaceOQUAKE.

This document fully specifies CPaceOQUAKE+ and all dependencies necessary
to implement it. {{configurations}} provides recommended configurations.
<!-- and {{test-vectors}} provides test vectors to assist in checking implementation correctness. -->

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
  length prefix. For example, lv_enode((0x00, 0x01, 0x02)) = (0x00, 0x03, 0x00, 0x01, 0x02).
  The function `lv_decode` parses a byte string that is expected to be encoded
  with a two-byte length preceding the remaining bytes, e.g.,
  `lv_decode((0x00, 0x03, 0x00, 0x01, 0x02)) = (0x00, 0x01, 0x02)`. Note that `lv_decode`
  can fail when the length of the actual bytes does not match that encoded in the
  prefix. For example, `lv_decode((0xFF, 0xFF, 0x00))` will fail.
- The notation `bytes[l..h]` refers to the slice of byte array `bytes` starting
  at index `l` and ending at index `h-1`. For example, given `bytes = (0x00, 0x01, 0x02)`, then `bytes[0..1] = 0x00` and `bytes[0..3] = (0x00, 0x01, 0x02)`. Similarly, the notation `bytes[l..]` refers to the slice of the byte
  array `bytes` starting at `l` until the end of `bytes`, i.e.., `bytes[l..] = bytes[l..len(bytes)]`.

All algorithms and procedures described in this document are laid out
in a Python-like pseudocode. Each function takes a set of inputs and parameters
and produces a set of output values. Parameters become constant values once
the protocol variant and the configuration are fixed.

# Overview

This document aims to specify two protocols: a symmetric and an asymmetric hybrid PAKE.
In the symmetric PAKE setting, the client and server share a password and use it to
establish an authenticated shared secret. In the asymmetric PAKE setting, the client first
registers a password verifier with the server. A verifier is a value that is derived
from the password and which the client will later use to demonstrate knowledge of the password.
After registration, the client uses its password and the server uses the corresponding
verifier to establish an authenticated shared secret such that the server learns nothing
of the client's password.

The aPAKE specified in this document is composed of multiple smaller protocols, including
the hybrid symmetric PAKE protocol called CPaceOQUAKE. CPaceOQUAKE is in turn a composition of two other
PAKE protocols: the existing CPace {{!CPACE=I-D.irtf-cfrg-cpace}} and a new post-quantum PAKE called OQUAKE.
To achieve the asymmetric property, the aPAKE also builds upon a password
confirmation sub-protocol as specified in {{pcp}}.

We refer to the fully composed aPAKE as CPaceOQUAKE+.
An abstract overview of the composition of this protocol is shown in the figure below.
In the subsequent sections we break down the sub-protocols into even smaller building blocks.

~~~ aasvg
            +--------------------+
            | CPaceOQUAKE+       |
            |  +--------------+  |
            |  | CPaceOQUAKE  |  |
            |  | +----------+ |  |
            |  | |  CPace   | |  |
Client's    |  | | protocol | |  |
password -->|  | +----------+ |  |<-- Verifier
            |  |              |  |
            |  | +----------+ |  |
            |  | |  OQUAKE  | |  |
            |  | | protocol | |  |
            |  | +----------+ |  |
            |  +--------------+  |
            |   .------------.   |
            |  |   Password   |  |
Session <---+  | confirmation |  +---> Session
  key       |   '------------'   |       key
            +--------------------+
~~~

We note that this standard only specifies the composition of CPace and OQUAKE.
It is not necessarily true that one can securely compose all PAKEs this way.

The rest of this document specifies CPaceOQUAKE+ and its dependencies. {{CPaceOQUAKE}}
specifies the CPaceOQUAKE protocol, and {{CPaceOQUAKEplus}} specifies the CPaceOQUAKE+ protocol,
incorporating the former protocol. Each of these pieces build upon the cryptographic dependencies
specified in {{crypto-deps}}.

# Cryptographic Dependencies {#crypto-deps}

The protocols in this document have four primary dependencies:

- Key Encapsulation Mechanism (KEM); {{deps-kem}}
- Binary Uniform Key Encapsulation Mechanism (BUKEM); {{deps-bukem}}
- Key Derivation Function (KDF); {{deps-symmetric}}
- Key Stretching Function (KSF); {{deps-ksf}}

{{configurations}} specifies different combinations of each of these dependencies
that are suitable for implementation.

## Key Encapsulation Mechanism {#deps-kem}

A Key Encapsulation Mechanism (KEM) is an algorithm that is used for exchanging
a secret from one party to another. We require an IND-CCA-secure KEM with key
derivation from a seed. It consists of the following syntax.

- DeriveKeyPair(seed): Deterministic algorithm to derive a key pair
  `(sk, pk)` from the byte string `seed`, where `seed` SHOULD have `Nseed` bytes.
- Encaps(pk): Randomized algorithm to generate an ephemeral,
  fixed-length symmetric key (the KEM shared secret) and
  a fixed-length encapsulation of that key that can be decapsulated
  by the holder of the secret key corresponding to `pk`. This function
  can raise an `EncapsError` on encapsulation failure.
- Decaps(ct, skR): Deterministic algorithm using the secret key `sk`
  to recover the ephemeral symmetric key (the KEM shared secret) from
  its encapsulated representation `ct`. This function can raise a
  `DecapsError` on decapsulation failure.
- Nseed: The length in bytes of the seed used to derive a key pair.
- Nct: The length in bytes of an encapsulated key produced by this KEM.
- Npk: The length in bytes of a public key for this KEM.

This specification uses X-Wing {{!XWING=I-D.connolly-cfrg-xwing-kem}}.

## Binary Uniform KEM {#deps-bukem}

A binary uniform KEM supports the same functions as defined above for
a KEM, and it must also be IND-CCA secure, but it must also achieve
two additional security properties. Namely, in addition to IND-CCA
security, a binary uniform KEM requires that:

1. Public keys are indistinguishable from random strings of bytes (of
the same length); and

2. Ciphertexts are anonymous in the presence of chosen ciphertext
attack (ANO-CCA).

These additional properties are crucial for the security of OQUAKE. In
other words, one MUST NOT use a KEM that has no uniform public keys
and no anonymous ciphertexts in place of a uniform KEM.

This specification uses a variant of ML-KEM768 {{FIPS203}}, denoted ML-BUKEM768.
This is instantiated with "KemeleonNR - ML-KEM768" {{!KEMELEON=I-D.veitch-kemeleon}}. Note that, while
Kemeleon provides uniform encoding for KEM ciphertexts and public keys, we only
require uniform enoding for public keys. Future specifications can replace use of
Kemeleon with a binary uniform KEM that is more efficient if one becomes available.


## Key Derivation Function {#deps-symmetric}

A Key Derivation Function (KDF) is a function that takes some source of initial
keying material and uses it to derive one or more cryptographically strong keys.
This specification uses a KDF with the following API and parameters:

- Extract(salt, ikm): Extract a pseudorandom key of fixed length `Nx` bytes from
  input keying material `ikm` and an optional byte string `salt`.
- Expand(prk, info, L): Expand a pseudorandom key `prk` using the optional string `info`
  into `L` bytes of output keying material.
- Nx: The output size of the `Extract()` function in bytes.


## Key Stretching Function {#deps-ksf}

This specification makes use of a Key Stretching Function (KSF), which is a slow
and expensive cryptographic hash function with the following API:

- Stretch(msg, salt, L): Apply a key stretching function to stretch the input `msg`
and salt `salt`, hardening it against offline dictionary attacks. This function also
needs to satisfy collision resistance. The output is a string of L bytes.

# CPaceOQUAKE Protocol {#CPaceOQUAKE}

The hybrid, symmetric PAKE protocol, denoted CPaceOQUAKE consists of CPace {{CPACE}}
combined with OQUAKE {{ABJ25}}. OQUAKE is a PAKE built from a BUKEM and KDF, using a
2-rounds of Feistel network to password-encrypt the BUKEM public key.
The OQUAKE protocol is based on the "NoIC" protocol analyzed in {{ABJ25}}.

The CPaceOQUAKE protocol is based on the `Sequential PAKE Combiner' protocol proposed by
{{HR24}}. A very close variant of this protocol was also analyzed in {{LL24}}.

At a high level, CPaceOQUAKE is a two-round protocol that runs between client and server
wherein, upon completion, both parties share the same session key if they agree
on the password-related string (PRS). Otherwise, they obtain random session keys.
This is summarized in the diagram below.

~~~ aasvg
            +----------------------------------------+
            | CPaceOQUAKE  +----------+              |
            |              |  CPace   |              |
Client's    |              | protocol |              |    Server's
password -->|              +----------+              |<-- password
            |                                        |
            |              +----------+              |
            |              |  OQUAKE  |              |
Session <---+              | protocol |              +--> Session
  key       |              +----------+              |      key
            +----------------------------------------+
~~~

CPaceOQUAKE composes CPace and OQUAKE by first running CPace between
client and server, and then incorporating the CPace session key into
the password before running OQUAKE between the server and client. We
explain the composition in more detail in {{!cpacequake-composition}}.

As describes in {{cpace}} and {{quake}}, both CPace and OQUAKE take
as input optional client and server identifiers, denoted U and S,
respectively. See {{identities}} for more discussion about these
identities and how they are chosen in practice.

## CPace Specification {#cpace}

CPace is a classical elliptic curve-based PAKE {{!CPACE}}. This section wraps the CPace specification in a consistent interface.
We use an interactive version of CPace that takes two rounds, in which there is a designated initiator and responder.
In other words, the responder only starts executing the protocol after it received the first message from the initiator.

The flow of the protocol consists of three messages sent between initiator and responder, produced by the functions
Init, Respond, and Finish, described below. Both parties take as input a password-related
string PRS, an optional unique shared session identifier sid, and an optional client identifier
U and server identifier S (e.g., a device identifier, an IP address, or URL pertaining to the
client and server). Upon completion, both parties obtain matching session keys if their PRS, sid, key
length (specified by N), and client and server identifiers match. Otherwise, they obtain random keys.
In exceptional cases, the protocol aborts.

### Initiation

The initiator starts the protocol using its password-related string PRS.
Additionally, it may bind the session to an existing shared session identifier sid.
CPace also allows to bind the session to an existing channel identifier.
To remain consistent with the other PAKEs in this specification, the channel identifier is the concatenation
of optional client and server identifiers.

~~~
CPace.Init

Input:
- PRS, password-related string, a byte string
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- ya, discrete logarithm intended to be stored in secret until the protocol finishes
- Ya, public point, intended to be sent to the responder

Parameters:
- G, a group environment as specified in CPace

def Init(PRS, sid, U, S):
  g = G.calculate_generator(H, PRS, U || S, sid)
  ya = G.sample_scalar()
  Ya = G.scalar_mult(ya, g)
  return ya, Ya
~~~

### Response

The responder performs the same actions as the initiator.
Since it already received the initiator's message, it can immediately finish its execution of the protocol.
It outputs the shared secret and a message Yb intended to be sent to the initiator.

~~~
CPace.Respond

Input:
- PRS, password-related string, a byte string
- Ya, public point, received from the initiator
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- ISK, the established shared secret
- Yb, public point, intended to be sent to the initiator

Parameters:
- G, a group environment as specified in CPace
- H, a hash function as specified in CPace

Exceptions:
- CPaceError, raised when an invalid value was encountered in CPace

def Respond(PRS, Ya, sid, U, S):
  g = G.calculate_generator(H, PRS, U || S, sid)
  yb = G.sample_scalar()
  Yb = G.scalar_mult(yb, g)

  K = G.scalar_mult_vfy(yb, Ya)
  If K = G.I, raise CPaceError

  ISK = H.hash(lv_cat(G.DSI || b"_ISK", sid, K) || transcript(Ya, Yb))

  return ISK, Yb
~~~

The functions `lv_cat` and `transcript` are defined in {{CPACE}}.

### Finish

The initiator finishes the protocol by combining the discrete logarithm ya generated by CPace.Init and the message Yb received
from the responder.

~~~
CPace.Finish

Input:
- ya, discrete logarithm that was generated using CPace.Init
- Yb, public point, received from the responder
- sid, session identifier, a byte string

Output:
- ISK, the established shared secret

Parameters:
- G, a group environment as specified in CPace
- H, a hash function as specified in CPace

Exceptions:
- CPaceError, raised when an invalid value was encountered in CPace

def Finish(ya, Yb, sid):
  K = G.scalar_mult_vfy(ya, Yb)
  If K = G.I, raise CPaceError

  ISK = H.hash(lv_cat(G.DSI || b"_ISK", sid, K) || transcript(Ya, Yb))

  return ISK
~~~

## OQUAKE Specification {#quake}

OQUAKE is a PAKE built on a BUKEM and KDF.  If the BUKEM provides security against quantum-enabled attacks,
then so does OQUAKE. It consists of three messages sent between initiator and responder, produced by
the functions Init, Respond, and Finish, described below. Both parties take as input a password-related
string PRS, an optional session identifier sid, and an optional client identifier U and server
identifier S. Upon completion, both parties obtain matching session keys if their PRS, sid, key length
(specified by N), and client and server identifiers match. Otherwise, they obtain random session keys.

The shared session identifier has the following requirements. If a client and server identifier are provided:

- The session identifier must match between the client and server
- This session identifier has not been used before in a session between the client and server

If no client and server identifiers are provided:

- The session identifier must match between the client and server
- This session identifier has not been used before by the client or server in any session with any other party

These requirements originate from the security proof for OQUAKE. If these requirements are not met, the proof
does not apply, but this does not mean that the protocol becomes vulnerable.

### Initiation

Init takes as input the initiator's PRS, an optional session identifier sid, and optional client and server identifiers
U and S. It produces a context for the initiator to store, as well as a protocol message that is sent to
the responder. Its implementation is as follows.

~~~
OQUAKE.Init

Input:
- PRS, password-related string, a byte string
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- context, opaque state for the initiator to store
- msg, an encoded protocol message for the initiator to send to the responder

Parameters:
- BUKEM, a BUKEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def Init(PRS, sid, U, S):
  seed = random(BUKEM.Nseed)
  (pk, sk) = BUKEM.DeriveKeyPair(seed)

  r = random(3 * Nsec)

  fullsid = encode_sid(sid, U, S)

  // T = XOR(pk, H(fullsid, PRS, r))
  prk_T_pad = KDF.Extract(PRS, DST || "OQUAKE" || fullsid || r)
  T_pad = KDF.Expand(prk_T_pad, DST || "T_pad", Npk)
  T = XOR(pk, T_pad)

  // s = XOR(r, H(fullsid, PRS, T))
  prk_s_pad = KDF.Extract(PRS, DST || "OQUAKE" || fullsid || T)
  s_pad = KDF.Expand(prk_s_pad, DST || "s_pad", 3 * Nsec)
  s = XOR(r, s_pad)

  init_msg = s || T

  return Context(PRS, sk, s, T, fullsid), init_msg
~~~

The encode_sid function is defined below.

~~~
encode_sid

Input:
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- fullsid, a byte string

Parameters:
- BUKEM, a BUKEM instance
- KDF, a KDF instance

def encode_sid(sid, U, U):
  fullsid =
    bytes_to_int(len(sid), 4) || sid ||
    bytes_to_int(len(U), 4) || U ||
    bytes_to_int(len(S), 4) || S
  return fullsid
~~~

### Response

Respond takes as input the PRS, the initiator's protocol message, an optional session identifier, and optional client and server identifiers.
It produces a 32-byte symmetric key and a protocol message intended to be sent to the initiator. Its implementation
is as follows.

~~~
OQUAKE.Respond

Input:
- PRS, password-related string, a byte string
- init_msg, encoded protocol message, a byte string
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- ss, output shared secret, a byte string of 32 bytes
- resp_msg, encoded protocol message, a byte string

Parameters:
- BUKEM, a BUKEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def Respond(PRS, init_msg, sid, U, S):
  (s, T) = init_msg[0..(3 * Nsec)], init_msg[(3 * Nsec)..]

  fullsid = encode_sid(sid, U, S)
  prk_s_pad = KDF.Extract(PRS, DST || "OQUAKE" || fullsid || T)
  s_pad = KDF.Expand(prk_s_pad, DST || "s_pad", 3 * Nsec)
  r = XOR(s, s_pad)

  prk_T_pad = KDF.Extract(PRS, DST || "OQUAKE" || fullsid || r)
  T_pad = KDF.Expand(prk_T_pad, DST || "T_pad", Npk)
  pk = XOR(T, T_pad)

  (ct, k) = BUKEM.Encaps(pk)

  prk_sk = KDF.Extract(PRS, DST || "OQUAKE" || fullsid || k)
  key = KDF.Expand(prk_sk, DST || "sk", Nkey)

  h = KDF.Expand(prk_sk, DST || "confirm", Nkc)

  resp_msg = ct || h

  return resp_msg, key
~~~

### Finish {#quake-finish}

Finish takes as input the initiator-created context that is output from Init
as well as the responder's reply message resp\_msg. It produces a symmetric key
that is output to the initiator. Its implementation
is as follows.

~~~
OQUAKE.Finish

Input:
- context, opaque state for the initiator to store TODO
- resp_msg, encoded protocol message, a byte string

Output:
- ss, output shared secret, a byte string of 32 bytes

Parameters:
- BUKEM, a BUKEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

Exceptions:
- AuthenticationError, raised when the key confirmation fails

def Finish(context, resp_msg):
  (PRS, sk, s, T, fullsid) = context
  ct, h = resp_msg[0..Npk], resp_msg[Npk..]

  try:
    k = BUKEM.Decaps(sk, ct)
    prk_sk = KDF.Extract(PRS, DST || "OQUAKE" || fullsid || k)
    key = KDF.Expand(prk_sk, DST || "sk", Nkey)

    h_expected = KDF.Expand(prk_sk, DST || "confirm", Nkc)
    if h != h_expected:
      return random(Nkey)

    return key
  catch DecapsError:
    return random(Nkey)
~~~

## Composition of CPace & OQUAKE {#cpacequake-composition}

CPaceOQUAKE is a sequential composition of CPace (see {{cpace}}) and
OQUAKE (see {{quake}}). Whereas running CPace and OQUAKE in parallel realizes
a worst-of-both worlds PAKE, this sequential composition realizes a
best-of-both worlds PAKE. In other words, CPaceOQUAKE remains as secure
as the strongest PAKE, resisting attacks that break the classical CPace
(e.g. by a quantum-capable attacker) or attacks that break the
quantum-resistant OQUAKE (e.g. by a flaw in the BUKEM). This assumes that
OQUAKE is instantiated with a quantum-resistant BUKEM.

To be precise, CPaceOQUAKE first runs CPace using password-related string PRS,
establishing a session key SK1 with the associated transcript tr1. It
then initiates OQUAKE using the password-related string `H(fullsid, PRS, tr1, SK1)`;
a secret derived from the the original password-related string and the outputs from
the CPace instance. Here, `fullsid` is the output of encode_sid(sid, U, S).
The final session key is then a hash of fullsid, the original password-related string,
both CPace and OQUAKE transcripts (tr1 and tr2, respectively), and both session keys
output from CPace and OQUAKE (SK1 and SK2, respectively), i.e.,
H(fullsid, tr1, tr2, SK1, SK2).

This is outlined in the diagram below. In CPaceOQUAKE, CPace is initiated by the
first party, while OQUAKE is initiated by the other party. This results in a protocol
that requires three messages.

~~~ aasvg
            +-------------------------------------------------------------------------------+
Client's    | CPaceOQUAKE                     +----------+                                  |    Server's
password ---)-------------+---PRS------------>|  CPace   +<--PRS---------+------------------(--- password
            |             |         +---------+ protocol +-+             |                  |
            |             |         |         +----------+ |             |                  |
            |             |         |                      +-------------(---------+        |
            |             v         v         +----------+               v         v        |
            | H(fullsid, PRS, tr1, SK1)------>|  OQUAKE  +<--H(fullsid, PRS, tr1, SK1)      |
Session <---)-H(fullsid, tr1, tr2, SK1, SK2)--+ protocol +---H(fullsid, tr1, tr2, SK1, SK2)-(--> Session
  key       |                                 +----------+                                  |      key
            +-------------------------------------------------------------------------------+
~~~

Unlike OQUAKE, CPaceOQUAKE does not require a shared session identifier sid, although this
is strongly recommended. If no sid is provided, CPace will run without an sid, and OQUAKE
will use a random string generated with random material provided by both parties. If an
sid is provided, both CPace and OQUAKE will use this sid.

An overview of the protocol flow is shown below. The protocol has four functions. Init and
InitiatorFinish are intended to be called by the initiator, and Respond and ResponderFinish
are intended to be called by the responder. The following subsections specify these functions.

~~~aasvg
Client: PRS,sid,U,S       Server: PRS,sid,U,S
        -----------------------------------------
     ctx1, (s1, msg1) =                    |
CPaceOQUAKE.Init(PRS,sid,U,S)              |
             |                             |
             |         (s1, msg1)          |
             |---------------------------->|
             |                             |
             |                ctx2, (s2, msg2, msg3) =
             |     CPaceOQUAKE.Respond(PRS,(s1,msg1),sid,U,S)
             |                             |
             |       s2, msg2, msg3        |
             |<----------------------------|
             |                             |
    client_key, msg4 =                     |
CPaceOQUAKE.InitiatorFinish(PRS, ...       |
(ctx1,s1),(s2,msg2,msg3),sid,U,S)          |
             |            msg4             |
             |---------------------------->|
             |                             |
             |                       server_key =
             |           CPaceOQUAKE.ResponderFinish(ctx2, msg4)
             |                             |
        -----------------------------------------
     output client_key              output server_key
~~~


### Client Initiation

The client initiates a CPace exchange with the server using input PRS, an optional session identifier sid,
and optional client and server identifiers U and S. The output of this process is some context for
completing the protocol and a protocol message. The client sends this message to the server.

~~~
CPaceOQUAKE.Init

Input:
- PRS, password-related string, a byte string
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- context, opaque state for the initiator to store
- msg, an encoded protocol message for the initiator to send to the responder

Parameters:
- CPace, parameterized instance of CPace

def Init(PRS, sid, U, S):
  ctx1, msg1 = CPace.Init(PRS, sid, U, S)
  s1 = random(32)
  init_msg = s1 || lv_encode(msg1)

  return (ctx1, s1), init_msg
~~~


### Server Response

The server processes the client message using its input PRS, an optional session identifier sid, and
optional client and server identifiers U and S. The first output of this function is a context that
is used to finish the protocol later. The second output is a protocol message intended for the client.

The server responds to the CPace session that the client initiated, and it initiates a new OQUAKE
session using both the PRS and the key established by CPace.

The server MUST ensure that exactly one of `s1` and `sid` exists. It MUST abort if the message does
not have the correct length.

~~~
CPaceOQUAKE.Respond

Input:
- PRS, password-related string, a byte string
- init_msg, the message received from the client
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- context, opaque state for the responder to store
- msg, an encoded protocol message for the responder to send to the initiator

Parameters:
- CPace, parameterized instance of CPace
- OQUAKE, parameterized instance of OQUAKE
- DST, domain separation tag, a byte string

def Respond(PRS, init_msg, sid, U, S):
  s1, msg1 = init_msg[0..32], lv_decode(init_msg[32..])

  key1, msg2 = CPace.Respond(PRS, msg1, sid, U, S)
  key1A = KDF.Expand(key1, DST || "prskey", Nkey)
  key1B = KDF.Expand(key1, DST || "outputkey", Nkey)

  s2 = random(32)
  prk_extended_sid = KDF.Extract(s1 || s2, DST || "CPaceOQUAKE")
  extended_sid = KDF.Expand(prk_extended_sid, DST || "SID", 32)

  fullsid = encode_sid(extended_sid, U, S)

  prk_PRS2 = KDF.Extract(PRS, DST || "CPaceOQUAKE" || fullsid || msg1 || msg2 || key1A)
  PRS2 = KDF.Expand(prk_PRS2, DST || "PRS2", Nkey)

  ctx2, msg3 = OQUAKE.Init(PRS2, extended_sid, U, S)

  resp_msg = s2 || lv_encode(msg2) || lv_encode(msg3)

  return Context(fullsid, PRS, msg1, msg2, msg3, key1B, ctx2), resp_msg
~~~

### Client Finish

The client finishes the protocol by processing the server response. The client obtains a
shared secret and a final message intended for the server. It does so by finishing the
CPace session and responding to the OQUAKE session.

The client must ensure that exactly one of (s1, s2) and sid exists.
The client should abort when the message does not have the correct length.

~~~
CPaceOQUAKE.InitiatorFinish

Input:
- PRS, password-related string, a byte string
- (ctx1, s1), the context generated by CPaceOQUAKE.Init
- resp_msg, the message received from the server
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- key, an N-byte shared secret
- msg, an encoded protocol message for the initiator to send to the responder

Parameters:
- CPace, parameterized instance of CPace
- OQUAKE, parameterized instance of OQUAKE
- DST, domain separation tag, a byte string

def InitiatorFinish(PRS, (ctx1, s1), resp_msg, sid, U, S):
  s2 = resp_msg[0..32]
  msg2 = lv_decode(resp_msg[32..])
  msg3 = lv_decode(resp_msg[32+len(msg2)..])

  key1 = CPace.Finish(ctx1, msg2, sid)
  key1A = KDF.Expand(key1, DST || "prskey", Nkey)
  key1B = KDF.Expand(key1, DST || "outputkey", Nkey)

  prk_extended_sid = KDF.Extract(s1 || s2, DST || "CPaceOQUAKE")
  extended_sid = KDF.Expand(prk_extended_sid, DST || "SID", 32)

  fullsid = encode_sid(extended_sid, U, S)
  prk_PRS2 = KDF.Extract(PRS, DST || "CPaceOQUAKE" || fullsid || msg1 || msg2 || key1A)
  PRS2 = KDF.Expand(prk_PRS2, DST || "PRS2", Nkey)

  key2, msg4 = OQUAKE.Respond(PRS2, msg3, extended_sid, U, S)

  prk_sessionkey = KDF.Extract(PRS, DST || "CPaceOQUAKE" || fullsid || msg1 || msg2 || msg3 || msg4 || key1B || key2)
  client_key = KDF.Expand(prk_sessionkey, DST || "sessionkey", Nkey)

  return client_key, msg4
~~~

### Server Finish

The server finishes the protocol by finising OQUAKE using the client's response, outputting a shared secret of N bytes.
It should abort when the message does not have the correct length.

~~~
CPaceOQUAKE.ResponderFinish

Input:
- ctx, context from the server's Response
- msg4, the message received from the server, a byte string

Output:
- key, an N-byte shared secret

Parameters:
- OQUAKE, parameterized instance of OQUAKE
- DST, domain separation tag, a byte string

def ResponderFinish(ctx, msg4):
  (fullsid, PRS, msg1, msg2, msg3, key1B, ctx2) = ctx

  key2 = OQUAKE.Finish(ctx2, msg4)

  prk_sessionkey = KDF.Extract(PRS, DST || "CPaceOQUAKE" || fullsid || msg1 || msg2 || msg3 || msg4 || key1B || key2)
  server_key = KDF.Expand(prk_sessionkey, DST || "sessionkey", Nkey)

  return server_key
~~~

# CPaceOQUAKE+ Protocol {#CPaceOQUAKEplus}

CPaceOQUAKE+ is the 5 message aPAKE resulting from applying a KEM-based
PAKE-to-aPAKE transformation to CPaceOQUAKE. At a high level, this
involves running CPaceOQUAKE on a verifier of the client's password.
To ensure that the client does indeed know the password pertaining
to that verifier, there is an additional password confirmation
stage that uses seed derived from the password. Both the verifier and
the seed are derived from the password using a key stretching function.
The seed is later used to derive a KEM public key. We refer to the collection
of the verifier and this public key as 'the verifiers'.

The CPaceOQUAKE+ protocol can be seen as a close variant (and a specific
instance) of the `augmented PAKE' construction presented in {{LLH24}} and in {{Gu24}}.

## Registering Clients

This subsection specifies functions for generating the verifiers and
a protocol for registering clients.

### Generating Verifiers {#gen-verifiers}

Verifiers are random-looking value derived from password-related strings
from which it is computionally impractical to derive the password-related
string. To make verifiers unique between different users with the same
password or servers that they interact with, we employ a salt, a user
account identifier, and an optional server identifier. The material
required for the verifiers is generated as follows:

~~~
GenVerifierMaterial

Input:
- PRS, password-related string, a byte string
- salt, client-specific salt, a byte string
- U and S, client and server identifiers

Output:
- ss, output shared secret, a byte string of 32 bytes
- resp_msg, encoded protocol message, a byte string

Parameters:
- KEM, a KEM instance
- KSF, a parameterized KSF instance
- DST, domain separation tag, a byte string

def GenVerifierMaterial(PRS, salt, U, S):
  verifier_seed = KSF.Stretch(DST || PRS || U || S, salt, Nverifier + KEM.Nseed)
  verifier = verifier_seed[0:Nverifier]
  seed = verifier_seed[Nverifier:Nverifier + KEM.Nseed]
  return verifier, seed
~~~

To derive an actual public key from the verifier material, we use the following function:

~~~
GenVerifiers

Input:
- PRS, password-related string, a byte string
- salt, client-specific salt, a byte string
- U and S, client and server identifiers

Output:
- ss, output shared secret, a byte string of 32 bytes
- resp_msg, encoded protocol message, a byte string

Parameters:
- KEM, a KEM instance

def GenVerifiers(PRS, salt, U, S):
  verifier, seed = GenVerifierMaterial(PRS, salt, U, S)
  (pk, sk) = KEM.DeriveKeyPair(seed)
  return verifier, pk
~~~

The server MUST store pk; it MUST NOT store seed.

### Registration

The registration phase consists of one message sent from the client to the server. This message
contains the verifier, a public key, and 32-byte salt. The server stores this information corresponding to
the client for future use in the verification flow. This phase requires a secure channel from client to
server in order to transfer the password verifier and public key.
The salt can be sent in plain text.

We recommend that the salt is a random byte string: `salt = random(32)`. However, in practice this
may require an additional communication flow, used by the server to send the salt to the client
before protocol CPaceOQUAKE+ starts. Instead, one may consider deriving the salt from some
client-specific value that it knows and can retain locally.

A high level flow overview of the registration flow is below.

~~~aasvg
Client: PRS, salt, U, S              Server: N/A
       ---------------------------------------
 (v, pk) = GenVerifiers(PRS, salt, U, S)
            |                           |
            |    salt, v, pk, U, S      |
            |-------------------------->|
            |                           |
            |                Store (salt, v, pk, U, S)
            |                           |
       ---------------------------------------
~~~


## The Password Confirmation Stage {#pcp}

In the password confirmation (PC) stage, the client proves knowledge
of its password without revealing it. It uses the registered verifiers from the
previous subsection. To do so securely, it uses the key established by CPaceOQUAKE,
which allows it to realize a confidential but unauthenticated channel.
In other words, this password confirmation stage cannot be used by itself.
This PC stage is parameterized by a KEM, KDF, KSF, and is additionally bound
to the preceding protocol via an agreed-upon transcript (tx); see {{configurations}}
for specific parameter configurations.

The password confirmation is a two-round challenge-response flow between the
server and client. In particular, the server challenges the client to prove
knowledge of its password. More precisely, it challenges the client to prove
knowledge of a seed, derived from the GenVerifierMaterial function (and
in turn derived from the password using a key stretching function).
Both client and server share a symmetric key as input. Additionally, the server
has the client's public key and salt stored from the previous registration flow.

A high level overview of this flow is below.

~~~aasvg
Client: SK, tx, seed, sid, U, S      Server: SK, tx, pk, sid, U, S
       ---------------------------------------
          ctx, challenge = PC-Challenge(SK, tx, pk, sid, U, S)
            |                           |
            |         challenge         |
            |<--------------------------|
            |                           |
client_key, response = PC-Response(SK, tx, seed, challenge, sid, U, S)
            |                           |
            |         response          |
            |-------------------------->|
            |                           |
                server_key = PC-Verify(ctx, response)
            |                           |
       ---------------------------------------
  output client_key            output server_key
~~~

### Server Challenge

To construct the challenge, the server encapsulates to the client's public
key. From the resulting shared secret, it then derives password confirmation
values and a new shared secret. The challenge message is the ciphertext encrypted
using a one-time pad derived from the shared secret. The password confirmation
values are byte strings of length `Nkc`.

The implementation MUST NOT reveal server_key from the context.

~~~
PC-Challenge

Input:
- SK, 32-byte symmetric key, a byte string
- transcript, the transcript from previously executed protocols to which this protocol is bound, a byte string
- pk, client-registered public key, a KEM public key
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- context, opaque state for the server to store values to complete the protocol
- challenge, an encoded protocol message for the server to send to the client

Parameters:
- KEM, a KEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def PC-Challenge(SK, transcript, pk, sid, U, S):
  (c, k) = KEM.Encaps(pk)
  r = KDF.Expand(SK, DST || "OTP", Nct)
  enc_c = XOR(c, r)

  confirm_input = encode_sid(sid, U, S) || enc_c || transcript

  prk_k_h1 = KDF.Extract(SK, DST || "h1" || confirm_input)
  prk_k_h2 = KDF.Extract(SK, DST || "h2" || confirm_input || k)

  // Derive h1 from the full transcript excluding k
  client_confirm = KDF.Expand(prk_k_h1, DST || "client_confirm", Nkc)

  // Derive h2 || SK from the full transcript including k
  server_confirm = KDF.Expand(prk_k_h2, DST || "server_confirm", Nkc)
  server_key = KDF.Expand(prk_k_h2, DST || "key", Nkey)

  challenge = (enc_c, client_confirm)

  return Context(server_confirm, server_key), challenge
~~~

### Client Response

Upon receipt of the challenge, the client recovers the KEM ciphertext by decrypting
the one-time pad ciphertext included in the challenge, using the key derived from the shared secret.
It then uses the seed to re-derive the KEM key pair, using the same procedure followed during
the registration flow. The client then decapsulates the KEM ciphertext to recover
the shared secret and derive the same password confirmation values and new
shared secret as the server.

The client then checks that the server-provided confirmation value matches its
own and aborts if not. Otherwise, it returns its own password confirmation value.
The client outputs the new shared secret as its output.

~~~
PC-Response

Input:
- SK, 32-byte symmetric key, a byte string
- transcript, the transcript from previously executed protocols to which this protocol is bound, a byte string
- seed, seed used to derive KEM public key
- challenge, an encoded protocol message for the server to send to the client
- sid, session identifier, a byte string
- U and S, client and server identifiers

Output:
- client_key, a 32-byte string
- response, an encoded protocol message for the client to send to the server

Exceptions:
- AuthenticationError, raised when the password confirmation values do not match

Parameters:
- KEM, a KEM instance
- KDF, a KDF instance
- DST, domain separation tag, a byte string

def PC-Response(SK, transcript, seed, challenge, sid, U, S):
  (enc_c, client_confirm_target) = challenge
  r = KDF.Expand(SK, DST || "OTP", Nct)
  c = XOR(enc_c, r)

  (pk, sk) = KEM.DeriveKeyPair(seed)

  try:
    k = KEM.Decaps(sk, c)

    confirm_input = encode_sid(sid, U, S) || enc_c || transcript

    prk_k_h1 = KDF.Extract(SK, DST || "h1" || confirm_input)
    prk_k_h2 = KDF.Extract(SK, DST || "h2" || confirm_input || k)

    // Derive h1 from the full transcript excluding k
    client_confirm = KDF.Expand(prk_k_h1, DST || "client_confirm", Nkc)

    // Derive h2 || SK from the full transcript including k
    server_confirm = KDF.Expand(prk_k_h2, DST || "server_confirm", Nkc)
    client_key = KDF.Expand(prk_k_h2, DST || "key", Nkey)

    if client_confirm != client_confirm_target:
      raise AuthenticationError

    return client_key, server_confirm
  catch DecapsError:
    raise AuthenticationError
~~~

### Server Verify

Upon receipt of the response, the server validates that the password confirmation
value matches its own value. If the value does not match, the server aborts.
Otherwise, the server outputs the new shared secret as its output.

~~~
PC-Verify

Input:
- context, opaque context produced by Challenge
- server_confirm_target, client's response message, a byte string

Output:
- server_key, a 32-byte string

Exceptions:
- AuthenticationError, raised when the password confirmation values do not match

Parameters:

def PC-Verify(context, server_confirm_target):
  (server_confirm, server_key) = context
  if server_confirm != server_confirm_target:
    raise AuthenticationError
  return server_key
~~~

## Composition of CPaceOQUAKE & Password Confirmation

The composition of CPaceOQUAKE and the password confirmation stage is
strictly sequential. First, the parties run CPaceOQUAKE using the verifier.
The client recovers this verifier using the `GenVerifierMaterial` function.
After that, the parties proceed with password confirmation, which is
initiated by the server using the stored public key. The client uses the
seed that was also produced by `GenVerifierMaterial` to prove knowledge of
the password. This seed MUST remain secret to prevent impersonation. An
overview of the composition is below.

~~~ aasvg
           +----------------------------------------------+
           | CPaceOQUAKE+                                 |
           |                          +--------------+    |
Client's   |   .-------------------.  | CPaceOQUAKE  |    |
password --)->| GenVerifierMaterial + | +----------+ |    |
           |   '----+---+----------'  | |  CPace   | |    |
           |        |   |             | | protocol | |    |
           |        |   +--Verifier-->| +----------+ |<---(-- Verifier
           |        |                 |              |    |
           |        |                 | +----------+ |    |
           |        |                 | |  OQUAKE  | |    |
           |        |               +-+ | protocol | +-+  |
           |        |               | | +----------+ | |  |
           |        |               | +--------------+ |  |
           |        |              SK  .------------.  SK |
           |        |               | |              | |  |
           |        |               | |              | |  |
           |        |               +->   Password   <-+  |
           |        +------seed-------> confirmation <----(-- Public key
           |                          |              |    |
Session <--)--------------------------+              +----(--> Session
  key      |                           '------------'     |      key
           +----------------------------------------------+
~~~

Upon successful completion of the entire protocol, the client and server will share a
symmetric key that was authenticated by knowledge of the password. The protocol
aborts if the password did not match. The protocol flows are shown below.
Note here that if the client does not know the salt, the server must send
it to the client before the protocol starts, which it can do in plain text.

~~~aasvg
Client: PRS,salt,U,S,sid      Server: v,pk,U,S,sid
          ----------------------------------------
(v, seed) = GenVerifierMaterial(PRS,salt,U,S)  |
ctx1, msg1 = CPaceOQUAKE.Init(v,sid,U,S)       |
            |                                  |
            |               msg1               |
            |--------------------------------->|
            |                                  |
            | ctx2, msg2 = CPaceOQUAKE.Respond(v,msg1,sid,U,S)
            |                                  |
            |               msg2               |
            |<---------------------------------|
            |                                  |
SK, msg3 = CPaceOQUAKE.InitiatorFinish(        |
  v,ctx1,msg2,sid,U,S)                         |
            |                                  |
            |               msg3               |
            |--------------------------------->|
            |                                  |
            |              SK = CPaceOQUAKE.ResponderFinish(ctx2,msg3)
            |              tx = msg1 || msg2 || msg3
            |             ctx3, chal = PC-Challenge(SK,tx,pk,sid,U,S)
            |                                  |
            |               chal               |
            |<---------------------------------|
            |                                  |
      tx = msg1 || msg2 || msg3                |
client_key, resp = PC-Response(SK,tx,seed,chal,sid,U,S)
            |                                  |
            |               resp               |
            |--------------------------------->|
            |                                  |
            |                   server_key = PC-Verify(ctx2, resp)
            |                                  |
          ----------------------------------------
      output client_key                 output server_key
~~~


# CPaceOQUAKE+ Configurations {#configurations}

CPaceOQUAKE+ is instantiated by selecting a configuration of a group and hash function
for the CPace protocol, a KEM, KDF, KSF, for password confirmation, and a KEM and KDF
for CPaceOQUAKE, and a general purpose cryptographic hash function H. The KEM, KDF,
are not required to be the same, so they are distinguished by "PC-" and "PAKE-"
prefixes, e.g., PC-KDF and PAKE-KDF are the KDFs for the password confirmation stage
and the CPaceOQUAKE protocol, respectively.

The RECOMMENDED configuration is below.

- CPace-Group: CPACE-RISTR255-SHA512 {{Section 4 of CPACE}}
- CPace-Hash: SHA-512
- KEM: X-Wing {{!XWING=I-D.connolly-cfrg-xwing-kem}}, where Nseed = 32, Nct = 1120, and Npk = 1216.
- PC-KDF: HKDF-SHA-256
- PC-KSF: Argon2id(S = zeroes(16), p = 4, T = Nh, m = 2^21, t = 1, v = 0x13, K = nil, X = nil, y = 2) {{!ARGON2=RFC9106}}
- BUKEM: ML-BUKEM768 {{deps-bukem}}, where Nseed = 64, Nct = 1514, and Npk = 1172.
- PAKE-KDF: HKDF-SHA-256
- H: SHA256
- DST: "1b3abc3cd05e8054e8399bc38dfcbc1321d2e1b02da335ed1e8031ef5199f672" (a randomly generated 32-byte string)

The RECOMMENDED parameters are (see {{params}}):

- Nverifier = 32
- Nkc = 64
- Nsec = 32
- Nkey = 32, this is achieved by choosing H in CPace with H.b_in_bytes = 32

Other documents can define configurations as needed for their use case, subject to the following requirements:

1. KEM MUST be a hybrid KEM, i.e., one that achieves both classical and post-quantum security.
2. The parameters must be chosen so they correspond with this KEM. E.g., Nseed must have the correct length.

For instance, one possible additional configuration is as follows.

- CPace-Group: CPACE-P256_XMD:SHA-256_SSWU_NU_-SHA256 {{Section 4 of CPACE}}
- CPace-Hash: SHA-256
- KEM: X-Wing {{!XWING=I-D.connolly-cfrg-xwing-kem}}, where Nseed = 32, Nct = 1120, and Npk = 1216.
- PC-KDF: HKDF-SHA-256
- PC-KSF: Scrypt(N = 32768, r = 8, p = 1) {{!SCRYPT=RFC7914}}
- BUKEM: ML-BUKEM768 {{deps-bukem}}, where Nseed = 64, Nct = 1514, and Npk = 1172.
- PAKE-KDF: HKDF-SHA-256
- H: SHA256
- DST: "b840fa4d4b4caec9e25d13d8c016cfe93e7468d54e936490bd0b0a3ffca1a01b" (a randomly generated 32-byte string)

# Implementation Considerations

Some functions included in this specification are fallible (as noted by their ability
to raise exceptions). The explicit errors generated
throughout this specification, along with conditions that lead to each error,
are as follows:

- AuthenticationError: The PC protocol fails password confirmation checks at the
  client or server; {{pcp}}

Beyond these explicit errors, CPaceOQUAKE+ implementations can produce implicit errors.
For example, if protocol messages sent between client and server do not match
their expected size, an implementation should produce an error.

The errors in this document are meant as a guide for implementors. They are not an
exhaustive list of all the errors an implementation might emit. For example, an
implementation might run out of memory.

# Security Considerations

This section discusses security considerations for the protocols specified in
this document.

## Identities {#identities}

Client and server identities are essential to authenticated key exchange protocols,
and PAKEs are no exception. This section discusses the role and importance of
identities in the PAKE protocols specified in this document.

### Symmetric PAKE identities {#symmetric-identities}

PAKEs are often analyzed in the universal composability (UC) framework,
which imposes several requirements on the protocols: (1) the existence
of a globally-unique session identifer associated with each protocol invocation,
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
we note that that this proof has not been published yet.

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
PAKEs specified in this document (in {{CPaceOQUAKEplus}}). Both
client and server identities can be long-lived, e.g., a client identity
could be an email address and a server identity could be a domain name.

Practically, applications should be mindful of what happens when these
identities change. Since they are both included in the password verifier
(see {{gen-verifiers}}), changing either identifier will require the
veirifer to be re-computed and the client to be re-registered. For a single
client, this change is minimal, but for a single server, which can have
many registered clients, this change can be expensive. Applications therefore
ought to consider the longevitiy and uniqueness of their party identifiers
when instantiating these protocols.

# IANA Considerations

This document has no IANA actions.

--- back

# Deriving parameters {#params}

This section discusses how to generate parameters, given an upper bound on an adversary's advantage in breaking the hybrid (a)PAKE. The parameters in this standard correspond to a classical hardness of 117 bits (considering the attacker can break CPace) and a quantum hardness of 100 bits. We assume that an adversary can perform at most 2^qq queries to random oracles or (a)PAKE sessions. We use qq = 64. The derivation below uses some approximations, ignoring small constants in the exponent such as 1 and 1.6. We also only study dominant terms in the advantage equations.

## Parameters for CPaceOQUAKE+

We have the following requirements:

- Nseed * 8 + Nverifier * 8 >= 2 * qq + classical hardness
- Nverifier * 8 >= qq + classical hardness
- Nkc * 8 >= qq + classical hardness
- KEM failure <= -qq - classical hardness
- KEM ind vs classical <= -qq - classical hardness
- KEM ind vs quantum <= -qq - quantum hardness
- CPaceOQUAKE vs classical <= classical hardness
- CPaceOQUAKE vs quantum <= quantum hardness

For ML-KEM we have Nseed = 32.
For consistency, the spec uses Nverifier = 32.
ML-KEM768's failure probability is 2^-165.2 and ML-KEM1024's failure probability is 2^-175.2. Both are slightly too large, but we deem them acceptable: the chance that an adversary encounters a failure is purely statistical and very small.

The following subsection discusses the parameters and hardness of CPaceOQUAKE.


## Parameters for CPaceOQUAKE

For the security of CPaceOQUAKE+, we require that CPaceOQUAKE provides:

- CPaceOQUAKE vs classical <= classical hardness
- CPaceOQUAKE vs quantum <= quantum hardness

We have the following requirements when CPaceOQUAKE relies on CPace's security:

- CPace vs classical <= classical hardness
- Nkey * 8 >= qq + classical hardness
- KEM failure <= -qq - classical hardness

We have the following requirements when CPaceOQUAKE relies on OQUAKE's security:

- OQUAKE vs classical <= classical hardness
- OQUAKE vs quantum <= quantum hardness
- Nkey * 8 >= 2*qq + classical hardness

So, the smallest Nkey = 32.
We ignore the KEM failure following the same reasoning as above.

The following subsections discuss the parameters and hardness of CPace and OQUAKE.


## Parameters for CPace

We refer to the CPace {{CPACE}}. This standard requires Nkey, the number of bytes in
CPace's session key, to be 32, so one must set H.bmax_in_bytes = 32.


## Parameters for OQUAKE
We have the following requirements:

- BUKEM ind vs classical <= -qq - classical hardness
- BUKEM ind vs quantum <= -qq - quantum hardness
- BUKEM public key uniformity vs classical <= -qq - classical hardness
- BUKEM public key uniformity vs quantum <= -qq - quantum hardness
- BUKEM ciphertext uniformity vs classical <= -qq - classical hardness
- BUKEM ciphertext uniformity vs quantum <= -qq - quantum hardness
- BUKEM key * 8 >= qq + classical hardness
- KEM failure <= -qq - classical hardness

For, ML-BUKEM it is as hard or harder to break public key and ciphertext uniformity as it is to break indistinguishability, so we discuss all three properties at once.

For ML-BUKEM768, the resistance to classical attacks is approximately `181 - qq` bits of security. So for qq = 64, classical hardness is approximately 117 bits of security. The resistance to quantum attacks is approximately `164 - qq` bits of security. So for qq = 64, quantum hardness is approximately 100 bits of security.

For ML-BUKEM1024, this would come out to `253 - 64 = 189` bits of security for classical attacks and `230 - 64 = 166` bits of security for quantum attacks.

The ML-BUKEM key is 32 bytes, so this satisfies the requirements.
We ignore the KEM failure following the same reasoning as above.


<!--
# Test Vectors {#test-vectors}

This section contains test vectors for the algorithms and protocols specified
in this document. The test vectors correspond to the configuration specified
in {{configurations}}.


## Password Confirmation Protocol Test Vectors {#tv-PCP}

This section contains test vectors for the PCP protocol specified in {{pcp}}.
Each vector consists of the following entries:

- seed: 32-byte seed for KEM encapsulation, encoded as a hexadecimal string;
- salt: 32-byte salt for password verification registration, encoded as a hexadecimal string;
- PRS: password reference string, encoded as a hexadecimal string;
- SID: optional session ID, encoded as a hexadecimal string;
- pk: derived KEM public key from PC-Init, serialized using SerializePublicKey and encoded as a hexadecimal string;
- SK: 32-byte shared secret for the PC protocol, encoded as a hexadecimal string;
- challenge: protocol message output from Challenge, encoded as a hexadecimal string;
- response: protocol message output from Response, encoded as a hexadecimal string; and
- key: derived shared secret output from the Challenge and Response for server and client, respectively, encoded as a hexadecimal string.

For these test vectors, the KSF is SHA-256. The vectors are below.

~~~
seed: 40e5a6554eb988ee21e84a593f744e611ededff48dfb0e43c763b3a8b0315bb
a11af1e05e840a1521987ecf82a37fdbbb0216ecbc85ce51005fc61b83d7c0929
salt:  b33f867d93433ff91557e6ecad9d934935cf8da580538c0e444eee15c86c32
04
PRS:  746573742070617373776f7264
SID:  4c43fe04b479f5b41eab59f18d93d5a9
pk:  67f7248ab55a3a35c6e9e1acece73d69d50a67f87b0a1c4aef942953567b6d7a
101ce75dfe04c5f7979f93d1749fd98c92dcb75c975d2830ac04a387b78a13573b076
ee3505a66c58c3a404a202c1f0b7d4a2b1bdd6696e1caa35bf89df6ec3f54d786b3b7
7f26ab3a3af755ee96c6f155088721966cb732e1c40f2e78a614b8abfc030c6d61399
f804531c90ce50275cec8035b77c3e8b7b049793d51b022690088e7eab901198b6e09
071dc946e67732c7a4bbb394714a61402dc64a28bab16f111ce34149a8150b19fbca9
36c45311020fe357300801ecb8b5513ab12e48592f6d922666a72229c9bfad3c92f15
0e2223154db9b50fb07fc0748fbef872ea9b5e3c22447487c1805ca0af8725573828d
40aacac9759ed48664c12a8641577cb8c5aa1a501fccc2149d123a4c48592fc6c9089
54f0e383996b8687d658a94a18a242274c08839b306b81270b1c717dfcb36c10809b8
ee5b70c724ba761b2c5e4ab43823725fb5fc46b17007038266b258ad19ac4369e8cd4
53c566a6aa85677056933bd926d466a5f4a9b0dcaab0d3f8a5e603681f960b099a5d1
ef8b677a27b02b9ae84a34f1f24445788be59752a68b4777613598786a50d42568675
82ad9a5a79e7663b5b28303959f5c5a69f5173d702bda6b6a0e0656613e58ad9e75aa
b353b8a570b88a79d3e020ad50738a4e17b82b0852544b212990843076a070323a491
8bf1f3144a70ac156232d83773d3d5c1137907e83b0c68165f71a1128122418669565
9293caf20512c73b3fd2a4d85f99d422c5829685138c921468126709187eb408668e6
a9e023565899ca69a53f1f79c70d2c525c7919289247278021387351ead1122fa5c7f
ac0022a0ab4413437d091804e543d3deaace3360978e926cb71bb32280b2948cb061b
7eb6187ee020602037144b93bbdacc1c5f362dc2c7a738057e5c973e0cf77f3023461
1052e949b22e0a32d67d68e5ea28c7e95493419732f249aa28c08e9509b9940845625
5e46fbc46898c61a6408b97b00ee1a868b2128266bcc7bca38e214b43364b408c0c54
67b472e592f1165aa9612b863b511ce31795fe320a0ab6f6851ca4f896675fc02eeb8
4f3d01ba691b51396a42eec0ab32f77eb061a72c902f3f45ba424088444c4857913be
91bb31e161245f3cde1aacfdce5a866224f3db0bcd53529b1da2be6020d1489839e00
04071a5607f33f890b386d6835792788e3c794136503f0c4269afa031ef6305d010b0
35a1325a8909179ce57972375e5b9284cc328b66f6e076d1ba085e38c9cedf29f2913
470f6051f1fa6a3880bd45e5784f019a93f37789880eb01c3fb9cc3ddb096968675a5
d65acb99571de52bf5d282731f34d5e69c070da3795202f65354034e65f35267b74a6
b3ea469936230f493c4235365d4357629e9429c2ab9edcb279be2688f690849e0b1be
d94b7a0d1113c6c372d247cd7b46b9cb492324c9e705692e888a7ffe52ca9f00f5dc8
2888370b09db519e8aa743052142e34294423a29e30428ccc94859693d07b5cdf6115
e176fe8da8dae1b4bc7a5c5b752a52e5ccdced571fbeb3b0f14a5fd2a397406980fd8
078e8786d70b2738187747658f58658b14d2b14d1f04ca18347a044c9b21b0bdb035e
33d2aeee45ab3106c4d8ba8ec9c9dc3eb4167db9965d92765c9b4522bb08cf35fd56c
1a19c426d38a6263c45728
SK:  75e99907f38993c973b58599ca73122e568baa5cfa2736e5049dd079f295362e
challenge:  3a27df1e4b119f391ec2e83cd864658df3b4cec728b32ff704cfc24fb
af3cf72a31c6a115f1fb58269c36d5256e6cf92f62de157b4b3e5669d09982391be43
6038da6950b09b2f6a860b793be2e670b723a5066e854bd505e7634f18fdae30e2ee7
2467132a56bbf22b854286ef7ea3c5b508088d78ebcc0db57ca7afebff377f233f10a
34ab5bbda3c200a0f1127127eaa89c621a39c67335c308869e7c100f9a98d94ebf264
698a6b24ab316347b62e2e4408bbb4241ad2430a156147914132ca937cc43dc2d37ea
1cf7ecf285195ab7dd2d6583b1ddfaed1c3d87bdea64f015e7dfaf6f5ea727b23bce6
3ea5e0614fbd345e01839983291ad7b696d1a08e262efde487e85a44384ed610704b4
9fa9d00c27ceeee88733bcefbb6b5f975eab85069988bc58883ba380c42b0d8dec070
8f9e1c6d0705606c0c0f82d10c9eb2ea17556897ba953819e717e3117f8b0f753bffa
4357d8f94b4b25acba72580682d3cd7d65d28286200bf4d2cd75dd4df4d94baf64fbb
3e57ac127f07164b99db146f29cddc404e313baabbecee1bd8393da7539da7b15f08b
7a8208d29c636257bae5fed04cd3935d1e342bc7eb29ccdc68a71a47c5f06fcbdd492
a0b80fbf23731d501c32c5fc28d974288f2c926b5eec29d4c905518d3e3bab3cdb411
842c3e2e1a3a414aff34f627b11db5f58d5d1e29e21294407c48f44f0b1c01237756f
4ed85032b5acdb7ee5cda80383fc8621b713b17472c549b362f9afd208ca2f6d4bd67
5f8a6af2c047f261b83b6e40bceac3416f7f749b81b780475c0a636d0ddb9eb49fd30
630b07dcd9ef2af3809bd251a94da40881b5116b27ab9f0d84f12072bf050d7d15e86
9770397fcf4508861f76ea461378d236ed99ab903a4026d19a22038e58f349d251e7b
d6148030f530d1c7e84a1a15febd2c21030c11a8bd2fe52bc629b650b330a7431c3e4
d6111eba76abdc95dd3af8f5839317bc2fa737107b9610280841d3af9c5b0dc69032c
f23bee87fdbde6c39a100994e5c2df3b3e70f9f52f388c9d65079ec15154bb731e6b1
3c33f438779572d23a67f5b421db648b27dcab657ba03dd355ee90dff8c4c8ef7bd2f
ed0b0dbbf7db006f0b5c045b92e77b84e9da9fdf4290a00ed8fb4d634f34ff6d84b71
951d2181c990bd374f47fd170b46fe61756b0a6011b41e4577a7e985feefbb312ed12
c2151cdcf633d3ef175ffc2f23ab28f3a80e39eea740683601a6498f4b97ad8f78884
592e3c8524d278a9a26801e813e73d228b76026f236d4cef2165ae9988ada31cca20a
f029d14969ecbd169d01de04ff946db136ecdefcaff840e21b18b6b14a1a1a3315e17
701ff74fb07f4c1d35bb6bc641ccc84a3d37aecb6fee530554d267195119da7f44e1b
a3aed0c67c07395d9e75a4e690ed0164787fa6a63b8cdd38fa090ea23982871fa1e9a
bf90712985d70e965402e1b0d4382b7be3b72e41282fdf44984a8901bdb0c5f3ce602
6d371738970a0ebc12cbe06f495b76b82217eef79908c52b8e557c47ea289255ac477
f3d9e19ff2325ae771d04195d5424c86f40a31869c31f2f585f53e924b6de8db4c812
2f02e76a2d09dc8ae767eddca309fce33f50b770f7dd5cfdd4f46c2112bee16f93499
5fa0b2f5e69dd9958f4fcc73840598e13f
response:  37fb1b659261093758f48f540f337893076b8819ef5f556696fa9ba8f8
717d91
key:  eebae83892d72a88e2d53b2a3b3f5ac0c24c9c69c8416312557f77008db9cc1
e

32 1120 32
32
seed: 3b30129132073b2a61e29403e2d57f60e530fe823ddeed80ee218a6c931f805
7764f38b1eb5665ab5972c9db8a5d8e06388a1296e440d7975639e71a37993d30
salt:  3c8fd7ae7c9aa2b2d1c4789f046f8b3155a76c566829df38d6cff98ca2ef5a
07
PRS:  746573742070617373776f7264
SID:  773d45f4506bff8e1cd2e9d062b8a23e
pk:  8e3292fd769532243b141b0c922b76ec63c6f2128faa9687c2196c7c99347d96
07c765a3e0faaea43829e8134c54a4c7bda82231999c61053cf29b2ef6fa91f5da948
4ac33f0fa510b8b324697686bc1c4dcf2b4ebe636f2957b8626c823a9c92b8b9b2401
2cf65cbda16038a8911c7488c76326b5cc4648a62b8bb476bffa79a523347c7443a2d
7432ca7f016e9100620264eb9e05250e18cbfd02347f3681b513eaadb6d7067984d9b
5692f703273c6e19f16e757a45adabcc4d3a3ef1eab1890a0959a93c88627f057b78f
94940a29a65fbc0ce96276d9c334edbca17d18404a996594efa0672ab2e1bd078e0fa
6611127835e9757b5c8033d67a318b01d07a536732742efbcac9c90830e30b4caa116
39c5681a4c16fe703d2e68b26cb6628a74b039344b6c58ed0d7ab63809940c393c463
6cd8836b9327c052d839d6bc503484303ad84d36fc98625ac457ca2d50969ccd31560
ea465abfa8d0240c20bc17aa95309dae53ec510b78b4143b3f97333aa7166d80a67b9
8f9d78ac64003b90595c330aae1ba15f1c733392ab89c21213e20c273d958311d4314
ad21593859e3bb9c12b26c916c27fad4ccbea3a916bbb481012b8fd6600bf23365b07
6be7f8b3d128426f5269a355bc4c628663e96154a65fa8ea357eca432360979218775
9d248bee2593ae47071486a9b05913534b2f6e94111c76488fca850798715cbb32664
c9352c5793f69fd9f3c9a4604aa86466f6008f94d7c719aac8bc5a2471a50f4a6b3db
010656e3544f1e940e1f6233d7c4595d8355b5055ec7c3c029407d0ac5b40357bf3ca
09a1743ef9d16a3212767b12b388148e94c13612112deeb34078b33ef8976501867b8
2965f1933123910a0da81b396dc32d66485b18748b0e2b0cb760fc42770766a401761
b08c3b7784167fd1983575f94c09b32f38a684f126312a9ab96f29c66812903107bdb
47bcdb226404e50a2c3360a15f95e115654062974322905db67a17eda1c190219e4e9
15a8189bb07a0441e37851312348c488f6514ffe35332ef99da4371025e53bf531202
3b199da26b05af08f54e2280b5594d498519060129117c0c396853f3a4edc42b91cd7
0dd9c53e7843963d033b7cd384e91353526941c7a4ada76a90dfecb0e6cc243393af7
572cda8654b68d99a3c8176c8897ec7076b39e7978bc0427ee8908e9648b75913f610
5e5128aea2552ac547375217aee72104d244cc50585749b9011651c5f408c9b4076c5
a256429f582f58502dea8a12bbb4f644c93845aa72f46109bd3ac3ec224c17a4e7eac
83296c0e803c7090cab15688c78bb733f284bfc03646c8984943c29be0601bb77b604
8c418981a0099221679696ee917cc47e17d5c56ad4c11c02e3b7fd4c1624bec169ab9
16adc07e53870c46a8cba3a4784d9c53af537e6931bf96aa6e3e80cc5be359ab67a01
8797eb5f670f488c103254e5bb539cdd4560e0a2a19e86a3fe0767359014ea57ac9ba
0d5366ce17e3c4a6280136cb3c42960ed0887f1e9019064683d75708c71b9e14118be
bfb6c394c5279d38380a7a920ac08ab8b5477a4174469aad57435792c5e784b0a8005
3a50600891a84a7fb0ceada135936877d6f2fdf320cbd88d62311b60a73d482319811
4d094af545fce5335a145011115721d2bf9ad6e22dd012bf4244733737bf74bfe349b
d2d91e0f8b60c0dd863f2c
SK:  000a7035444b5505dceaabc0494c435631abb144ca0242d450d463f792325e5e
challenge:  afd063e56a36a60fa0520e132f583b75fd82d0c823240e94f85dbf464
098c503af451d9e91d253d1f2ee3da15d00370a80a1f7328e8b4f2135878dcff0a579
86a7617774d64c00aab8e3dca2732857cb3635dc3e788e7ecf07d115db713a8d42a4d
6e17dbb1af37d1dffc789344631cf38ff80534d18e8769bdebe2b2a7d77f7f8cd802e
c644d596186b696144df96a3cd14c5177be93a9c7b2b4cb152f1f3313f69bd5fa206c
317b6d5bbeb578b0241d21d5ccee07aa055dce6f969d921f448ce455287ea6eba1833
6155b4c7fae472445d2f30588084bc7225fa07a887db6e586e4d4f44af1c294cb112d
84536b877c570053a365780e2f3ccfdc92be8cfb527eaa3ac87e2c02aac6d129d04e1
81a404354c9fc2eb4d73513131bb437048e974f3e6907d2b28d56493634e5b9edb8f7
e356854119dbede512f6cc52794d1c15059bbc59d3783b07088c55b48f8b4b69fba9f
5dbe845eeb86034ef3b6d0765f1bcf361952fcd94f9ca33dcf2f5cae6943518fc87ba
aa4acc5d8ef056bd65e60ac52617254681e41b31bdb51803d1a27731dc4183255ebb9
4db1b45e7a84821e358a3ce0bbfc8f982bfb7ad1deb61e6b8718875c6cf6549dab765
45da0d71891f7fb95d51bdb7aa362e7e27706761da2f78a70f00aeec0d6d2f710720e
2431c6c35e3760b93051d2e83c6c68c125e895973555a9de6b736ea8d38d913f2d0ec
9d7d41fd23ae1f999af5e1e3f10d4dd2753f7f83b550139848bf582833bd34248c424
5f01f3131176eec196dc4ecb6c6517a7cec94dde2806af44557c5ec07d63e6efa219a
723bec5f4e2470e5a57b021b395fd1f8d36826d99a9b0eaf1458d25fd52ae499a1587
0197f4ecde53cdd7b076b44bded65e6a291b8a1722af52bfff782173d06f65678a186
095fc48d1be339ce280c21d356c298a60ebfa9ca421ca091ab5e2f28f5167b641c0de
1cba4c5ddcf27950350134701696fe5b6063b3a21d7690a2c2406a949db2f88c2d205
e20f92012618ae0698e071c2fc6d81bad5c791dfb8e391b4138edd92bcbd05cab4566
160421165406b4fe3e17f87e80af03e942396c8dcf590da6b9b30f0d08802df320c84
c88d46251cfb77f3b94a7908caa718ce2deb31209c00dcd0c990c31c1da93f4755cd8
97685c1234e3cb92b08ea6ff7ce035bd2372552e29fa98e7ef9890ae9d61c83c8b275
9f3edee6cebbd97f1b6b063efffcdc792e64343bd368a99166d313f6c7757182d89a2
9c9f6f32947d95dccd47164184c51b555e303fce895f9750f2938d94912fe40e7cf2a
3b5cd9c486906f9f76744de9269c4dd3e1469cd0dd720ddb59f5effe454da764a99f1
1fee3abe86ff00a190c1de28965fc9b3a42ceb6f41659c140773abdc2e0902a8a0c56
117a25c6f7b19c5e5d9c421daae445c402a500c0fdee03dce2f5dfd6d74613de7096a
ac90db5ebbcdd92837f9fad8ae397d7fefdf10aebdf6df4b27f5f61c5ffc47016fd5b
8f0456c858d92aa3f0188dad5b271779ca0ae479d0bcc301be32397aa9905b164b788
7136b5b33a39e49bc6a9f9f57482b2aec082faecadeb0eeceda3fb6ccc07132c37601
f7849711dd4d5d5a27ea3f43f32a1dee7b773fea55cc4b6ca3e46efae52259d1aa079
2fbaa62a0e7f126eb9d80ebe44064e008c
response:  5d30fbc51d341e49c0cdc96ccfe18a25372cea8cd7eed01acae245d402
6bde16
key:  ee7ac0f6a0ab18483d203aae52aa893b746ab54df182ff2e2e0d1d4f73605d5
0
~~~

## OQUAKE Protocol Test Vectors {#tv-OQUAKE}

This section contains test vectors for the OQUAKE protocol specified in {{quake}}.
Each vector consists of the following entries:

- PRS: password reference string, encoded as a hexadecimal string;
- SID: optional session ID, encoded as a hexadecimal string;
- init_msg: output message from Init, encoded as a hexadecimal string;
- resp_msg: output message from Respond, encoded as a hexadecimal string; and
- key: derived shared secret shared between client and server, respectively, encoded as a hexadecimal string.

The vectors are below.

~~~
PRS: 4b6cf40f371bc801e81b8f2b26cd5a0f
SID:  652b728f66e2ee44a5354dfb7236cdca
init_msg:  59fb9e82387ce589dc8e2f4a2759eb9402ad30968545a119419e9a36bd
eb4d712489761cc7cd4e8856289840903e871a12c9ecf199e7e2e4e43816fe6049a6c
9ae29ea00a0bd58411bfd9a789c9b57ad7d7e45a867e7565bdd21ef79a708f27f4b92
918bc8967d35c609e6acae596b994719f9a84388d9c2707bf8db15ed13f42ca327844
c42e331ee892847bda3a21e9b9d56e47374374e94a0bf3301b09bed0d9813af3d7b52
fb85e50063917c63070000213f24e8af110197a1a8186ef62fd59dc3dffc1d0dd7819
722950694195694b97f8d62dab464321433134f4bc140c6e107b282a3e71dfa3645d1
4f7e4da70fd99e89be47f1f26b7c3a33e005a43abb71813a1fef959dc7acb109e3323
e4241f35596dfef0715e0c0106d9530af464c4699b2e3925a6dd6e996e97eb42ce57a
187c8e94d901510d462e02f0092622a67edd3a612b78fad83aa9b557ed42ebc0bcb7e
9b72bfff81916f232085c7b0d618411d39ccbac4c3091f3506d246de2d5ead0a5b184
ca5b36dd408419edc21742d6b141e9cb647a55bb0797fb3308ad49cc567a4d0338049
44cba3303de1bc088f240a45f9526bece4c372c9a50e83a669e1bece4ae92e3736f95
99d4f1f65434db5c5b7cfedbbbb9c2620f2f0e9804046ef53b5c47f0876be57970c93
74eeff829bbeb265afffed437f1c23b60af5a5210bef5f76b334bd269ae17b890320d
5e54051985cd7b67ae9a7472d70fb6eb0575a5bd44b64ab55b2cade147c6f4aa2aefb
dcb4b1662eb6c0fd292877d688cc5df46f39189869cd8c027b405833d10ed3b3f75d0
55f49e4bea1267e2635a0d182df59862fa31bee58318be03310e9d5eabd404fe91e8c
179af9c0a64d4b02d68d4f23ebb01d9674581d06d6211f47afadaf94f94eca7855ad6
10f68e4c39c045f4c41740ae668f203b712cb29607a824bf9d3a7a09455676fbbafd1
c6dc3b35837a7a6f9ae8b47237c2f9d462f9f068135190a9bac33575f8bfdde1d0775
f156db3731619ed0e06f00fb597688bd6d4e5364e02c91870cfdb593c6ed88e072a18
bd13bebe80942db9c317b7d7b9461d168295fe4ceb262a343393c8e76d214236dd807
46a98da9dd89ce75ce70155426b7d79186c526c0bdf37e27b683e9183da95d38d9159
d00a1d6382d18a96a571e2a94dbf0271f04dde59029b7e8c5a606e1833cbbd85e8d07
93b016113049d011a94a0f7530cb152894eee984541efd7d79c67495b11358d270bcd
809734860461989bf21f5cb2b87ae7b59865465eae9275b7ef904d5425d459f0c185a
eaddd3e76b4177b2171bddb9af2568f62c19c5a08491e1c690d7631cd938381488993
4923a0a2f12fd93623b762b6284f7eea3f9e2890970a851d1afe57d617f94d40aab58
85c10cd3dde1b0444ac20368f0e6ec5f3912558c9c2f23ab0a2ced9043a84291cb5c9
41a2ffbab5a7d355fb0b86a888290bcf77414f0aec23ed728803454b1be26b3f365cc
2a5986b8f85359a1d8c205946ca9e7875647cc11d02db5d7a1e588f56f9fcb971be59
246d2aefe07a420d156aedcbdbc8892958d0b7957508f94d1c97d9a80242f383d5da5
5c8dc41ef43f1cac4877b4417ddb0df0c30cfbccb7dc3a15105322ce2ff15e8c00615
9d073af55e8de553bc1b1d3cc1eef9c515e3daa6be4320e076213cafc87c4c9c4dbb3
7c9f31d1a69efa63560091c2b69de070a131755a871913ecc4e7cd9046f9d7e9ad690
45102f34f9896f3b9c66fe6fd57d14830a1bd9e4be02cb3dfa57fde56a53aca03e84d
f1a502c32646852947
resp_msg:  3c69d8f3bdbec6939b033a0cff661a5f90b3ec64dcdf0bdf3adeeae196
08affa26fe752f3e555ecdbe86f94d97429aba9bb0f2919a126b9640d480d5898c0f1
09c2594359298cfae0042d602836f3011bafd355d145999bfec12856f9a268a980cc6
cf0f428048e34b147215b3e710c252730ad3e55992f020c36953e2dad702d53a2b6ba
683d9dad12dcd4b02c8b5db9dbf7947797ab349a3567130bd7c69fa034b366e3b2144
a3be4def379dd68ce5c2127e50d6084f5e602c901af8dc245fca25f211a5c7b52b1c1
bda95dae0c32f457ea4159dbff55c0d30f709d848e0aa099bc769c2f477826b60810b
2be56b85d05f3c2a21a4b992323b3dac596d8386b0b8520d7c382ef0a33066f706464
24087d18907c8cb18c867af40479fb5d0d07440bbecef42ecdd52eb86002af611d34a
239d843e86491e6cac35954dc24a7fce979de6533996e46866e6ef66804ae7f9b3c49
b5372aa4143b08093cfb18057558083788c45cea615d4d44c7ba55938743fc4e7dfeb
eb1558556adcf19a0cdecf56f09da2c56cbe3d94d6157e8425b421080a890ca3cb52b
c909889b6e108f483b46e36e7443944345cc64a8973fbaf0b42359e7d505dc4442273
fe7da0568358a17817b7af22af9344e44cb43a83af27255a04d0a77d7c0c78231c7b1
ac2f0c3bd106ea5243d556ba5b6e0671723238ab82573247030b4f8c65dc3a075d713
2db25843ba711800b7a28dc1301e19d9a5750622149e8892523ae40ca1390e19b3bba
a92b4ffc87dbd2d9c6a3479ff802c02b54d85e91fb94c458fcd1158df8f7b20e274a6
a15866d33926189ce9c02798bf89e15943fbc73d6ca679c0773304aff40eb12836988
75e7ba4bf8058f67ef53cd5e924d8be307a57b037938adb6b198edc2c4c3136de60c6
aedf6df29028576ed39e84f6b4b8c4bff4971123039e3fb2dcb0c742e3bb213740740
52e02cab1f460880ff5335c4b1dcd9335ef213e36a51f6cb94550b3423d72c18df738
283faa8c419186acc853f08eea3e981ec9e131221fd93bd4dec2e7037b39330a5863a
cedbcbf5b069198194405d1498448a17303f0e963cac45ba981ce512b2a2cf1e0b54b
ce01f366b22c366b7bff5a56c094e005f9115ba3e6497274874e3ae62424d9f206d3b
b2e13976c345f1cb6b730f40103a6dad5b5db0689478139240b547926d41854837786
a753f0276e50ad4d8758fb8c59d46829000b81cb3e0a8d8a416008613495086f40d72
ca2d2184f8634c9c24961265dc54fa7bcd64057c0462c3cc476574ab7ec52a28799d4
747b2ea046da24703209a2bb437ebfafe144d87e2af44831fd29e72cf3f991885ac55
72366a7d363520713879bd1294c0f4130870aad78902ef083572672220e4d565e82a1
ea97b99d25954843f0293e64e37a367a08ff46f11bad769e56f41024332ea16085086
244368d75eda13117d37df5e388d2e198704c2e7f9349ac82014fe0da23c74be0a8a2
5c07b48689b92dbf6f328f998c32af4bdfd2f1add5285161983b58e5c86413e15b2b1
410dacf4daa116b9a9663ea40a3383375033ee94893
key:  e795ba6852ff724c76b21a65e3e0c889ec75b5c0f1a59c8abb3ebb414a5b9af
a
~~~

## CPaceOQUAKE Protocol Test Vectors {#tv-CPaceOQUAKE}

This section contains test vectors for the CPaceOQUAKE protocol specified in {{quake}}.
Each vector consists of the following entries:

- PRS: password reference string, encoded as a hexadecimal string;
- SID: optional session ID, encoded as a hexadecimal string;
- respond_seed: 64-byte seed used by the Respond function, encoded as a hexadecimal string;
- client_respond_seed: 32-byte seed used by the Finish function, encoded as a hexadecimal string;
- init_msg: output message from Init, encoded as a hexadecimal string;
- resp_msg: output message from Respond, encoded as a hexadecimal string;
- finish_msg: output message from Finish, encoded as a hexadecimal string; and
- key: derived shared secret shared between client and server, respectively, encoded as a hexadecimal string.

The vectors are below.

~~~
PRS: 95fdc24f9330e38e226b6169c9b76243
SID:  019ffb301f2cd83a7fe4f20cca7b8a1d
respond_seed:  4af73379f88cee47ac4a34a41204603cb673304b00b471777a8ba0
abbadea6481d1f03f00b20571b9b3f9019430a9f6ca807bfd9877844ea2c846b7a691
c4429
client_respond_seed:  a1359fa55ee62e45abc989df0ebbf1f9d6d77799271944b
b7f161b1318edf4ae
init_msg:  0470fb7f997079372fadf64cc0bea52b60a25aa2a75eb613c8c6ecff48
382cbbe1ee710fdd7761b8998d4c81ac001c2e1a186bba88dfe3046b7ba26085714d7
eb4d79c6d58b61b99272ed87b7180bd96c3e9bbe02c59dfeda84c95d06f3a7fdf11
resp_msg:  04d8ac3a98d80ba2e26c9afa92eea9ca6eb28fbd0661a1086a04062432
64b9c021efb7e8a4a81599ca92e0a9d6e713f379c9133fdcce8829510f7106c9007e9
48b3f865a6ce7365c86f540ad587dfc79fc3ef81708ede611e79009fe13fa5a08dead
3b519a73394e1c965aff84a27f83cc28940ae0c517c3450f09761a2b5ecd53069e76c
f63c084c3d0965f4a624cd4c916156b92966cc7a2c78a809a8d611cb387c5f5a4cca5
cd98edd163df78c8c6ed204b3e6defb7f2e8cb5d45157fded7ac8190fe45bb7481401
1c59fc02ce5a91dbb003b8ec39018a1b47d59ce6f748b40523e3a8c4a9625439506f8
56cc4025269c608fa8d6358c292d4e2e2d41e26199b2b61d0b12ce780518c663fe641
b1af74ca57178e1666dcdef7a50d474a47519cf565f5b3045c36c9c8752246cd6d7b1
376c0c7688453b5c120a70503a8d407287bae71e976f3e0ce54ee2ce1e2c7d3fb2937
b34a6c40b4608dcf615e628f0c56fc31921a25a4261593022c5f222bcd9e08f4b3e09
1c466d4f62ffeb48538f79574b04c0d181ad30f9488aee97153bb5b570b40b425a60f
2d42b88cf8a434c7eb9f844358c49a0d6c35dbb87c39da659e4567607f9211ae45b87
303754211bc799952ee027ca93913997547a20d17c70f012f26db4562476010c82101
9825365e732c113695302ae82fad948cefa6c1527b4e7867db3060b9d5106ebc154eb
69d0454d5040789e5593a4a3290305d9f780798e750c6c56f2ef1653e9271aeeee7db
5850b7ee6f54e7e865f485832aecd3a1f75ad2f0fe9f0b0e9db2a84fe2bde39c240b9
b16b4241a585e579444e4212f7f047360b6750bc88d9b682892fc21fac3c6ae27d7fc
46773424f931ffc325e098157899226498beca1ea65370f314c3b78fc963edb7ff1fb
cc1554df08cc46d7438d96ae91b9e5038bbeeabff2fda5d242e678e19959a5d7c4491
9fcc63e41232b4b674f0f9d03777a4d06286e55b6bebc67e6def1c64abf758e5fe2a1
f490312ed5715fe6a3659c1067c69630801d1d75bfe9a4e67b6ea638ee6452cecb96f
8ffbd99ab95b067e1fc25f847024e25822ca42d5676bb66e17e71bf72900134ac3597
5c559faf239ecf1ab465f1613d3cb184186e831c1b8b2448145f05b35e7a0215b2a81
4e53fe4c2108833f050fee8c2239dc1bf67c87dd2c6f1332d06e8f337644ed7685bc6
79d8dd8786915756f2705a4d1f97179943934ae6823b36c8d2096165d70506b595659
ac1452449f1ca3a35fcd08c793df9f8798830dab531e9147d1a7847eb564d1eaf5290
c612b3e282fe661f5530f692ec362eebdf4acf6308f588e9729bebd1d22407541d464
68cc8f85c492e9a575e7a406b01482bde89c60e43720682bb8fd8f14627dc262d1d1c
86ca004672368b4d008cc3d2bb205f62c431f5f29763bb0452058edf265f5a2b14ea7
d65a75ecb763e3581dd5b329b3e7ca9c4cb128c7f4e61abe7c6d9e428f687c261fadd
772bf9db759d7f07c3de34a85fee53bfb9e7acd93dfe597d716f2471c65b3d905a108
4f485e5beb0b5e03de550a476bd2f38455ecf1b324c906caeb3ed38e2135e6817c291
8fa430d1fc042dfea4325f6f0ffe5632277e56bc615f3448dc0f3c22ea154edea2081
31730e1dc06548d92d224e598ded68052276c68833f4018e0e6c2758ad18306a10aae
b2ef65d04f41c948a082a7125129aa55930e4408e807287c89d8938c1c5580d44ac3e
a34629ece428be94edcc530eb481516d99e5796f3c807604cb3b1cbb181323da06b81
6e82555674e2aaad11fd42b0b523fc5ab9534a32591ecead66af7bab26357d6c0a1f7
39ee6ea87cce2ec3a76744fb3420d8973607a82e017d1f815fab2905e6a1daf724326
563e31de4e3be87ab4e7765822bd833c1e80a6704655951519b44db6d04aa4c130991
ec4b0
finish_msg:  ede54396ba16d1bbaa128dec29f4b6c4ae3fcbe358c7e3039c328f3e
d6329be53cc00acbbb29779dafd66ddcf9cc646cae3342c27c268dc1cf30e17cac3d2
7ef67e57be40dc8407fb3604c9953066191cb814829efb83f8dc1eca01e5d11cc2982
0a7bfe2905e48207ed4531413a671f2798771c1b134aae989222590839ee3a9d325ee
364ceb5fe151e79c1ada732ad1f16332b125b80a24338a9198746e5c482208355fd71
1eb9883b7178b0b30d8fbefdfd6476ad59937809ece53dda7159b1fc9681f882e02e3
f7ca4c6d347faab6a3c2bee9fb40b2b128d1515835278bbbb39fd128d09fcb9244bb5
0eaf45a3737851845faeb8be99f56e5133cb9e64247296823ad1957385e521e714ca3
f3bd5a20b2d0d7062a7b1d39ca26b6535ecc8b540748d1e9e1ec7ebe3567ee9d74ac1
3cfafa9c4dbc9ece8e95873f7804d2aaa9c1ae9b258ad9bf235065b9404f6b977dd7d
382f94a7f8222a479f38dbe62d6b6c18725b7cc54f52a8b391f8d4bf2aab5555aaa43
ed39363011975d9c0ee518d1ed101e6972c728c4f7c697d89b3ff30352c85c10574ee
7d25e340c68149d48358aeda8cc0120234613ee5c62be2313a83e6c5dd943ee2b8029
ad5ccab1fac80ba26df5186ea7f077b0ea907fa787624a2bc723c91a0dde8e347eb25
921a8b1fe0c63101b8e95611656d1dcd3950a19412b3e380031131fd11dfbe6b6c5ec
8910e267a997a8141a883c6bb160abca75bf0175b2dd8f5d64cd21b9c824b49e0dbf4
24fb11334c35c9e34b13bb00a6cb4f88e3524b3db4b7a4e412b492dae2f5de34720bf
7165e240113839c390d4152b89c26f6abffb75d7c65e6ccc8b827299c76e26a8767ef
4f7f812345cbc0f87a3ca4185b2cb1d0493d4868c76b82b498d25735cda0d8fa1af98
3a0650da133afb581a73b4c0c2efae82f394269af4826dcf8b5c40b3a3f73ce5c447d
441416fa8429fbee319cc8f3abba7c0942908d6b5f8be4670b418c8ac5a33a24fbd19
471bc9de44f56a0c1b9a02156049c8679c2287a8c99045eb31eb04c9aed7c64d4652f
1b6c230ebbe56e34d2e02f8f9025fd85f254f232a1c9599913513950d24bbee7a9a6c
f49bb5c4bcb90bed2d1745e29c50b858297c1e8efcd7f38a9eb4ee54484f5b3403e77
979900c97296c3b79f4b6c8473496715d1d21e4ece8c2a7c3b0c02c052529ee5460c7
106730c4782a5557caed41f0578056c6d5e894dd14880bb14cf85562b79f18b937576
28a1a61722f6dade684638fb2047576e692b206905749fb362ed7d6e5af17be94b2f8
7e2236e53a7fa521172a7c395a4842d21ad69d0689689c92943669f63f9652b86ecf0
b120ab0bb280934cb67db883f0d2f210224cf3f7f2f1254a689aab54a8366ad264852
8edfb014e0de56aaf2415a50b6d446c83178ba76fdcf86f1c9b336449d346c1d44216
6de28f89b33063ab3f493af1ec393e665fff1ee4acbed39fa9b05169c256a5670ff0d
7d7afbd56308bf997f78e5ec9035117f7495c09d7d6539f63ce4af995eca7d27a4f4c
35bfd9d2def1792cce03c67547618e31c75fa11568c7d
key:  ffd24aec545e3a8c651d25d31dd8ece89aca16c41f4a7688f126702faf27ef5
e
~~~

## CPaceOQUAKE+ Protocol Test Vectors {#tv-CPaceOQUAKEplus}

This section contains test vectors for the CPaceOQUAKE+ protocol specified in {{quake}}.
Each vector consists of the following entries:

- PRS: password reference string, encoded as a hexadecimal string;
- SID: optional session ID, encoded as a hexadecimal string;
- pcp_salt: 32-byte salt used for in PC registration phase, encoded as a hexadecimal string;
- respond_seed: 64-byte seed used by the Respond function, encoded as a hexadecimal string;
- client_respond_seed: 32-byte seed used by the Finish function, encoded as a hexadecimal string;
- pcp_init_seed: 64-byte seed used by the Challenge function, encoded as a hexadecimal string;
- init_msg: output message from Init, encoded as a hexadecimal string;
- resp_msg: output message from Respond, encoded as a hexadecimal string;
- finish_msg: output message from Finish, encoded as a hexadecimal string;
- challenge: protocol message output from Challenge, encoded as a hexadecimal string;
- response: protocol message output from Response, encoded as a hexadecimal string; and
- key: derived shared secret shared between client and server, respectively, encoded as a hexadecimal string.

The vectors are below.

~~~
PRS: 41ac73f17f60eec0ee8cce874a4f9a7c
SID:  0744270cab992ae77c1cbea2ebb4c03f
pcp_salt:  9f5b52b091f6cea43c531ab526c6380ba665482eae33fc5c7e8f321572
3db2cc
respond_seed:  9ca72674368b8e8eb3b8868ac7be437a081a46be2480166e128ebb
048583324c8cc54cf679fd91e98f99567204e49517d745c4ed5d54913fb55c084e9ef
4ecab
client_respond_seed:  9bf12f1a9d1edd3e5aca33042fe51a2d42c37fb2f979812
ab150d8fc3e1811ca
pcp_init_seed:  6e410475f8c923df6420589ff93cc60f21a523f1f4d0de7b4bb62
d7078fc7e74f2c9a84a5b5d893fb75cb89711d8d83ef188f63c64d3106bdaa5331deb
db21f3
init_msg:  042d6e23f15b0ca7c0854f57ef4d12b855b74c04e29f6c73424f1f0100
3d7c26577f39c922ea3cdaf212603f462cd2bd774270c87d1997820c1a05f59ff2fe3
3d7ac9d31530e9fdb4cd0c76c893afb570bd6444f63e9dcee3c3bfea04f3b287da8
resp_msg:  0473c52c05586d8c1fc3c83ea8713c575fcbc176a23d4fdd92408c758c
f2d455da463d75b015cec7bb421c5e9dcb49873f3c4ee92e1dbb66f32c5d480d09971
e1fd6f48b5a7221b97444d46c555fc41cc17c2809afb8cf9c4aabb5d41378e98505ac
c2553b27572898d72c52ba345d24239565b5aaeeb23fedbcf4bd11db9a81088e35438
b196b8c42702111579ef5c66b0df7937aef44b24f8178f0a2d731f8d0eafcb32ab3c8
e0dac5b162a02773e15f280998091d0418c6679093a668f5f3f84877509224dcf84b0
f0aaf79ee5903682c9c3a34c6541dd85fb2e11f640f2f178cbfe963d44d2a41b6bdae
e83d3391a9e84c3b7add5759eec7cc8002d6405ddaca1f84c45d6526826b5db09c49b
d0b2d291777dec859e276304ecdb6dbe0e84c8aa7e564c59c4a36185137163349d779
9f9fbbe584801c7b1e4683f332a4b08e9892172de0bd2f1bbcd213284b1303c5cb6f9
5a1e31b7833be5e0a1330a8a0b03701871c234e0a8c3b5f1471579c05ba6f42283a0d
65d0ca7a5058a5b93a7a11d9d75d08764517fbb07a1ecdeab00d4f6e2058011bcf5ac
94d51ba21fc1dedb59bbd851ac0e6be58485c835ce439b58615080982985aeb73f272
59119384c94630d8a8ec7300d5f0b71db3ef5469b26fe8ee3c6b19cbffbb85531b81e
c4df164fc5e52bac40d084142c39504e55668626886b225fcf263c345c9155d805d1e
679907b8b3cbef82bd3bbfc6ba66047f79f284d7c401f5910c11fd1ac7523057c65c0
8802b525996874f748a529f1d4717827bf202a0ba8dbd3eae5cedf25bfb6b5f7d4e1b
bbe27d00d0fa120584c93899220579270bad126182384e5e42fece3439b9f87302127
de09ef6f0d6f01ecc7e1c779fab4bf3753d77d2a1af21a73d3da03de568dbb533da5c
1319bfc51ad887124bec5742acc2db42d91527c5f03913e8a388341db1f5df395e237
44e5ea29799fca3e2953da5aac19ade8bca6039bcbf4363ba0412d239b9fae4ddf527
ac62d6d060fcf152e84c568b17f232f2755ae6307459935dd761b56f50075188173a0
b1a708e0c463feea1addfd2110d131853596bd24940566c27cf5ace6582a116d72250
f5d2c5cba3939b60364a29e22652c299ec274135cfe1c7483a76b57f51278f342e47b
0efa6b02624a7263184a7148cb500c19b6dcc4d8d0fa4864bcd48d2c982850587b8e4
cc97f1a21e3a1306a9797f00a2e2db20c4a5ba2b3063a231b00bd21b63ffe1856def7
00b583bb1dee0b68e3c5c0713136f4cce803c4e206a18de44e9010138a19eb56efc79
28de6681ef3e7c780bcfe18a120c581ed02980f1f94638281208ddb52f293ccd717be
b4fd1db30467d9c3e0eb6dacfb333479cf984a2f536cedf29b2fe4a060a44026d96d8
522f808a8af156e0da559cf795d5c87cc2aedfa872e4a8f9cbbdd197651f128b1e314
51bd97d1086fb97178a1a35510fe90c56d5fa1692e17a9226134db1de8e00480ab964
f81b8fc07744af32f31d6290d8d62d9c353356d3ce61a76f6f486b6069c92de0826cb
67ec5567fc43b03dd3c3c1213f389d27df91e5b6135518cfc252ef80d26c41b96a738
35c280381dcc2bba3e8174fc953fe9d0beff59bb993a00bf791bf6b8eb1e1deaa541b
f444f3fcb6388612585ca5e0d2b9e3e015a93dffd6f9e8d078310099d3cc848e8df8c
e1b3c574f161ba6c188aba22ebc3578054426e2dd6a587e93fc82c2ba672cd2b5b4d3
ef3a1b15ee89321977074fd413281978049f0404dc3691bb0a05dac4b0448787febea
dcb8fc5389573f95f3070b0119d629aefd228367e25dc0b39e48bdcf9f69be9ceeee8
5265935ce91743bb1f7af5f77a027ade15345c6dc31bfe6b146503ad2c0ebb0d0bffb
cc46f49a0ffe089ad53a70fed545862ae88cb3f05d3801de7c648dc2f5e485a685a25
a9466
finish_msg:  6b5cb16f05cce347ef09985934b84aa864525eed628bf4f629eb5a4e
00e79dc9af0369524728b4b02fb35340735afe1982e9630276cc11507aa867b08f1a8
b4b334b77e5dfc0490b28a37a24db5ee81dc83b7e62ca5309277384191c50491c6239
8113a9a97ea10d394a87a7695960ccbe696ba9ccc66e8798d7f6993cb7166c3782e54
e306cf726afb1e2608c4bc0478ab210d63b99111262ab45da115c44b233a2c5e000e1
b533741ee1ee4fc61663c33f4f642e2e44687334a1ff89eaba2e81d10b0ab62c80379
9846a732cce5aff1e0cfa15ff25c9ef7b736a9bd8e687202b6689971c5c80642386a0
9309dc0c2848b8255d1b8621ad36df2fef748bae6075a7a7a3b5d53cc0dce36ca71b2
70380fb4c27be9327dc0fd6cee07bb626d989e4ed31bfb09247d92fd954fa238b037b
2a1bceca482db496a43e2c1ce75d4897bbabae60b61f9e3720cf912b42f0895326147
f4ecdbd84263a839a8f4279f41d01ca221340141218b6bcbecc0a45fbc1611dc1db20
cf5b6eef0838ca41ffe9ac0ceccf19dcecd8195998f5ab2f79da7b1e32aa64ea39a82
4ea12e9c0f435ee4fc6648a90e6d8fb2d0f68b0d921aa8d3eccbc7ffa06a12c06cf49
6c12eaf93f160ab4cfcf120cbd9561e5a98f15432d25f04c01210c657efb8f195c7db
66fe449e1cdfa806b216d8d3956f683438c323a9f119e69152032f548faaf349288d2
f1be03dd489073ac60ff78013cd36a4d14041a57925065978eef792eb7acf8de709bc
960dda900a362ef2711e07b50613ce91dc5d01900780bd1a5615091993b27aa362516
fe0a9622ee5baaf06584190324d8be291d7f696eef2afcc3df1e9d6b7dd7eee874e30
487ade9bf79e4766976228880bc8a72d23f4550ea6822e071230db6343b833cb44072
ca144ad94fe14283ec2b98c80e6be4aaf518e6a9db3b6bac9cc0b80100968bd614bc4
8109ecc5ebfb56ec3a3455872bcd2d1ce8b30d57c4960f6389d504bb22f0092121132
df9192bff2ef8bd3fd12a6ed1191643e79000bcbde5cd47f1581f46f82ebbba3f0d03
913bca0498ff384be79a485aad91fe75cdbe4dbb6a884f8ea9237ab4f3ac54817f1d8
0b1100d4a022325e8a144e13873c4ce5604f8cdfd3e5b21c04ed0deaaab9406381212
b9be4f1b216fc3790b2abd521ae18ba9fa8375f96a9b4963722864230cbb598902360
798fceb7c7fc8c672c7b6c362fde5f08d04b85e744a870e2d3dc3520bddf38d5bd50d
274571313789d8efd9c32a6155609abcde0287f374c89e60487fd8e4882bd24491996
0c048984e2e14464afe449032b560c3a2a93896dfcea0d04960cda6e2858b0291709e
7a1cc61f33b65f05d4d84ac4e48ee8e86ae11750102dffc96473db257e445b821fa5b
8ca563acbd5711e07c643e2840f4a0491d4e3df82952aaeabf0adce061d2c7d54540c
a22e22dfdf4332fdcc949e6af3a9d1d0c5bb0506e94f63083241ec57a435719850fbf
802187d700d4088694db7e188971a9184f741d70603b5f784cc826835d4da0725fa77
f0e78d787959b4e66be1732b7cfcf0d28323daa3f198b
challenge:  4902871a0bd91409647c036591ccbf0f6a794d0ad20aeed41e1920888
0a8bd5ec184c0206e37257b788417bc1f8fc49d6ae783378859166328f07754548b53
7a08d0b23cb5addbdcadee252524c964da28a518cf57f947358fd7275b10d48cfccc2
506b81858446a8490e62d17596c6a5e508044177bbb0b398fe55e6e4183dcd330dced
4f9fc8db636f14fcb8213a95f79d32e3b4baec543189dcb0f2f1c8a92d406eabc4cc5
301a5f7dd05a0dcdcaffbb0f66ff5d6c862daf56940fbcd658bf738af27285c6bbe29
70439a52912cbe78a1462d1e34553e757809c4a4ea5467dc47b8272f5027f61363212
d8d23e29c6f4d5f701395ab5a67229291e8c6a24f34ace8c6ceeaf71b9f7c5e2f134e
97960bad15746462c35bddcf07bcd0871b0dd1ab40334f160d57d05772244df5be8b6
66add46870abc4579653df10c6e363ee38aa572fa4e31c3c569f1e636c27bcba4c806
3a0b0547c793acef5240602049aa19e4a3524e3382a803f215824e69bca890ec4d838
4582d5739ece314e346cf5b9ed59a252ba84edac83ff10af3b3531ce6d628f9215d7b
21c79001cd81c9cc42d9dd38c2c338c52062990a6858ec6eaee5352c4d35de8f7a6d0
d38ef7b556581bffe57a7ffcb47b62f74b4d5b9d2c2167bba8456326b6a6aaded31bd
6234e6accd4f65602f3cd31f8e4314bea25ff56876b1cc3f6884091c296285c6c6aa0
7ca143282b267064de7d15212388a9b1a8af395ec76f4e699d4e445666ff19c55fba0
ab02bb1cc0ce769c61f4e950c866796fc34d9adf50320f95256fd2bcd498683d1a923
c8155f1afa09a67ef5205bb4337da9b848a3855ca544470fde7426087f46e86584ece
d565cccb803e418c06f76e7fe5c85becf2b3cf2e6ee55bb00d367373619067c9379c0
3017c201a03ba783f183cc7f2d620aca9a58dc9bc0fa3a770859ea021a597a4938ea8
f098edbd3231a2eb9b05e13b4366567097c1bcdeeb4de7ff2f4935028eea7eeab3065
95dddae916057039cca50cf0ed1f392526979a8636aca9d6459536f014a21024fde3e
7d53690cb660f6baa8b93f37d054d59ec7c3d0420de912abbf33e018762ce1c1158e7
3420e520eba03c804cef703add7a9ec9cedcf200b8b8c8a37f7d25d5c60484a067106
aa6900857c6c68a2ec51241352bf9223947ddaa9273429dc5f624d6e6b82ae245e139
c91e3fb26c07e2a50122240401782b982fdabdba1d773d559c3429d68564c379d433e
fb54aa0548de8f115f69b2d6e93a7a9fbc8115e2f17ab2e67fd1583cbbdf71f03561e
2477af18d14d25fc47befc3b6f53dd980bd55cf1607e042d312d8b629101f4be66266
20e21326d1bfd832c1d54035ae1160d1bab5120e2b33b2e3f29e5a94e19dbfd02b7f9
675ae056dd58bf8d62ad8192280b71148e080091efa793b37be7614aec16d0203bf6f
fe68e9d0c33a93226c95758f85f974a5d44800e029380b510d30f20c34519114ad793
8a581d82dea7dc56e3e66d27ac03e6a1350c63043274be8ea4b5a0150d888804b37ec
5ad0ac43846cb4cac7ddfddeccca5ace739febdd9aa7c383d3c47d88f0bfaf43900a2
fd846e0dbdc9065923fe7c97566e112318e0b7acc4430c470cdeae0ce8dd03b74a08f
52b8a2a3dc72c945a00ac470c0934e1820
response:  0302cb4f4b3679b8d66ff3ca9d5c1c7571ab48f3741d69eb8aebccdc36
b1f680
key:  20a66324c9db64f2907bbe5171856e6c38f6575c431535a4c733a4f92d1698d
c
~~~

-->

<!--
# Acknowledgments
{:numbered="false"}

TODO acknowledge.
-->
