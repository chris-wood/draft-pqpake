#!/usr/local/bin/sage
# vim: syntax=python

from random import randbytes
from typing import Any, Optional, Tuple
from kemeleon import DecodePk, EncodePk
from util import xor
from drbg import UnsafeDRBG
from util import wrap_print, to_hex

from params import OQUAKEParameters, quake_params_default


def oquake_init(params: OQUAKEParameters, PRS: bytes, SID: bytes, U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[Any, bytes]:
    while True:
        pk, sk = params.mlkem.KeyGen()
        uniform_pk = EncodePk(params.mlkem.params(), pk)
        if uniform_pk is not None:
            break

    r = randbytes(params.Nrandomness)

    prk_T = params.KDF.Extract(b"OQUAKE", PRS + SID + r)
    T = xor(uniform_pk, params.KDF.Expand(prk_T, b"T", params.NpkUni))

    prk_s = params.KDF.Extract(b"OQUAKE", PRS + SID + T)
    s = xor(r, params.KDF.Expand(prk_s, b"s", params.Nrandomness))
    init_msg = s + T

    if U is None:
        U = b""
    if S is None:
        S = b""
    prk_tx = params.KDF.Extract(b"OQUAKE", SID + init_msg + PRS + U + S)

    return (sk, prk_tx), init_msg


def oquake_respond(params: OQUAKEParameters, PRS: bytes, SID: bytes, init_msg: bytes, U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[bytes, bytes]:
    s = init_msg[0:params.Nrandomness]
    T = init_msg[params.Nrandomness:params.Nrandomness+params.NpkUni]

    prk_s = params.KDF.Extract(b"OQUAKE", PRS + SID + T)
    r = xor(s, params.KDF.Expand(prk_s, b"s", params.Nrandomness))

    prk_T = params.KDF.Extract(b"OQUAKE", PRS + SID + r)
    uniform_pk = xor(T, params.KDF.Expand(prk_T, b"T", params.NpkUni))
    pk = DecodePk(params.mlkem.params(), uniform_pk)
    
    (ct, k) = params.mlkem.Encaps(pk, seed)

    if U is None:
        U = b""
    if S is None:
        S = b""
    prk_tx = params.KDF.Extract(b"OQUAKE", SID + init_msg + PRS + U + S)
    prk_key = params.KDF.Extract(b"OQUAKE", prk_tx + ct + k)
    key = params.KDF.Expand(prk_key, b"key", 32)
    h = params.KDF.Expand(prk_key, b"h", 24)

    resp_msg = ct + h
    return key, resp_msg


def oquake_finish(params: OQUAKEParameters, context, resp_msg: bytes) -> bytes:
    (sk, prk_tx) = context

    ct = resp_msg[0:-24]
    h = resp_msg[-24:]
    k = params.mlkem.Decaps(sk, ct)

    prk_key = params.KDF.Extract(b"OQUAKE", prk_tx + ct + k)
    key = params.KDF.Expand(prk_key, b"key", 32)
    hp = params.KDF.Expand(prk_key, b"h", 24)

    if h != hp:
        raise Exception("AuthenticationError")

    return key


def run_OQUAKE(rng: UnsafeDRBG):
    print("OQUAKE")
    PRS = rng.random_bytes(16)
    SID = rng.random_bytes(16)
    U = rng.random_bytes(16)
    S = rng.random_bytes(16)
    init_seed = rng.random_bytes(64)
    respond_seed = rng.random_bytes(32)

    ctx, init_msg = oquake_init(quake_params_default, PRS, SID, U, S, init_seed)
    ss_server, resp_msg = oquake_respond(quake_params_default, PRS, SID, init_msg, U, S, respond_seed)
    ss_client = oquake_finish(quake_params_default, ctx, resp_msg)
    assert ss_server == ss_client

    wrap_print("PRS:", to_hex(PRS))
    wrap_print("SID: ", to_hex(SID))
    wrap_print("U: ", to_hex(U))
    wrap_print("S: ", to_hex(S))
    wrap_print("init_msg: ", to_hex(init_msg))
    wrap_print("resp_msg: ", to_hex(resp_msg))
    wrap_print("key: ", to_hex(ss_server))
    print()


if __name__ == "__main__":
    rng = UnsafeDRBG()
    run_OQUAKE(rng)
