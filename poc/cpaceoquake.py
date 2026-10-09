#!/usr/local/bin/sage
# vim: syntax=python

from random import randbytes
from typing import Any, Optional, Tuple
from kemeleon import DecodePk, EncodePk
from util import xor
from drbg import UnsafeDRBG
from util import wrap_print, to_hex

from params import CPaceParameters, OQUAKEParameters, CPaceOQUAKEParameters, cpace_params_default, quake_params_default, cpaceoquake_params_default

#from sagelib.pcp import pcp_init, pcp_challenge, pcp_response, pcp_verify
from sagelib.RFC7748_X448_X25519 import *
from sagelib.CPace_string_utils import *
from sagelib.CPace_hashing import *
from sagelib.CPace_coffee import *
from sagelib.CPace_weierstrass import *
from sagelib.CPace_montgomery import *
from sagelib.test_vectors_X448_X25519 import *


# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-11#name-the-cpace-protocol
def cpace_init(params: CPaceParameters, PRS: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes]) -> Tuple[Any, bytes]:
    if U is None:
        U = b"Ainitiator"
    if S is None:
        S = b"Bresponder"
    if SID is None:
        SID = b""
    CI = (prepend_len(U) + prepend_len(S))
    g = params.G.calculate_generator(params.H, PRS, CI, SID, False)
    ya = params.G.sample_scalar(b"A")
    Ya = params.G.scalar_mult(ya, g)
    init_msg = Ya # network_encode(...)
    return (SID, ya, init_msg), init_msg


def cpace_respond(params: CPaceParameters, init_msg: bytes, PRS: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes]) -> Tuple[bytes, bytes]:
    if U is None:
        U = b"Ainitiator"
    if S is None:
        S = b"Bresponder"
    if SID is None:
        SID = b""
    CI = (prepend_len(U) + prepend_len(S))
    g = params.G.calculate_generator(params.H, PRS, CI, SID, False)
    yb = params.G.sample_scalar(b"B")
    Yb = params.G.scalar_mult(yb, g)
    resp_msg = Yb # network_encode(...)
    Ya = init_msg
    prk = params.G.scalar_mult_vfy(yb, Ya)

    concatenated_msg_transcript = o_cat(init_msg, resp_msg)
    ss_input = lv_cat(params.G.DSI_ISK, SID, prk) + concatenated_msg_transcript
    ss = params.H.hash(ss_input)

    return ss, resp_msg


def cpace_finish(params: CPaceParameters, context, resp_msg: bytes) -> bytes:
    (SID, ya, init_msg) = context
    Yb = resp_msg
    prk = params.G.scalar_mult_vfy(ya, Yb)
    
    concatenated_msg_transcript = o_cat(init_msg, resp_msg)
    ss_input = lv_cat(params.G.DSI_ISK, SID, prk) + concatenated_msg_transcript
    ss = params.H.hash(ss_input)

    return ss


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


def cpaceoquake_init(params: CPaceOQUAKEParameters, PRS: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes]) -> Tuple[Any, bytes]:
    ctx1, msg1 = cpace_init(params.cpace_params, PRS, SID, U, S)

    s1 = b""
    if SID is None:
        s1 = randbytes(32)

    return (ctx1, s1), msg1 + s1


def cpaceoquake_respond(params: CPaceOQUAKEParameters, PRS: bytes, init_msg: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[Any, bytes]:
    if SID is None:
        msg1 = init_msg[:-32]
        s1 = init_msg[-32:]
        s2 = randbytes(32)
        cpace_SID = None
        SID = params.KDF.Expand(s1 + s2, b"CPaceOQUAKE_sid", 32)
    else:
        cpace_SID = SID
        msg1 = init_msg
        s2 = b""
    
    key1, msg2 = cpace_respond(params.cpace_params, msg1, PRS, cpace_SID, U, S)
    ctx2, msg3 = oquake_init(params.quake_params, PRS + key1, SID, U, S, seed)

    return ctx2, msg2 + msg3 + s2


def cpaceoquake_initiator_finish(params: CPaceOQUAKEParameters, PRS: bytes, context: Tuple[Any, bytes], resp_msg: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[bytes, bytes]:
    ctx1, s1 = context

    msg2 = resp_msg[:1 + params.cpace_params.G.field_size_bytes * 2]
    key1 = cpace_finish(params.cpace_params, ctx1, msg2)

    if SID is None:
        msg3 = resp_msg[1 + params.cpace_params.G.field_size_bytes * 2:-32]
        s2 = resp_msg[-32:]
        SID = params.KDF.Expand(s1 + s2, b"CPaceOQUAKE_sid", 32)
    else:
        msg3 = resp_msg[1 + params.cpace_params.G.field_size_bytes * 2:]

    key2, msg4 = oquake_respond(params.quake_params, PRS + key1, SID, msg3, U, S, seed)
    return key2, msg4


def cpaceoquake_responder_finish(params: CPaceOQUAKEParameters, context, resp_msg):
    return oquake_finish(params.quake_params, context, resp_msg)


def run_CPace(rng: UnsafeDRBG):
    print("CPace")
    PRS = rng.random_bytes(16)
    SID = rng.random_bytes(16)
    U = rng.random_bytes(16)
    S = rng.random_bytes(16)
    ctx, init_msg = cpace_init(cpace_params_default, PRS, SID, U, S)
    ss_server, resp_msg = cpace_respond(cpace_params_default, init_msg, PRS, SID, U, S)
    ss_client = cpace_finish(cpace_params_default, ctx, resp_msg)
    assert ss_server == ss_client

    wrap_print("PRS:", to_hex(PRS))
    wrap_print("SID: ", to_hex(SID))
    wrap_print("U: ", to_hex(U))
    wrap_print("S: ", to_hex(S))
    wrap_print("init_msg: ", to_hex(init_msg))
    wrap_print("resp_msg: ", to_hex(resp_msg))
    wrap_print("key: ", to_hex(ss_server))
    print()


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


def run_CPaceOQUAKE_SID(rng: UnsafeDRBG):
    print("CPaceOQUAKE")
    PRS = rng.random_bytes(16)
    SID = rng.random_bytes(16)
    U = rng.random_bytes(16)
    S = rng.random_bytes(16)
    respond_seed = rng.random_bytes(64)
    client_respond_seed = rng.random_bytes(32)

    client_ctx, init_msg = cpaceoquake_init(cpaceoquake_params_default, PRS, SID, U, S)
    server_ctx, resp_msg = cpaceoquake_respond(cpaceoquake_params_default, PRS, init_msg, SID, U, S, respond_seed)
    client_key, client_finish_msg = cpaceoquake_initiator_finish(cpaceoquake_params_default, PRS, client_ctx, resp_msg, SID, U, S, client_respond_seed)
    server_key = cpaceoquake_responder_finish(cpaceoquake_params_default, server_ctx, client_finish_msg)
    assert server_key == client_key

    wrap_print("PRS:", to_hex(PRS))
    wrap_print("SID: ", to_hex(SID))
    wrap_print("U: ", to_hex(U))
    wrap_print("S: ", to_hex(S))
    wrap_print("respond_seed: ", to_hex(respond_seed))
    wrap_print("client_respond_seed: ", to_hex(client_respond_seed))
    wrap_print("init_msg: ", to_hex(init_msg))
    wrap_print("resp_msg: ", to_hex(resp_msg))
    wrap_print("finish_msg: ", to_hex(client_finish_msg))
    wrap_print("key: ", to_hex(server_key))
    print()


def run_CPaceOQUAKE_noSID(rng: UnsafeDRBG):
    print("CPaceOQUAKE - no sid")
    PRS = rng.random_bytes(16)
    SID = None
    U = rng.random_bytes(16)
    S = rng.random_bytes(16)
    respond_seed = rng.random_bytes(64)
    client_respond_seed = rng.random_bytes(32)

    client_ctx, init_msg = cpaceoquake_init(cpaceoquake_params_default, PRS, SID, U, S)
    server_ctx, resp_msg = cpaceoquake_respond(cpaceoquake_params_default, PRS, init_msg, SID, U, S, respond_seed)
    client_key, client_finish_msg = cpaceoquake_initiator_finish(cpaceoquake_params_default, PRS, client_ctx, resp_msg, SID, U, S, client_respond_seed)
    server_key = cpaceoquake_responder_finish(cpaceoquake_params_default, server_ctx, client_finish_msg)
    assert server_key == client_key

    wrap_print("PRS:", to_hex(PRS))
    wrap_print("U: ", to_hex(U))
    wrap_print("S: ", to_hex(S))
    wrap_print("respond_seed: ", to_hex(respond_seed))
    wrap_print("client_respond_seed: ", to_hex(client_respond_seed))
    wrap_print("init_msg: ", to_hex(init_msg))
    wrap_print("resp_msg: ", to_hex(resp_msg))
    wrap_print("finish_msg: ", to_hex(client_finish_msg))
    wrap_print("key: ", to_hex(server_key))
    print()


if __name__ == "__main__":
    rng = UnsafeDRBG()
    run_CPace(rng)
    run_OQUAKE(rng)
    run_CPaceOQUAKE_SID(rng)
    run_CPaceOQUAKE_noSID(rng)
