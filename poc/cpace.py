#!/usr/local/bin/sage
# vim: syntax=python

from typing import Any, Optional, Tuple
from drbg import UnsafeDRBG
from util import wrap_print, to_hex

from params import CPaceParameters, cpace_params_default

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


if __name__ == "__main__":
    rng = UnsafeDRBG()
    run_CPace(rng)
