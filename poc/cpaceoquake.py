from random import randbytes
from typing import Any, Optional, Tuple
from drbg import UnsafeDRBG
from util import wrap_print, to_hex

from params import CPaceOQUAKEParameters, cpaceoquake_params_default
from cpace import cpace_init, cpace_respond, cpace_finish, run_CPace
from oquake import oquake_init, oquake_respond, oquake_finish, run_OQUAKE


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
