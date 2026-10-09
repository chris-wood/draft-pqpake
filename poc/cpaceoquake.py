from typing import Any, Tuple

from drbg import UnsafeDRBG
from util import EncodePublicContext, OS2IP, assert_raises, lv_decode, lv_encode, trace, wrap_print, to_hex
from cpace import cpace_init, cpace_respond, cpace_finish, run_CPace
from oquake import oquake_init, oquake_respond, oquake_finish, run_OQUAKE
from deps import CPaceError


def decode_cpaceoquake_resp(params, resp_msg: bytes) -> Tuple[bytes, bytes]:
    if len(resp_msg) < 2:
        raise ValueError("CPaceOQUAKE responder message has an invalid length")
    L = OS2IP(resp_msg[0:2])
    if L != params.cpace_params.G.field_size_bytes:
        raise ValueError("CPaceOQUAKE responder message has an invalid length")
    return resp_msg[2:2 + L], resp_msg[2 + L:]


def cpaceoquake_init(params, PRS: bytes, public_context: bytes, secret_context: bytes, rng) -> Tuple[Any, bytes]:
    ctx1, Ya = cpace_init(params.cpace_params, PRS, public_context, secret_context, rng)
    return ctx1, lv_encode(Ya)


def cpaceoquake_respond(params, PRS: bytes, public_context: bytes, secret_context: bytes, init_msg: bytes, rng) -> Tuple[Any, bytes]:
    Ya = lv_decode(init_msg)
    if len(Ya) != params.cpace_params.G.field_size_bytes:
        raise ValueError("CPaceOQUAKE initiator message has an invalid length")

    key1, Yb, th1 = cpace_respond(params.cpace_params, PRS, public_context, secret_context, Ya, rng)
    ctx2, oquake_init_msg = oquake_init(params.oquake_params, PRS, th1, key1, rng)

    resp_msg = lv_encode(Yb) + oquake_init_msg

    return (ctx2, key1), resp_msg


def cpaceoquake_initiator_finish(params, PRS: bytes, public_context: bytes, secret_context: bytes, state: Any, resp_msg: bytes, rng) -> Tuple[bytes, bytes, bytes]:
    ctx1 = state
    (Yb, oquake_init_msg) = decode_cpaceoquake_resp(params, resp_msg)

    key1, th1 = cpace_finish(params.cpace_params, ctx1, public_context, Yb)
    msg, key2, th2 = oquake_respond(params.oquake_params, PRS, th1, key1, oquake_init_msg, rng)

    prk = params.KDF.Extract(key2, params.DST + b"CPaceOQUAKE" + th2 + key1)
    client_key = params.KDF.Expand(prk, params.DST + b"key", params.Nkey)
    trace("cpaceoquake_key", client_key)

    return client_key, msg, th2


def cpaceoquake_responder_finish(params, state: Any, msg3: bytes, rng) -> Tuple[bytes, bytes]:
    (ctx2, key1) = state
    key2, th2 = oquake_finish(params.oquake_params, ctx2, msg3, rng)

    prk = params.KDF.Extract(key2, params.DST + b"CPaceOQUAKE" + th2 + key1)
    server_key = params.KDF.Expand(prk, params.DST + b"key", params.Nkey)
    trace("cpaceoquake_key", server_key)

    return server_key, th2


def run_CPaceOQUAKE(params, rng: UnsafeDRBG, sid):
    print("CPaceOQUAKE" if sid is not None else "CPaceOQUAKE - no sid")
    PRS = rng.random_bytes(16)
    public_context = EncodePublicContext(sid, rng.random_bytes(16), rng.random_bytes(16))
    secret_context = rng.random_bytes(16)

    client_state, init_msg = cpaceoquake_init(params, PRS, public_context, secret_context, rng)
    server_state, resp_msg = cpaceoquake_respond(params, PRS, public_context, secret_context, init_msg, rng)
    client_key, finish_msg, client_th = cpaceoquake_initiator_finish(params, PRS, public_context, secret_context, client_state, resp_msg, rng)
    server_key, server_th = cpaceoquake_responder_finish(params, server_state, finish_msg, rng)
    assert (client_key, client_th) == (server_key, server_th)

    wrap_print("PRS:", to_hex(PRS))
    wrap_print("public_context:", to_hex(public_context))
    wrap_print("secret_context:", to_hex(secret_context))
    wrap_print("init_msg:", to_hex(init_msg))
    wrap_print("resp_msg:", to_hex(resp_msg))
    wrap_print("finish_msg:", to_hex(finish_msg))
    wrap_print("key:", to_hex(server_key))
    wrap_print("th:", to_hex(server_th))
    print()


if __name__ == "__main__":
    from params import cpace_params_default, oquake_params_default, cpaceoquake_params_default as params

    rng = UnsafeDRBG()
    run_CPace(cpace_params_default, rng)
    run_OQUAKE(oquake_params_default, rng)
    run_CPaceOQUAKE(params, rng, rng.random_bytes(16))
    run_CPaceOQUAKE(params, rng, None)

    # With different passwords, both parties obtain unrelated keys.
    client_state, init_msg = cpaceoquake_init(params, b"password", b"", b"", rng)
    server_state, resp_msg = cpaceoquake_respond(params, b"other password", b"", b"", init_msg, rng)
    client_key, finish_msg, _ = cpaceoquake_initiator_finish(params, b"password", b"", b"", client_state, resp_msg, rng)
    server_key, _ = cpaceoquake_responder_finish(params, server_state, finish_msg, rng)
    assert client_key != server_key

    # Messages of the wrong length are rejected, and so is the neutral element as Ya or Yb.
    neutral = lv_encode(params.cpace_params.G.I)
    assert_raises(ValueError, cpaceoquake_respond, params, b"password", b"", b"", init_msg[:-1], rng)
    assert_raises(CPaceError, cpaceoquake_respond, params, b"password", b"", b"", neutral, rng)
    assert_raises(ValueError, cpaceoquake_initiator_finish, params, b"password", b"", b"", client_state, resp_msg[:-1], rng)
    assert_raises(CPaceError, cpaceoquake_initiator_finish, params, b"password", b"", b"", client_state,
                  neutral + resp_msg[len(neutral):], rng)
    assert_raises(ValueError, cpaceoquake_responder_finish, params, server_state, finish_msg + b"\x00", rng)
