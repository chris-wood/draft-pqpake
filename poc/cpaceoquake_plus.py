from typing import Any, Tuple

from cpaceoquake import cpaceoquake_init, cpaceoquake_initiator_finish, cpaceoquake_respond, cpaceoquake_responder_finish
from deps import AuthenticationError
from drbg import UnsafeDRBG
from pwconf import GenVerifier, GenVerifierMaterial, encode_registration, pwconf_challenge, pwconf_respond, pwconf_verify
from util import EncodePublicContext, to_hex, wrap_print


def cpaceoquakeplus_init(params, PRS: bytes, salt: bytes, U: bytes, S: bytes, public_context: bytes, secret_context: bytes, rng) -> Tuple[Any, bytes]:
    (v, seed) = GenVerifierMaterial(params.pwconf_params, PRS, salt, U, S)
    ctx, msg = cpaceoquake_init(params.cpaceoquake_params, v, public_context, secret_context, rng)
    return (ctx, v, seed, public_context, secret_context), msg


def cpaceoquakeplus_respond(params, v: bytes, public_context: bytes, secret_context: bytes, init_msg: bytes, rng) -> Tuple[Any, bytes]:
    ctx, msg = cpaceoquake_respond(params.cpaceoquake_params, v, public_context, secret_context, init_msg, rng)
    return ctx, msg


def cpaceoquakeplus_initiator_continue(params, state: Any, msg2: bytes, rng) -> Tuple[Any, bytes]:
    (ctx, v, seed, public_context, secret_context) = state
    SK, msg, th = cpaceoquake_initiator_finish(params.cpaceoquake_params, v, public_context, secret_context, ctx, msg2, rng)
    return (SK, th, seed), msg


def cpaceoquakeplus_responder_continue(params, state: Any, msg3: bytes, pk: bytes, kem_blind: bytes, rng) -> Tuple[Any, bytes]:
    SK, th = cpaceoquake_responder_finish(params.cpaceoquake_params, state, msg3, rng)
    return pwconf_challenge(params.pwconf_params, SK, th, pk, kem_blind, rng)


def cpaceoquakeplus_initiator_finish(params, state: Any, msg4: bytes) -> Tuple[bytes, bytes, bytes]:
    (SK, th, seed) = state
    return pwconf_respond(params.pwconf_params, SK, th, seed, msg4)


def cpaceoquakeplus_responder_finish(state: Any, msg5: bytes) -> Tuple[bytes, bytes]:
    return pwconf_verify(state, msg5)


def run_CPaceOQUAKEPlus(params, rng: UnsafeDRBG):
    print("CPaceOQUAKE+")
    PRS = rng.random_bytes(16)
    U = rng.random_bytes(16)
    S = rng.random_bytes(16)
    public_context = EncodePublicContext(rng.random_bytes(16), U, S)
    secret_context = rng.random_bytes(16)

    # Registration
    salt = rng.random_bytes(32)
    v, pk, kem_blind = GenVerifier(params.pwconf_params, PRS, salt, U, S, rng)
    reg_msg = encode_registration(salt, v, pk, kem_blind, U, S)

    # Online phase
    client_state, msg1 = cpaceoquakeplus_init(params, PRS, salt, U, S, public_context, secret_context, rng)
    server_state, msg2 = cpaceoquakeplus_respond(params, v, public_context, secret_context, msg1, rng)
    client_state, msg3 = cpaceoquakeplus_initiator_continue(params, client_state, msg2, rng)
    server_state, msg4 = cpaceoquakeplus_responder_continue(params, server_state, msg3, pk, kem_blind, rng)
    client_key, msg5, client_th = cpaceoquakeplus_initiator_finish(params, client_state, msg4)
    server_key, server_th = cpaceoquakeplus_responder_finish(server_state, msg5)
    assert (client_key, client_th) == (server_key, server_th)

    wrap_print("PRS:", to_hex(PRS))
    wrap_print("U:", to_hex(U))
    wrap_print("S:", to_hex(S))
    wrap_print("public_context:", to_hex(public_context))
    wrap_print("secret_context:", to_hex(secret_context))
    wrap_print("reg_msg:", to_hex(reg_msg))
    wrap_print("msg1:", to_hex(msg1))
    wrap_print("msg2:", to_hex(msg2))
    wrap_print("msg3:", to_hex(msg3))
    wrap_print("msg4:", to_hex(msg4))
    wrap_print("msg5:", to_hex(msg5))
    wrap_print("key:", to_hex(server_key))
    wrap_print("th:", to_hex(server_th))
    print()


if __name__ == "__main__":
    from params import cpaceoquakeplus_params_default as params

    rng = UnsafeDRBG()
    run_CPaceOQUAKEPlus(params, rng)

    salt = rng.random_bytes(32)
    v, pk, kem_blind = GenVerifier(params.pwconf_params, b"password", salt, b"U", b"S", rng)

    # A client with the wrong password fails password confirmation.
    client_state, msg1 = cpaceoquakeplus_init(params, b"other password", salt, b"U", b"S", b"", b"", rng)
    server_state, msg2 = cpaceoquakeplus_respond(params, v, b"", b"", msg1, rng)
    client_state, msg3 = cpaceoquakeplus_initiator_continue(params, client_state, msg2, rng)
    server_state, msg4 = cpaceoquakeplus_responder_continue(params, server_state, msg3, pk, kem_blind, rng)
    try:
        cpaceoquakeplus_initiator_finish(params, client_state, msg4)
        assert False
    except AuthenticationError:
        pass

    # The server rejects an incorrect confirmation value.
    client_state, msg1 = cpaceoquakeplus_init(params, b"password", salt, b"U", b"S", b"", b"", rng)
    server_state, msg2 = cpaceoquakeplus_respond(params, v, b"", b"", msg1, rng)
    client_state, msg3 = cpaceoquakeplus_initiator_continue(params, client_state, msg2, rng)
    server_state, msg4 = cpaceoquakeplus_responder_continue(params, server_state, msg3, pk, kem_blind, rng)
    _, msg5, _ = cpaceoquakeplus_initiator_finish(params, client_state, msg4)
    try:
        cpaceoquakeplus_responder_finish(server_state, bytes(len(msg5)))
        assert False
    except AuthenticationError:
        pass
