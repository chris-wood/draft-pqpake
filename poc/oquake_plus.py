from typing import Any, Tuple

from deps import AuthenticationError
from drbg import UnsafeDRBG
from oquake import oquake_init, oquake_respond, oquake_finish
from pwconf import GenVerifier, GenVerifierMaterial, pwconf_challenge, pwconf_respond, pwconf_verify
from util import EncodePublicContext, assert_raises, wrap_print, to_hex


def oquakeplus_init(params, PRS: bytes, salt: bytes, U: bytes, S: bytes, public_context: bytes, secret_context: bytes, rng) -> Tuple[Any, bytes]:
    (v, seed) = GenVerifierMaterial(params.pwconf_params, PRS, salt, U, S)
    ctx, msg = oquake_init(params.oquake_params, v, public_context, secret_context, rng)
    return (ctx, seed), msg


def oquakeplus_respond(params, v: bytes, public_context: bytes, secret_context: bytes, init_msg: bytes, pk: bytes, kem_blind: bytes, rng) -> Tuple[Any, bytes]:
    oquake_resp, SK, th = oquake_respond(params.oquake_params, v, public_context, secret_context, init_msg, rng)
    state, challenge = pwconf_challenge(params.pwconf_params, SK, th, pk, kem_blind, rng)
    resp_msg = oquake_resp + challenge
    return state, resp_msg


def oquakeplus_finish(params, state: Any, resp_msg: bytes, rng) -> Tuple[bytes, bytes, bytes]:
    (ctx, seed) = state
    N = params.oquake_params.BUA_sKEM.Nct + params.oquake_params.Nkc
    (oquake_resp, challenge) = resp_msg[0:N], resp_msg[N:]

    SK, th = oquake_finish(params.oquake_params, ctx, oquake_resp, rng)

    return pwconf_respond(params.pwconf_params, SK, th, seed, challenge)


def oquakeplus_verify(state: Any, response: bytes) -> Tuple[bytes, bytes]:
    return pwconf_verify(state, response)


def run_OQUAKEPlus(params, rng: UnsafeDRBG):
    print("OQUAKE+")
    PRS = rng.random_bytes(16)
    U = rng.random_bytes(16)
    S = rng.random_bytes(16)
    public_context = EncodePublicContext(rng.random_bytes(16), U, S)
    secret_context = rng.random_bytes(16)

    # Registration
    salt = rng.random_bytes(32)
    v, pk, kem_blind = GenVerifier(params.pwconf_params, PRS, salt, U, S, rng)

    # Online phase
    client_state, init_msg = oquakeplus_init(params, PRS, salt, U, S, public_context, secret_context, rng)
    server_state, resp_msg = oquakeplus_respond(params, v, public_context, secret_context, init_msg, pk, kem_blind, rng)
    client_key, response, client_th = oquakeplus_finish(params, client_state, resp_msg, rng)
    server_key, server_th = oquakeplus_verify(server_state, response)
    assert (client_key, client_th) == (server_key, server_th)

    wrap_print("PRS:", to_hex(PRS))
    wrap_print("U:", to_hex(U))
    wrap_print("S:", to_hex(S))
    wrap_print("public_context:", to_hex(public_context))
    wrap_print("secret_context:", to_hex(secret_context))
    wrap_print("salt:", to_hex(salt))
    wrap_print("init_msg:", to_hex(init_msg))
    wrap_print("resp_msg:", to_hex(resp_msg))
    wrap_print("response:", to_hex(response))
    wrap_print("key:", to_hex(server_key))
    wrap_print("th:", to_hex(server_th))
    print()


if __name__ == "__main__":
    from params import oquakeplus_params_default as params

    rng = UnsafeDRBG()
    run_OQUAKEPlus(params, rng)

    salt = rng.random_bytes(32)
    v, pk, kem_blind = GenVerifier(params.pwconf_params, b"password", salt, b"U", b"S", rng)

    # A client with the wrong password fails password confirmation.
    client_state, init_msg = oquakeplus_init(params, b"other password", salt, b"U", b"S", b"", b"", rng)
    server_state, resp_msg = oquakeplus_respond(params, v, b"", b"", init_msg, pk, kem_blind, rng)
    assert_raises(AuthenticationError, oquakeplus_finish, params, client_state, resp_msg, rng)

    # The server rejects an incorrect confirmation value.
    client_state, init_msg = oquakeplus_init(params, b"password", salt, b"U", b"S", b"", b"", rng)
    server_state, resp_msg = oquakeplus_respond(params, v, b"", b"", init_msg, pk, kem_blind, rng)
    _, response, _ = oquakeplus_finish(params, client_state, resp_msg, rng)
    assert_raises(AuthenticationError, oquakeplus_verify, server_state, bytes(len(response)))

    # A challenge of the wrong length is rejected.
    client_state, init_msg = oquakeplus_init(params, b"password", salt, b"U", b"S", b"", b"", rng)
    server_state, resp_msg = oquakeplus_respond(params, v, b"", b"", init_msg, pk, kem_blind, rng)
    assert_raises(ValueError, oquakeplus_finish, params, client_state, resp_msg[:-1], rng)
