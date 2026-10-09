from typing import Any, Optional, Tuple

from cpaceoquake import cpaceoquake_init, cpaceoquake_initiator_finish, cpaceoquake_respond, cpaceoquake_responder_finish
from drbg import UnsafeDRBG
from params import CPaceOQUAKEPlusParameters, PasswordConfirmationParameters, cpaceoquakeplus_params_default, pwconf_params_default
from util import to_hex, wrap_print, xor


VERIFIER_LENGTH = 32
SEED_LENGTH = 96
KC_LENGTH = 32


def GenVerifierMaterial(params: PasswordConfirmationParameters, PRS: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    verifier_seed = params.KSF.Stretch(PRS, salt, VERIFIER_LENGTH + SEED_LENGTH)
    verifier = verifier_seed[:VERIFIER_LENGTH]
    seed = verifier_seed[VERIFIER_LENGTH:]
    return verifier, seed


def GenVerifiers(params: PasswordConfirmationParameters, PRS: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    verifier, seed = GenVerifierMaterial(params, PRS, salt)
    pk, _ = params.KEM.DeriveKeyPair(seed)
    return verifier, pk


def pwconf_challenge(params: PasswordConfirmationParameters, SK: bytes, salt: bytes, pk: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[Tuple[bytes, bytes], bytes]:
    if SID is None:
        SID = b""
    if U is None:
        U = b""
    if S is None:
        S = b""
    
    c, k = params.KEM.Encaps(pk, seed)
    prk_kc = params.KDF.Extract(b"kc", SK + c + k + SID + U + S)
    h1 = params.KDF.Expand(prk_kc, b"h1", KC_LENGTH)
    h2 = params.KDF.Expand(prk_kc, b"h2", KC_LENGTH)
    server_key = params.KDF.Expand(prk_kc, b"vkey", 32)

    r = params.KDF.Expand(SK, b"OTP", params.KEM.C_LEN)
    challenge = xor(c, r) + h1

    return (h2, server_key), challenge


def pwconf_response(params: PasswordConfirmationParameters, SK: bytes, kem_seed: bytes, msg: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[bytes, bytes]:
    if U is None:
        U = b""
    if S is None:
        S = b""

    cr = msg[:-KC_LENGTH]
    h1 = msg[-KC_LENGTH:]
    
    r = params.KDF.Expand(SK, b"OTP", params.KEM.C_LEN)
    c = xor(cr, r)

    _, sk = params.KEM.DeriveKeyPair(kem_seed)
    k = params.KEM.Decaps(sk, c)
    prk_kc = params.KDF.Extract(b"kc", SK + c + k + SID + U + S)
    h1p = params.KDF.Expand(prk_kc, b"h1", KC_LENGTH)
    h2p = params.KDF.Expand(prk_kc, b"h2", KC_LENGTH)
    client_key = params.KDF.Expand(prk_kc, b"vkey", 32)

    if h1 != h1p:
        raise Exception("AuthenticationError")
    
    return client_key, h2p


def pwconf_verify(context: Tuple[bytes, bytes], msg: bytes) -> bytes:
    h2, server_key = context
    
    if h2 != msg:
        raise Exception("AuthenticationError")
    
    return server_key


def cpaceoquakeplus_init(params: CPaceOQUAKEPlusParameters, PRS: bytes, salt: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes]) -> Tuple[Any, bytes]:
    verifier, kem_seed = GenVerifierMaterial(params.pwconf_params, PRS, salt)
    ctx1, msg1 = cpaceoquake_init(params.cpaceoquake_params, verifier, SID, U, S)

    return (verifier, ctx1, kem_seed), msg1


def cpaceoquakeplus_respond(params: CPaceOQUAKEPlusParameters, verifier: bytes, msg: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[Any, bytes]:
    return cpaceoquake_respond(params.cpaceoquake_params, verifier, msg, SID, U, S, seed)


def cpaceoquakeplus_initiator_respond(params: CPaceOQUAKEPlusParameters, context: Any, msg: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[Any, bytes]:
    verifier, ctx1, kem_seed = context
    SK, msg3 = cpaceoquake_initiator_finish(params.cpaceoquake_params, verifier, ctx1, msg, SID, U, S, seed)

    return (SK, kem_seed), msg3


def cpaceoquakeplus_challenge(params: CPaceOQUAKEPlusParameters, context: Any, msg: bytes, salt: bytes, pk: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[Any, bytes]:
    SK = cpaceoquake_responder_finish(params.cpaceoquake_params, context, msg)
    return pwconf_challenge(params.pwconf_params, SK, salt, pk, SID, U, S, seed)


def cpaceoquakeplus_response(params: CPaceOQUAKEPlusParameters, context: Any, msg: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[bytes, bytes]:
    SK, kem_seed = context

    return pwconf_response(params.pwconf_params, SK, kem_seed, msg, SID, U, S, seed)


def cpaceoquakeplus_verify(context: Any, msg: bytes) -> bytes:
    return pwconf_verify(context, msg)


def run_CPaceOQUAKEPlus(rng: UnsafeDRBG):
    print("CPaceOQUAKE+")
    PRS = rng.random_bytes(16)
    SID = rng.random_bytes(16)
    U = rng.random_bytes(16)
    S = rng.random_bytes(16)
    server_respond_seed = rng.random_bytes(64)
    client_respond_seed = rng.random_bytes(32)
    challenge_seed = rng.random_bytes(64)
    response_seed = rng.random_bytes(64)

    # Registration
    salt = rng.random_bytes(32)
    verifier, pk = GenVerifiers(pwconf_params_default, PRS, salt)

    # Query
    (ctx1, init_msg) = cpaceoquakeplus_init(cpaceoquakeplus_params_default, PRS, salt, SID, U, S)
    (ctx2, resp_msg) = cpaceoquakeplus_respond(cpaceoquakeplus_params_default, verifier, init_msg, SID, U, S, server_respond_seed)
    (ctx3, finish_msg) = cpaceoquakeplus_initiator_respond(cpaceoquakeplus_params_default, ctx1, resp_msg, SID, U, S, client_respond_seed)
    (ctx4, challenge) = cpaceoquakeplus_challenge(cpaceoquakeplus_params_default, ctx2, finish_msg, salt, pk, SID, U, S, challenge_seed)
    (client_key, response) = cpaceoquakeplus_response(cpaceoquakeplus_params_default, ctx3, challenge, SID, U, S, response_seed)
    server_key = cpaceoquakeplus_verify(ctx4, response)

    assert client_key == server_key

    wrap_print("PRS:", to_hex(PRS))
    wrap_print("SID: ", to_hex(SID))
    wrap_print("U: ", to_hex(U))
    wrap_print("S: ", to_hex(S))
    wrap_print("salt: ", to_hex(salt))
    wrap_print("server_respond_seed: ", to_hex(server_respond_seed))
    wrap_print("client_respond_seed: ", to_hex(client_respond_seed))
    wrap_print("challenge_seed: ", to_hex(challenge_seed))
    wrap_print("response_seed: ", to_hex(response_seed))

    wrap_print("init_msg: ", to_hex(init_msg))
    wrap_print("resp_msg: ", to_hex(resp_msg))
    wrap_print("finish_msg: ", to_hex(finish_msg))
    wrap_print("challenge: ", to_hex(challenge))
    wrap_print("response: ", to_hex(response))
    wrap_print("key: ", to_hex(server_key))
    print()


if __name__ == "__main__":
    rng = UnsafeDRBG()
    run_CPaceOQUAKEPlus(rng)
