from typing import Any, Tuple

from deps import AuthenticationError, TH
from util import OS2IP, lv_encode, trace, xor


def GenVerifierMaterial(params, PRS: bytes, salt: bytes, U: bytes, S: bytes) -> Tuple[bytes, bytes]:
    material = params.KSF.Stretch(params.DST + lv_encode(PRS) + lv_encode(U) + lv_encode(S),
                                  salt, params.Nv + params.KEM.Nseed)
    v = material[0:params.Nv]
    seed = material[params.Nv:params.Nv + params.KEM.Nseed]
    trace("v", v)
    trace("seed", seed)
    return v, seed


def DeriveKEMSeed(params, seed: bytes, kem_blind: bytes) -> bytes:
    prk = params.KDF.Extract(seed, params.DST + b"KEMSeed" + kem_blind)
    return params.KDF.Expand(prk, params.DST + b"kem_seed", params.KEM.Nseed)


def GenVerifier(params, PRS: bytes, salt: bytes, U: bytes, S: bytes, rng) -> Tuple[bytes, bytes, bytes]:
    v, seed = GenVerifierMaterial(params, PRS, salt, U, S)
    kem_blind = rng.random_bytes(32, "kem_blind")
    (sk, pk) = params.KEM.DeriveKeyPair(DeriveKEMSeed(params, seed, kem_blind))
    trace("pk", pk)
    return v, pk, kem_blind


def encode_registration(salt: bytes, v: bytes, pk: bytes, kem_blind: bytes, U: bytes, S: bytes) -> bytes:
    return salt + v + pk + kem_blind + lv_encode(U) + lv_encode(S)


def decode_registration(params, reg_msg: bytes) -> Tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    Nv, Npk = params.Nv, params.KEM.Npk
    if len(reg_msg) < 64 + Nv + Npk:
        raise ValueError("registration message has an invalid length")
    salt = reg_msg[0:32]
    v = reg_msg[32:32 + Nv]
    pk = reg_msg[32 + Nv:32 + Nv + Npk]
    kem_blind = reg_msg[32 + Nv + Npk:64 + Nv + Npk]
    identifiers = []
    rest = reg_msg[64 + Nv + Npk:]
    for _ in range(2):
        if len(rest) < 2 or len(rest) < 2 + OS2IP(rest[0:2]):
            raise ValueError("registration message has an invalid length")
        L = OS2IP(rest[0:2])
        identifiers.append(rest[2:2 + L])
        rest = rest[2 + L:]
    if rest:
        raise ValueError("registration message has an invalid length")
    U, S = identifiers
    return salt, v, pk, kem_blind, U, S


def pwconf_challenge(params, SK: bytes, th: bytes, pk: bytes, kem_blind: bytes, rng) -> Tuple[Any, bytes]:
    (k, c) = params.KEM.Encaps(pk, rng)
    trace("pc_k", k)
    r = params.KDF.Expand(SK, params.DST + b"OTP", params.KEM.Nct + 32)
    enc_c = xor(c + kem_blind, r)

    prk_pc = params.KDF.Extract(SK, params.DST + b"PC" + th + enc_c + k)
    client_confirm = params.KDF.Expand(prk_pc, params.DST + b"client_confirm", params.Nkc)
    server_confirm = params.KDF.Expand(prk_pc, params.DST + b"server_confirm", params.Nkc)
    server_key = params.KDF.Expand(prk_pc, params.DST + b"key", params.Nkey)

    th_out = TH(params.KDF, params.DST, b"PC", th, enc_c, client_confirm, server_confirm)
    challenge = enc_c + client_confirm

    return (server_confirm, server_key, th_out), challenge


def pwconf_respond(params, SK: bytes, th: bytes, seed: bytes, challenge: bytes) -> Tuple[bytes, bytes, bytes]:
    Nct = params.KEM.Nct
    if len(challenge) != Nct + 32 + params.Nkc:
        raise ValueError("password confirmation challenge has an invalid length")
    (enc_c, client_confirm_target) = challenge[0:Nct + 32], challenge[Nct + 32:]

    r = params.KDF.Expand(SK, params.DST + b"OTP", Nct + 32)
    c_and_blind = xor(enc_c, r)
    c = c_and_blind[0:Nct]
    kem_blind = c_and_blind[Nct:Nct + 32]

    (sk, pk) = params.KEM.DeriveKeyPair(DeriveKEMSeed(params, seed, kem_blind))

    # The KEMs of the configurations use implicit rejection, so decapsulating a
    # ciphertext of the correct length does not fail.
    k = params.KEM.Decaps(c, sk)
    trace("pc_k", k)

    prk_pc = params.KDF.Extract(SK, params.DST + b"PC" + th + enc_c + k)
    client_confirm = params.KDF.Expand(prk_pc, params.DST + b"client_confirm", params.Nkc)
    if client_confirm != client_confirm_target:
        raise AuthenticationError()

    server_confirm = params.KDF.Expand(prk_pc, params.DST + b"server_confirm", params.Nkc)
    client_key = params.KDF.Expand(prk_pc, params.DST + b"key", params.Nkey)
    th_out = TH(params.KDF, params.DST, b"PC", th, enc_c, client_confirm, server_confirm)

    return client_key, server_confirm, th_out


def pwconf_verify(state: Any, server_confirm_target: bytes) -> Tuple[bytes, bytes]:
    (server_confirm, server_key, th_out) = state
    if server_confirm != server_confirm_target:
        raise AuthenticationError()
    return server_key, th_out
