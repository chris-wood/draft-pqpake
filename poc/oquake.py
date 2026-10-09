from typing import Any, Tuple

from drbg import UnsafeDRBG
from util import EncodePublicContext, assert_raises, lv_encode, trace, xor, wrap_print, to_hex
from deps import TH


def decode_oquake_init(params, init_msg: bytes) -> Tuple[bytes, bytes, bytes]:
    Nr, Nt, Nrho = params.Nr, params.BUA_sKEM.Nt, params.BUA_sKEM.Nrho
    if len(init_msg) != Nr + Nt + Nrho:
        raise ValueError("OQUAKE initiator message has an invalid length")
    return init_msg[0:Nr], init_msg[Nr:Nr + Nt], init_msg[Nr + Nt:Nr + Nt + Nrho]


def decode_oquake_resp(params, resp_msg: bytes) -> Tuple[bytes, bytes]:
    Nct = params.BUA_sKEM.Nct
    if len(resp_msg) != Nct + params.Nkc:
        raise ValueError("OQUAKE responder message has an invalid length")
    return resp_msg[0:Nct], resp_msg[Nct:]


def derive_effective_PRS(params, PRS: bytes, public_context: bytes, secret_context: bytes) -> bytes:
    prk_ePRS = params.KDF.Extract(PRS, params.DST + b"OQUAKE-context" +
                                  lv_encode(public_context) + lv_encode(secret_context))
    return params.KDF.Expand(prk_ePRS, params.DST + b"effective_PRS", params.Nkey)


def oquake_init(params, PRS: bytes, public_context: bytes, secret_context: bytes, rng) -> Tuple[Any, bytes]:
    effective_PRS = derive_effective_PRS(params, PRS, public_context, secret_context)

    (sk, pk) = params.BUA_sKEM.KeyGen(rng)
    (ut, rho) = params.BUA_sKEM.Split(pk)
    trace("oquake_upk", pk)

    r = rng.random_bytes(params.Nr, "oquake_r")

    # T = XOR(ut, H(public_context, effective_PRS, rho, r))
    prk_T_pad = params.KDF.Extract(effective_PRS, params.DST + b"OQUAKE" + lv_encode(public_context) + rho + r)
    T_pad = params.KDF.Expand(prk_T_pad, params.DST + b"T_pad", params.BUA_sKEM.Nt)
    T = xor(ut, T_pad)

    # s = XOR(r, H(public_context, effective_PRS, rho, T))
    prk_s_pad = params.KDF.Extract(effective_PRS, params.DST + b"OQUAKE" + lv_encode(public_context) + rho + T)
    s_pad = params.KDF.Expand(prk_s_pad, params.DST + b"s_pad", params.Nr)
    s = xor(r, s_pad)

    init_msg = s + T + rho

    return (effective_PRS, sk, pk, rho, s, T, public_context), init_msg


def oquake_respond(params, PRS: bytes, public_context: bytes, secret_context: bytes, init_msg: bytes, rng) -> Tuple[bytes, bytes, bytes]:
    (s, T, rho) = decode_oquake_init(params, init_msg)

    effective_PRS = derive_effective_PRS(params, PRS, public_context, secret_context)

    prk_s_pad = params.KDF.Extract(effective_PRS, params.DST + b"OQUAKE" + lv_encode(public_context) + rho + T)
    s_pad = params.KDF.Expand(prk_s_pad, params.DST + b"s_pad", params.Nr)
    r = xor(s, s_pad)

    prk_T_pad = params.KDF.Extract(effective_PRS, params.DST + b"OQUAKE" + lv_encode(public_context) + rho + r)
    T_pad = params.KDF.Expand(prk_T_pad, params.DST + b"T_pad", params.BUA_sKEM.Nt)
    ut = xor(T, T_pad)

    pk = params.BUA_sKEM.Combine(ut, rho)
    (k, ct) = params.BUA_sKEM.Encaps(pk, rng)

    prk_sk = params.KDF.Extract(effective_PRS, params.DST + b"OQUAKE" + lv_encode(public_context) +
                                s + T + pk + ct + k)
    h = params.KDF.Expand(prk_sk, params.DST + b"confirm", params.Nkc)
    key = params.KDF.Expand(prk_sk, params.DST + b"key", params.Nkey)

    resp_msg = ct + h
    th = TH(params.KDF, params.DST, b"OQUAKE", public_context, s, T, rho, ct, h)
    trace("oquake_k", k)
    trace("oquake_key", key)
    trace("oquake_th", th)

    return resp_msg, key, th


def oquake_finish(params, state: Any, resp_msg: bytes, rng) -> Tuple[bytes, bytes]:
    (effective_PRS, sk, pk, rho, s, T, public_context) = state
    (ct, h) = decode_oquake_resp(params, resp_msg)

    th = TH(params.KDF, params.DST, b"OQUAKE", public_context, s, T, rho, ct, h)

    # ML-BUA-sKEM uses implicit rejection, so decapsulating a ciphertext of the
    # correct length does not fail.
    k = params.BUA_sKEM.Decaps(ct, sk)
    trace("oquake_k", k)
    trace("oquake_th", th)

    prk_sk = params.KDF.Extract(effective_PRS, params.DST + b"OQUAKE" + lv_encode(public_context) +
                                s + T + pk + ct + k)
    h_expected = params.KDF.Expand(prk_sk, params.DST + b"confirm", params.Nkc)
    if h != h_expected:
        return rng.random_bytes(params.Nkey, "random_key"), th

    key = params.KDF.Expand(prk_sk, params.DST + b"key", params.Nkey)
    trace("oquake_key", key)
    return key, th


def run_OQUAKE(params, rng: UnsafeDRBG):
    print("OQUAKE")
    PRS = rng.random_bytes(16)
    public_context = EncodePublicContext(rng.random_bytes(16), rng.random_bytes(16), rng.random_bytes(16))
    secret_context = rng.random_bytes(16)

    state, init_msg = oquake_init(params, PRS, public_context, secret_context, rng)
    resp_msg, key_responder, th_responder = oquake_respond(params, PRS, public_context, secret_context, init_msg, rng)
    key_initiator, th_initiator = oquake_finish(params, state, resp_msg, rng)
    assert (key_initiator, th_initiator) == (key_responder, th_responder)

    wrap_print("PRS:", to_hex(PRS))
    wrap_print("public_context:", to_hex(public_context))
    wrap_print("secret_context:", to_hex(secret_context))
    wrap_print("init_msg:", to_hex(init_msg))
    wrap_print("resp_msg:", to_hex(resp_msg))
    wrap_print("key:", to_hex(key_responder))
    wrap_print("th:", to_hex(th_responder))
    print()


if __name__ == "__main__":
    from params import oquake_params_default as params

    rng = UnsafeDRBG()
    run_OQUAKE(params, rng)

    # With different passwords, both parties obtain unrelated keys, but the same transcript hash.
    state, init_msg = oquake_init(params, b"password", b"", b"", rng)
    resp_msg, key_responder, th_responder = oquake_respond(params, b"other password", b"", b"", init_msg, rng)
    key_initiator, th_initiator = oquake_finish(params, state, resp_msg, rng)
    assert key_initiator != key_responder and th_initiator == th_responder

    # Messages of the wrong length are rejected.
    assert_raises(ValueError, oquake_respond, params, b"password", b"", b"", init_msg[:-1], rng)
    assert_raises(ValueError, oquake_finish, params, state, resp_msg + b"\x00", rng)
