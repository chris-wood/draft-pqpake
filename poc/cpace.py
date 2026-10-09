# CPace with the group environment G_X25519 and hash function SHA-512, as
# specified in draft-irtf-cfrg-cpace, and the CPace wrapper of this document.

import hashlib
from typing import Any, Tuple

import x25519
from deps import TH, CPaceError
from drbg import UnsafeDRBG
from util import assert_raises, trace, wrap_print, to_hex


# String utility functions of draft-irtf-cfrg-cpace

def prepend_len(data):
    "prepend LEB128 encoding of length"
    length = len(data)
    length_encoded = b""
    while True:
        if length < 128:
            length_encoded += bytes([length])
        else:
            length_encoded += bytes([(length & 0x7f) + 0x80])
        length = int(length >> 7)
        if length == 0:
            break
    return length_encoded + data


def lv_cat(*args):
    result = b""
    for arg in args:
        result += prepend_len(arg)
    return result


def zero_bytes(n):
    return bytes(n)


def generator_string(DSI, PRS, CI, sid, s_in_bytes):
    # Concat all input fields with prepended length information.
    # Add zero padding in the first hash block after DSI and PRS.
    len_zpad = max(0, s_in_bytes - 1 - len(prepend_len(PRS))
                      - len(prepend_len(DSI)))
    return lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)


def transcript_ir(Ya, ADa, Yb, ADb):
    result = lv_cat(Ya, ADa) + lv_cat(Yb, ADb)
    return result


class H_SHA512:

    def __init__(self):
        self.b_in_bytes = 64
        self.bmax_in_bytes = 64
        self.s_in_bytes = 128

    def hash(self, m: bytes, l: int = None) -> bytes:
        if l is None:
            l = self.b_in_bytes
        assert l <= self.bmax_in_bytes
        return hashlib.sha512(m).digest()[:l]


# Curve25519 in Montgomery form, and the non-square Z for Elligator 2
P = 2**255 - 19
A = 486662
Z = 2


def decodeUCoordinate(u: bytes, bits: int) -> int:
    u_list = list(u)
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1 << (bits % 8)) - 1
    return sum(u_list[i] << 8 * i for i in range((bits + 7) // 8))


def encodeUCoordinate(u: int, bits: int) -> bytes:
    return bytes((u >> 8 * i) & 0xff for i in range((bits + 7) // 8))


def elligator2(r: int) -> int:
    # Maps a field element r to the u-coordinate of a point on Curve25519 (B = 1).
    v = (-A * pow(1 + Z * r * r, -1, P)) % P
    epsilon = pow(v**3 + A * v**2 + v, (P - 1) // 2, P)
    return (epsilon * v - (1 - epsilon) * A * pow(2, -1, P)) % P


class G_X25519:

    def __init__(self):
        self.field_size_bytes = 32
        self.field_size_bits = 255
        self.I = zero_bytes(self.field_size_bytes)
        self.DSI = b"CPace255"

    def calculate_generator(self, H, PRS: bytes, CI: bytes, sid: bytes) -> bytes:
        gen_str = generator_string(self.DSI, PRS, CI, sid, H.s_in_bytes)
        gen_str_hash = H.hash(gen_str, self.field_size_bytes)
        u = decodeUCoordinate(gen_str_hash, self.field_size_bits)
        return encodeUCoordinate(elligator2(u), self.field_size_bits)

    def sample_scalar(self, rng, label: str) -> bytes:
        return rng.random_bytes(self.field_size_bytes, label)

    def scalar_mult(self, y: bytes, g: bytes) -> bytes:
        return x25519.X(y, g)

    def scalar_mult_vfy(self, y: bytes, g: bytes) -> bytes:
        return x25519.X(y, g)


def cpace_init(params, PRS: bytes, public_context: bytes, secret_context: bytes, rng) -> Tuple[Any, bytes]:
    g = params.G.calculate_generator(params.H, PRS, secret_context, public_context)
    ya = params.G.sample_scalar(rng, "cpace_ya")
    Ya = params.G.scalar_mult(ya, g)
    return (ya, Ya), Ya


def cpace_respond(params, PRS: bytes, public_context: bytes, secret_context: bytes, Ya: bytes, rng) -> Tuple[bytes, bytes, bytes]:
    g = params.G.calculate_generator(params.H, PRS, secret_context, public_context)
    yb = params.G.sample_scalar(rng, "cpace_yb")
    Yb = params.G.scalar_mult(yb, g)

    K = params.G.scalar_mult_vfy(yb, Ya)
    if K == params.G.I:
        raise CPaceError()

    ISK = params.H.hash(lv_cat(params.G.DSI + b"_ISK", public_context, K) + transcript_ir(Ya, b"", Yb, b""))
    th = TH(params.KDF, params.DST, b"CPace", public_context, Ya, Yb)
    trace("cpace_ISK", ISK)
    trace("cpace_th", th)

    return ISK, Yb, th


def cpace_finish(params, state: Any, public_context: bytes, Yb: bytes) -> Tuple[bytes, bytes]:
    (ya, Ya) = state

    K = params.G.scalar_mult_vfy(ya, Yb)
    if K == params.G.I:
        raise CPaceError()

    ISK = params.H.hash(lv_cat(params.G.DSI + b"_ISK", public_context, K) + transcript_ir(Ya, b"", Yb, b""))
    th = TH(params.KDF, params.DST, b"CPace", public_context, Ya, Yb)
    trace("cpace_ISK", ISK)
    trace("cpace_th", th)

    return ISK, th


def run_CPace(params, rng: UnsafeDRBG):
    print("CPace")
    PRS = rng.random_bytes(16)
    public_context = rng.random_bytes(16)
    secret_context = rng.random_bytes(16)
    state, Ya = cpace_init(params, PRS, public_context, secret_context, rng)
    ISK_responder, Yb, th_responder = cpace_respond(params, PRS, public_context, secret_context, Ya, rng)
    ISK_initiator, th_initiator = cpace_finish(params, state, public_context, Yb)
    assert (ISK_initiator, th_initiator) == (ISK_responder, th_responder)

    wrap_print("PRS:", to_hex(PRS))
    wrap_print("public_context:", to_hex(public_context))
    wrap_print("secret_context:", to_hex(secret_context))
    wrap_print("Ya:", to_hex(Ya))
    wrap_print("Yb:", to_hex(Yb))
    wrap_print("ISK:", to_hex(ISK_responder))
    wrap_print("th:", to_hex(th_responder))
    print()


if __name__ == "__main__":
    from params import cpace_params_default

    rng = UnsafeDRBG()
    run_CPace(cpace_params_default, rng)

    # A point that yields the neutral element makes either party abort.
    params = cpace_params_default
    assert_raises(CPaceError, cpace_respond, params, b"PRS", b"", b"", params.G.I, rng)
    state, Ya = cpace_init(params, b"PRS", b"", b"", rng)
    assert_raises(CPaceError, cpace_finish, params, state, b"", params.G.I)
