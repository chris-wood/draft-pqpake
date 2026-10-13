# Kemeleon encoding of ML-KEM encapsulation keys (EncodeEk and DecodeEk), as
# specified in draft-irtf-cfrg-kemeleon. Each encoded polynomial is serialized
# as a little-endian integer of (B + t) / 8 bytes.

from typing import List, Sequence

import mlkem


N = 256
Q = 3329
B = 2996  # ceil(N * log2(Q))
Q_POW_N = Q**N


def EncodedLength(t: int) -> int:
    assert (B + t) % 8 == 0
    return (B + t) // 8


def Accumulate(a: Sequence[int]) -> int:
    r = 0
    for coefficient in reversed(a):
        assert 0 <= coefficient < Q
        r = r * Q + coefficient
    return r


def MaxM(a: Sequence[int], t: int) -> int:
    # The largest value of m in VectorEncode: floor((2^(B+t) - 1 - r) / q^n)
    return (2**(B + t) - 1 - Accumulate(a)) // Q_POW_N


def VectorEncode(a: Sequence[int], t: int, m: int) -> int:
    assert 0 <= m <= MaxM(a, t)
    return Accumulate(a) + m * Q_POW_N


def VectorDecode(r: int) -> List[int]:
    r = r % Q_POW_N
    a = []
    for _ in range(N):
        a.append(r % Q)
        r //= Q
    return a


def EncodeEkDerand(ek: bytes, params, t: int, ms: Sequence[int]) -> bytes:
    """Kemeleon.EncodeEk, with the randomness m of each polynomial given as input."""
    t_hat = mlkem.DecodeVec(ek[:-32], params.k, 12)
    rho = ek[-32:]
    assert len(ms) == params.k
    rs = [VectorEncode(poly.cs, t, m) for poly, m in zip(t_hat.ps, ms)]
    return b"".join(r.to_bytes(EncodedLength(t), "little") for r in rs) + rho


def EncodeEk(ek: bytes, params, t: int, rng) -> bytes:
    t_hat = mlkem.DecodeVec(ek[:-32], params.k, 12)
    ms = [rng.random_integer(MaxM(poly.cs, t), "kemeleon_m") for poly in t_hat.ps]
    return EncodeEkDerand(ek, params, t, ms)


def DecodeEk(eek: bytes, params, t: int) -> bytes:
    length = EncodedLength(t)
    assert len(eek) == params.k * length + 32
    polys = [mlkem.Poly(VectorDecode(int.from_bytes(eek[i * length:(i + 1) * length], "little")))
             for i in range(params.k)]
    return mlkem.EncodeVec(mlkem.Vec(polys), 12) + eek[-32:]


if __name__ == "__main__":
    from drbg import UnsafeDRBG

    rng = UnsafeDRBG()
    t = 132
    for params in [mlkem.params768, mlkem.params1024]:
        for _ in range(10):
            ek, _ = mlkem.KeyGen(rng.random_bytes(64), params)
            eek = EncodeEk(ek, params, t, rng)
            assert len(eek) == params.k * 391 + 32
            assert DecodeEk(eek, params, t) == ek

            # The smallest and largest values of m also encode correctly.
            t_hat = mlkem.DecodeVec(ek[:-32], params.k, 12)
            for ms in [[0] * params.k, [MaxM(poly.cs, t) for poly in t_hat.ps]]:
                assert DecodeEk(EncodeEkDerand(ek, params, t, ms), params, t) == ek

            # Every byte string of the right length decodes to a valid encapsulation key.
            ek_any = DecodeEk(rng.random_bytes(len(eek)), params, t)
            mlkem.Enc(ek_any, rng.random_bytes(32), params)
