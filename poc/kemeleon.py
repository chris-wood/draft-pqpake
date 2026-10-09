import math
import random
from typing import List, Optional, Sequence
import mlkem


N = 256
Q = 3329


def msb(k: int, x: int) -> bool:
    bitlength = math.ceil(Q * math.log2(k * N))
    return bool(x >> bitlength)


def VectorEncode(k: int, a: Sequence[int]) -> Optional[bytes]:
    r = 0
    for i in range(k * N):
        r += Q**i * a[i]
    
    if msb(k, r):
        return None
    
    byte_count = math.ceil(k * N * math.log2(Q) / 8)
    # FIXME: This leaves the top-most bits as 0
    return r.to_bytes(byte_count, 'little')


def VectorDecode(k: int, r: bytes) -> List[int]:
    r = int.from_bytes(r, byteorder='little')
    a = [None] * (k * N)
    for i in range(k * N):
        a[i] = r % Q
        r //= Q
    return a


def ByteDecodePK(b: int, x: bytes, params) -> List[int]:
    polys = mlkem.DecodeVec(x, params.k, b).ps
    poly_iter = iter(polys)
    elements = list(next(poly_iter).cs)
    for poly in poly_iter:
        elements.extend(list(poly.cs))
    return elements


def EncodePk(params, pk: bytes) -> Optional[bytes]:
    t = pk[:-32]
    rho = pk[-32:]
    t_zq = ByteDecodePK(12, t, params)
    r = VectorEncode(params.k, t_zq)

    if r is None:
        return None
    
    return r + rho


def ByteEncodePK(b: int, x: List[int], params) -> bytes:
    assert len(x) == 256 * params.k
    ps = [mlkem.Poly(x[i * 256:(i+1)*256]) for i in range(params.k)]
    return mlkem.EncodeVec(mlkem.Vec(ps), b)


def DecodePk(params, uniform_pk: bytes) -> bytes:
    r = uniform_pk[:-32]
    rho = uniform_pk[-32:]
    t_zq = VectorDecode(params.k, r)
    t = ByteEncodePK(12, t_zq, params)
    return t + rho


if __name__ == "__main__":
    for _ in range(100):
        while True:
            a = [random.randint(0, Q - 1) for _ in range(256)]
            a_uni = VectorEncode(1, a)
            if a_uni is not None:
                break
        assert a == VectorDecode(1, a_uni)

    for _ in range(100):
        while True:
            pk, sk = mlkem.KeyGen(random.randbytes(64), mlkem.params768)
            pk_uni = EncodePk(mlkem.params768, pk)
            if pk_uni is not None:
                break
        assert pk == DecodePk(mlkem.params768, pk_uni)
