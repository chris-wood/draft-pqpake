import json
import os
from random import randint, randbytes
from typing import List, Sequence, Tuple

import mlkem
from deps import BUKEM
from mlkem import params768
from util import to_hex, wrap_print


T = 256
Q = 3329

M = 20583747174217604960599309727511997353078881862543197050652779655391418
MASK = 224
INT_BYTES = 404

COMPLEMENT_MASK = 255 ^ MASK

NPK_SEQS = 3

R = 64

NC_SEQS = 4


def random(byte_count: int) -> bytes:
    return randbytes(byte_count)


def random_integer_uniform(lo_incl: int, hi_excl: int) -> int:
    return randint(lo_incl, hi_excl - 1)


def to_bytes_little_endian(y: int, byte_count: int) -> bytearray:
    return bytearray(y.to_bytes(byte_count, 'little'))


# TODO: Make separate functions for pk and c that take N and Q_POW_N as inputs, and maybe assert lengths
def ByteEncodeUniform(x: Sequence[int], N: int) -> bytes:
    ys = bytearray()

    for i in range(N):
        a = 0
        for j in reversed(range(1, T)):
            a += x[i * T + j]
            a *= Q
        a += x[i * T]

        f = random_integer_uniform(0, M + 1)
        y = f * pow(Q, T) + a

        y = to_bytes_little_endian(y, INT_BYTES)
        b = random(1)[0] & MASK
        y[-1] |= b

        ys += y
    
    return bytes(ys)


def split_into_parts(ys: bytes, N: int) -> List[bytearray]:
    assert len(ys) % N == 0
    block_size = len(ys) // N
    return [bytearray(ys[i * block_size:(i + 1) * block_size]) for i in range(N)]


def div_mod(y: int, q: int) -> Tuple[int, int]:
    return y // q, y % q


def from_bytes_little_endian(bs: bytes) -> int:
    return int.from_bytes(bs, byteorder='little')


def ByteDecodeUniform(ys: bytes, N: int) -> bytes:
    ys_parts = split_into_parts(ys, N)
    x = [None for _ in range(N * T)]

    for i in range(N):
        y = ys_parts[i]
        y[-1] &= COMPLEMENT_MASK
        y = from_bytes_little_endian(y)
        for j in range(T):
            (y, x[i * T + j]) = div_mod(y, Q)
        
    return x


def SplitXRho(pk: bytes) -> Tuple[bytes, bytes]:
    return pk[:-32], pk[-32:]


def ByteDecodePK(b: int, x: bytes, params) -> List[int]:
    polys = mlkem.DecodeVec(x, params.k, b).ps
    poly_iter = iter(polys)
    elements = list(next(poly_iter).cs)
    for poly in poly_iter:
        elements.extend(list(poly.cs))
    return elements


def DeriveKeyPair(seed: bytes, params):
    assert len(seed) == 64
    (pk, sk) = mlkem.KeyGen(seed, params)
    (x, rho) = SplitXRho(pk)
    t = ByteDecodePK(12, x, params)
    pk_uniform = ByteEncodeUniform(t, NPK_SEQS) + rho
    return pk_uniform, sk


def DecompressUniform(d: int, y: int) -> int:
    l = (y * Q - (Q >> 1 + 1) + (1 << d)) >> d
    h = (y * Q + (Q >> 1)) >> d
    mod = h + 1 - l
    r = random_integer_uniform(0, 1 << (8 * R))
    return l + (r % mod)


def ByteEncodePK(b: int, x: List[int], params) -> bytes:
    assert len(x) == 256 * params.k
    ps = [mlkem.Poly(x[i * 256:(i+1)*256]) for i in range(params.k)]
    return mlkem.EncodeVec(mlkem.Vec(ps), b)


def SplitC1C2(c: bytes, params) -> Tuple[bytes, bytes]:
    split = params.du * params.k * 256 // 8
    c1, c2 = c[:split], c[split:]
    return c1, c2


def ByteDecodeC1(c1: bytes, params) -> List[int]:
    # TODO: Reduce duplication
    polys = mlkem.DecodeVec(c1, params.k, params.du).ps
    poly_iter = iter(polys)
    elements = list(next(poly_iter).cs)
    for poly in poly_iter:
        elements.extend(list(poly.cs))
    return elements


def ByteDecodeC2(c2: bytes, params) -> List[int]:
    poly = mlkem.DecodePoly(c2, params.dv)
    return list(poly.cs)


def Encaps(pk_uniform: bytes, seed: bytes, params) -> Tuple[bytes, bytes]:
    assert len(seed) == 32
    (x, rho) = SplitXRho(pk_uniform)
    pk = ByteEncodePK(12, ByteDecodeUniform(x, NPK_SEQS), params)
    (c, k) = mlkem.Enc(pk + rho, seed, params)
    (c1, c2) = SplitC1C2(c, params)

    u_uniform = [DecompressUniform(params.du, element) for element in ByteDecodeC1(c1, params)]
    v_uniform = [DecompressUniform(params.dv, element) for element in ByteDecodeC2(c2, params)]
    c_uniform = ByteEncodeUniform(u_uniform + v_uniform, NC_SEQS)

    return c_uniform, k


def SplitUV(c_elements: List[int], params) -> Tuple[mlkem.Vec, mlkem.Vec]:
    u_elements = mlkem.Vec((mlkem.Poly(c_elements[i * 256:(i + 1) * 256]) for i in range(params.k)))
    v_elements = mlkem.Vec((mlkem.Poly(c_elements[params.k * 256:(params.k + 1) * 256]),))
    return u_elements, v_elements


def Decaps(sk: bytes, c_uniform: bytes, params) -> bytes:
    u_uniform, v_uniform = SplitUV(ByteDecodeUniform(c_uniform, NC_SEQS), params)
    u_uniform.Compress(params.du)
    c1 = u_uniform.Compress(params.du).Encode(params.du)
    c2 = v_uniform.Compress(params.dv).Encode(params.dv)
    return mlkem.Dec(sk, c1 + c2, params)


class MLBUKEM(BUKEM):

    def __init__(self, name, params):
        super().__init__(name)
        self._params = params

    def DeriveKeyPair(self, seed: bytes) -> Tuple[bytes, bytes]:
        return DeriveKeyPair(seed, self._params)
    
    def Encaps(self, pk: bytes, seed: bytes) -> Tuple[bytes, bytes]:
        return Encaps(pk, seed, self._params)
    
    def Decaps(self, sk: bytes, ct: bytes) -> bytes:
        return Decaps(sk, ct, self._params)
    

# TODO: We currently do not support other parameter sets because some of the contents are for 768
class MLBUKEM768(MLBUKEM):

    def __init__(self):
        super().__init__("ML-BUKEM768", params768)

    def _pk_len(self) -> int:
        return NPK_SEQS * INT_BYTES + 32
    
    def _c_len(self) -> int:
        return NC_SEQS * INT_BYTES
    

def run_MLBUKEM():
    vectors = []
    for _ in range(3):
        keypair_seed = os.urandom(64)
        encaps_seed = os.urandom(32)
        pk, sk = DeriveKeyPair(keypair_seed, params768)
        c, k = Encaps(pk, encaps_seed, params768)
        
        wrap_print("keypair_seed:", to_hex(keypair_seed))
        wrap_print("pk: ", to_hex(pk))
        wrap_print("sk: ", to_hex(sk))
        wrap_print("encaps_seed", to_hex(encaps_seed))
        wrap_print("c: ", to_hex(c))
        wrap_print("k: ", to_hex(k))
        print()

        vector = {
            "keypair_seed": to_hex(keypair_seed),
            "pk": to_hex(pk),
            "sk": to_hex(sk),
            "encaps_seed": to_hex(encaps_seed),
            "c": to_hex(c),
            "k": to_hex(k),
        }
        vectors.append(vector)
    
    print(json.dumps(vectors, indent=4))


if __name__ == "__main__":
    x = [i for i in range(512)]
    assert x == ByteDecodeUniform(ByteEncodeUniform(x, 2), 2)

    params = mlkem.params768
    pk, sk = DeriveKeyPair(random(64), params)

    d = 10
    for x in range(Q):
        y1 = mlkem.Compress(x, d)
        y2 = mlkem.Compress(DecompressUniform(d, y1), d)
        assert y1 == y2

    d = 11
    for x in range(Q):
        y1 = mlkem.Compress(x, d)
        y2 = mlkem.Compress(DecompressUniform(d, y1), d)
        assert y1 == y2

    d = 4
    for x in range(Q):
        y1 = mlkem.Compress(x, d)
        y2 = mlkem.Compress(DecompressUniform(d, y1), d)
        assert y1 == y2

    d = 5
    for x in range(Q):
        y1 = mlkem.Compress(x, d)
        y2 = mlkem.Compress(DecompressUniform(d, y1), d)
        assert y1 == y2

    c, k1 = Encaps(pk, random(32), params)
    k2 = Decaps(sk, c, params)

    assert k1 == k2

    run_MLBUKEM()
