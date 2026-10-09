# ML-BUA-sKEM: ML-KEM with public keys encoded using Kemeleon.EncodeEk.

from typing import Sequence, Tuple

import kemeleon
import mlkem
from deps import BUASKEM


KEMELEON_T = 132


class MLBUASKEM(BUASKEM):

    def __init__(self, name, params):
        super().__init__(name)
        self.params = params
        self.Nt = params.k * kemeleon.EncodedLength(KEMELEON_T)
        self.Nrho = 32
        self.Npk = self.Nt + self.Nrho
        self.Nct = 32 * (params.du * params.k + params.dv)

    def KeyGen(self, rng) -> Tuple[bytes, bytes]:
        (ek, dk) = mlkem.KeyGen(rng.random_bytes(64, "keygen_seed"), self.params)
        upk = kemeleon.EncodeEk(ek, self.params, KEMELEON_T, rng)
        return dk, upk

    def KeyGenDerand(self, seed: bytes, ms: Sequence[int]) -> Tuple[bytes, bytes]:
        """KeyGen, with the ML-KEM seed d || z and the Kemeleon randomness given as input."""
        (ek, dk) = mlkem.KeyGen(seed, self.params)
        upk = kemeleon.EncodeEkDerand(ek, self.params, KEMELEON_T, ms)
        return dk, upk

    def Split(self, upk: bytes) -> Tuple[bytes, bytes]:
        ut = upk[0:self.Nt]
        rho = upk[self.Nt:self.Npk]
        return ut, rho

    def Combine(self, ut: bytes, rho: bytes) -> bytes:
        return ut + rho

    def Encaps(self, upk: bytes, rng) -> Tuple[bytes, bytes]:
        return self.EncapsDerand(upk, rng.random_bytes(32, "encaps_m"))

    def EncapsDerand(self, upk: bytes, m: bytes) -> Tuple[bytes, bytes]:
        """Encaps, with the ML-KEM randomness m given as input."""
        pk = kemeleon.DecodeEk(upk, self.params, KEMELEON_T)
        (ct, k) = mlkem.Enc(pk, m, self.params)
        return k, ct

    def Decaps(self, ct: bytes, sk: bytes) -> bytes:
        return mlkem.Dec(sk, ct, self.params)


class MLBUASKEM768(MLBUASKEM):

    def __init__(self):
        super().__init__("ML-BUA-sKEM-768", mlkem.params768)


class MLBUASKEM1024(MLBUASKEM):

    def __init__(self):
        super().__init__("ML-BUA-sKEM-1024", mlkem.params1024)


if __name__ == "__main__":
    from drbg import UnsafeDRBG

    rng = UnsafeDRBG()
    # Sizes from the table of ML-BUA-sKEM parameter sets: (Npk, Nt, Nrho, Nct)
    for kem, sizes in [(MLBUASKEM768(), (1205, 1173, 32, 1088)), (MLBUASKEM1024(), (1596, 1564, 32, 1568))]:
        assert (kem.Npk, kem.Nt, kem.Nrho, kem.Nct) == sizes
        for _ in range(5):
            rng.draws = []
            sk, pk = kem.KeyGen(rng)
            assert len(pk) == kem.Npk
            assert kem.Combine(*kem.Split(pk)) == pk

            # KeyGenDerand reproduces KeyGen from the randomness that KeyGen consumed.
            seed = [value for label, value in rng.draws if label == "keygen_seed"][0]
            ms = [value for label, value in rng.draws if label == "kemeleon_m"]
            assert kem.KeyGenDerand(seed, ms) == (sk, pk)

            k, ct = kem.Encaps(pk, rng)
            assert len(ct) == kem.Nct
            assert kem.Decaps(ct, sk) == k
