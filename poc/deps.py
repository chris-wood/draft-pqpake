from abc import ABC, abstractmethod
import hmac
import hashlib
import math
import functools
from typing import Tuple
from util import lv_encode
from xwing import GenerateKeyPairDerand, EncapsulateDerand, Decapsulate
import mlkem


class KEM(ABC):
    """KEM with key derivation from a seed, used for password confirmation."""

    def __init__(self, name, Nseed, Nct, Npk):
        self.name = name
        self.Nseed = Nseed
        self.Nct = Nct
        self.Npk = Npk

    @abstractmethod
    def DeriveKeyPair(self, seed: bytes) -> Tuple[bytes, bytes]:
        """Returns (sk, pk)."""
        pass

    @abstractmethod
    def Encaps(self, pk: bytes, rng) -> Tuple[bytes, bytes]:
        """Returns (k, ct)."""
        pass

    @abstractmethod
    def Decaps(self, ct: bytes, sk: bytes) -> bytes:
        pass


class BUASKEM(ABC):
    """Splittable binary KEM with uniform public keys and anonymous ciphertexts."""

    def __init__(self, name):
        self.name = name

    @abstractmethod
    def KeyGen(self, rng) -> Tuple[bytes, bytes]:
        """Returns (sk, pk)."""
        pass

    @abstractmethod
    def Split(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Returns (ut, rho)."""
        pass

    @abstractmethod
    def Combine(self, ut: bytes, rho: bytes) -> bytes:
        pass

    @abstractmethod
    def Encaps(self, pk: bytes, rng) -> Tuple[bytes, bytes]:
        """Returns (k, ct)."""
        pass

    @abstractmethod
    def Decaps(self, ct: bytes, sk: bytes) -> bytes:
        pass


class MLKEM(KEM):

    def __init__(self, name, params):
        super().__init__(name, 64, 32 * (params.du * params.k + params.dv), 384 * params.k + 32)
        self.params = params

    def DeriveKeyPair(self, seed):
        # KeyGen_internal(seed[0:32], seed[32:64])
        (ek, dk) = mlkem.KeyGen(seed, self.params)
        return dk, ek

    def Encaps(self, pk, rng):
        (ct, k) = mlkem.Enc(pk, rng.random_bytes(32, "kem_encaps_m"), self.params)
        return k, ct

    def Decaps(self, ct, sk):
        return mlkem.Dec(sk, ct, self.params)


class MLKEM768(MLKEM):

    def __init__(self):
        super().__init__("ML-KEM-768", mlkem.params768)


class MLKEM1024(MLKEM):

    def __init__(self):
        super().__init__("ML-KEM-1024", mlkem.params1024)


class XWingKEM(KEM):

    def __init__(self):
        super().__init__("X-Wing", 32, 1120, 1216)

    def DeriveKeyPair(self, seed):
        return GenerateKeyPairDerand(seed)

    def Encaps(self, pk, rng):
        return EncapsulateDerand(pk, rng.random_bytes(64, "kem_encaps_eseed"))

    def Decaps(self, ct, sk):
        return Decapsulate(ct, sk)


class KDF(ABC):

    def __init__(self, name):
        self.name = name
    
    @abstractmethod
    def Extract(self, salt: bytes, ikm: bytes) -> bytes:
        pass

    @abstractmethod
    def Expand(self, prk: bytes, info: bytes, L: int) -> bytes:
        pass


class HKDF(KDF):

    def __init__(self, fast_hash):
        KDF.__init__(self, "HKDF-" + fast_hash().name.upper())
        self.hash = fast_hash

    def Extract(self, salt, ikm):
        return hmac.digest(salt, ikm, self.hash)

    def Expand(self, prk, info, L):
        # https://tools.ietf.org/html/rfc5869
        # N = ceil(L/HashLen)
        # T = T(1) | T(2) | T(3) | ... | T(N)
        # OKM = first L octets of T
        hash_length = self.hash().digest_size
        N = math.ceil(L / hash_length)
        Ts = [bytes(bytearray([]))]
        for i in range(N):
            Ts.append(hmac.digest(
                prk, Ts[i] + info + int(i+1).to_bytes(1, 'big'), self.hash))

        def concat(a, b):
            return a + b
        T = functools.reduce(concat, map(lambda c: c, Ts))
        return T[0:L]


def TH(KDF: KDF, DST: bytes, label: bytes, *fields: bytes) -> bytes:
    """The transcript hash TH, computed with the KDF and DST of the configuration."""
    return KDF.Extract(DST + b"TH-" + label, b"".join(lv_encode(f) for f in fields))


class AuthenticationError(Exception):
    """Password confirmation failed at the client or server."""
    pass


class CPaceError(Exception):
    """An invalid value, such as a point that yields the group identity, was encountered in CPace."""
    pass


class MAC(object):

    def __init__(self, name):
        self.name = name
    
    def mac(self, key, input):
        raise Exception("Not implemented")


class HMAC(MAC):

    def __init__(self, fast_hash):
        MAC.__init__(self, "HMAC-" + fast_hash().name.upper())
        self.hash = fast_hash

    def output_size(self):
        return self.hash().digest_size

    def mac(self, key, input):
        return hmac.digest(key, input, self.hash)


class KSF(ABC):

    def __init__(self, name):
        self.name = name

    @abstractmethod
    def Stretch(self, msg: bytes, salt: bytes, length: int) -> bytes:
        pass


class Scrypt(KSF):

    def __init__(self, N, r, p):
        super().__init__("scrypt")
        self.N = N
        self.r = r
        self.p = p

    def Stretch(self, msg: bytes, salt: bytes, length: int) -> bytes:
        return hashlib.scrypt(msg, salt=salt, n=self.N, r=self.r, p=self.p,
                              maxmem=2 * 128 * self.r * self.N * self.p, dklen=length)
