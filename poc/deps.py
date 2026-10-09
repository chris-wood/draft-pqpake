#!/usr/local/bin/sage
# vim: syntax=python

from abc import ABC, abstractmethod
import hmac
import hashlib
import math
import functools
from random import randbytes
from typing import Tuple
from xwing import GenerateKeyPairDerand, EncapsulateDerand, Decapsulate
import mlkem


class KEM(ABC):

    def __init__(self, name):
        self.name = name

    def KeyGen(self) -> Tuple[bytes, bytes]:
        return self.DeriveKeyPair(randbytes(64))

    @abstractmethod
    def DeriveKeyPair(self, seed: bytes) -> Tuple[bytes, bytes]:
        pass

    @abstractmethod
    def Encaps(self, pk: bytes, seed: bytes) -> Tuple[bytes, bytes]:
        pass

    @abstractmethod
    def Decaps(self, sk: bytes, ct: bytes) -> bytes:
        pass

    @property
    def PK_LEN(self) -> int:
        return self._pk_len()
    
    @property
    def C_LEN(self) -> int:
        return self._c_len()

    @abstractmethod
    def _pk_len(self) -> int:
        pass

    @abstractmethod
    def _c_len(self) -> int:
        pass


class BUKEM(KEM):
    pass


class MLKEM(KEM):

    @abstractmethod
    def params(self):
        pass


class MLKEM768(MLKEM):

    def __init__(self):
        super().__init__("ML-KEM768")

    def DeriveKeyPair(self, seed):
        return mlkem.KeyGen(seed, mlkem.params768)
    
    def Encaps(self, pk, seed):
        return mlkem.Enc(pk, seed, mlkem.params768)
    
    def Decaps(self, sk, ct):
        return mlkem.Dec(sk, ct, mlkem.params768)
    
    def _pk_len(self):
        return 1184
    
    def _c_len(self):
        return 1088
    
    def params(self):
        return mlkem.params768
    

class XWingKEM(KEM):

    def __init__(self):
        KEM.__init__(self, "X-Wing")

    def DeriveKeyPair(self, seed):
        sk, pk = GenerateKeyPairDerand(seed)
        return pk, sk

    def Encaps(self, pk, seed):
        ss, ct = EncapsulateDerand(pk, seed)
        return ct, ss

    def Decaps(self, sk, ct):
        return Decapsulate(ct, sk)
    
    def _pk_len(self) -> int:
        raise 1216

    def _c_len(self) -> int:
        return 1120

    # def serialize_public_key(self, pk):
    #     return pk

    # def deserialize_public_key(self, enc):
    #     return enc


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
    def Stretch(self, PRS: bytes, salt: bytes, length: int) -> bytes:
        pass


class SHA256KeyStretchingFunction(KSF):

    def __init__(self):
        self.name = "identity"

    def Stretch(self, PRS: bytes, salt: bytes, length: int) -> bytes:
        h = hashlib.shake_128()
        h.update(PRS)
        h.update(salt)
        return h.digest(length)
