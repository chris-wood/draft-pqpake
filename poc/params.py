import hashlib
from cpace import G_X25519, H_SHA512
from ml_bua_skem import MLBUASKEM768, MLBUASKEM1024
from deps import BUASKEM, KDF, KEM, KSF, MLKEM768, MLKEM1024, XWingKEM, HKDF, Scrypt


# Common parameters of all configurations
Nv = 32
Nkc = 32
Nr = 64
Nkey = 32


class CPaceParameters:

    def __init__(self, G, H, KDF: KDF, DST: bytes):
        self.G = G
        self.H = H
        self.KDF = KDF
        self.DST = DST


class OQUAKEParameters:

    def __init__(self, BUA_sKEM: BUASKEM, KDF: KDF, DST: bytes, Nr: int, Nkc: int, Nkey: int):
        self.BUA_sKEM = BUA_sKEM
        self.KDF = KDF
        self.DST = DST
        self.Nr = Nr
        self.Nkc = Nkc
        self.Nkey = Nkey


class CPaceOQUAKEParameters:

    def __init__(self, cpace_params: CPaceParameters, oquake_params: OQUAKEParameters, KDF: KDF, DST: bytes, Nkey: int):
        self.cpace_params = cpace_params
        self.oquake_params = oquake_params
        self.KDF = KDF
        self.DST = DST
        self.Nkey = Nkey


class PasswordConfirmationParameters:

    def __init__(self, KEM: KEM, KDF: KDF, KSF: KSF, DST: bytes, Nv: int, Nkc: int, Nkey: int):
        self.KEM = KEM
        self.KDF = KDF
        self.KSF = KSF
        self.DST = DST
        self.Nv = Nv
        self.Nkc = Nkc
        self.Nkey = Nkey


class OQUAKEPlusParameters:

    def __init__(self, oquake_params: OQUAKEParameters, pwconf_params: PasswordConfirmationParameters):
        self.oquake_params = oquake_params
        self.pwconf_params = pwconf_params


class CPaceOQUAKEPlusParameters:

    def __init__(self, cpaceoquake_params: CPaceOQUAKEParameters, pwconf_params: PasswordConfirmationParameters):
        self.cpaceoquake_params = cpaceoquake_params
        self.pwconf_params = pwconf_params


# The following functions build the parameters of each protocol from its
# components. The DST of the outermost protocol applies throughout.

def oquake_configuration(BUA_sKEM: BUASKEM, DST: bytes) -> OQUAKEParameters:
    return OQUAKEParameters(BUA_sKEM, HKDF(hashlib.sha256), DST, Nr, Nkc, Nkey)


def cpaceoquake_configuration(G, H, BUA_sKEM: BUASKEM, DST: bytes) -> CPaceOQUAKEParameters:
    return CPaceOQUAKEParameters(CPaceParameters(G, H, HKDF(hashlib.sha256), DST),
                                 oquake_configuration(BUA_sKEM, DST), HKDF(hashlib.sha256), DST, Nkey)


def pwconf_configuration(KEM: KEM, DST: bytes) -> PasswordConfirmationParameters:
    return PasswordConfirmationParameters(KEM, HKDF(hashlib.sha256), Scrypt(32768, 8, 1), DST, Nv, Nkc, Nkey)


def oquakeplus_configuration(BUA_sKEM: BUASKEM, KEM: KEM, DST: bytes) -> OQUAKEPlusParameters:
    return OQUAKEPlusParameters(oquake_configuration(BUA_sKEM, DST), pwconf_configuration(KEM, DST))


def cpaceoquakeplus_configuration(G, H, BUA_sKEM: BUASKEM, KEM: KEM, DST: bytes) -> CPaceOQUAKEPlusParameters:
    return CPaceOQUAKEPlusParameters(cpaceoquake_configuration(G, H, BUA_sKEM, DST), pwconf_configuration(KEM, DST))


# The preferred configuration of each protocol: oquake-mlbuaskem1024,
# cpaceoquake-x25519-mlbuaskem1024, oquakeplus-mlbuaskem1024-mlkem1024, and
# cpaceoquakeplus-x25519-mlbuaskem1024-xwing
oquake_params_default = oquake_configuration(
    MLBUASKEM1024(), bytes.fromhex("601ed384c5775ddd3021f51a4660fff24bf4eaa7845a958b2cade75289d184cd"))
cpaceoquake_params_default = cpaceoquake_configuration(
    G_X25519(), H_SHA512(), MLBUASKEM1024(), bytes.fromhex("443e3089985f0f8dddfb20cc5e8618f447bdcfe6dd39abb23911cd784c075120"))
oquakeplus_params_default = oquakeplus_configuration(
    MLBUASKEM1024(), MLKEM1024(), bytes.fromhex("284e89132c00ba4f49e66d0af9e63c4c8efa701ce4b66bb6fcf1ce9cc5c35be1"))
cpaceoquakeplus_params_default = cpaceoquakeplus_configuration(
    G_X25519(), H_SHA512(), MLBUASKEM1024(), XWingKEM(), bytes.fromhex("7de162c387ba1bad9c790e7e56bd245d6753d045185cbc3972eba34ddac1a9db"))
cpace_params_default = cpaceoquake_params_default.cpace_params
