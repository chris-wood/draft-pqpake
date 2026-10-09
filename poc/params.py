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


# The configurations of the specification, by identifier. The configurations
# with P-384 are not implemented.
CONFIGURATIONS = {
    "oquake-mlbuaskem1024": oquake_configuration(
        MLBUASKEM1024(), bytes.fromhex("601ed384c5775ddd3021f51a4660fff24bf4eaa7845a958b2cade75289d184cd")),
    "oquake-mlbuaskem768": oquake_configuration(
        MLBUASKEM768(), bytes.fromhex("ca45261d9fe329b856389ebbf7f37ffa76c0034d8fc356454e1291d7d23e2045")),
    "oquakeplus-mlbuaskem1024-mlkem1024": oquakeplus_configuration(
        MLBUASKEM1024(), MLKEM1024(), bytes.fromhex("284e89132c00ba4f49e66d0af9e63c4c8efa701ce4b66bb6fcf1ce9cc5c35be1")),
    "oquakeplus-mlbuaskem768-mlkem768": oquakeplus_configuration(
        MLBUASKEM768(), MLKEM768(), bytes.fromhex("2a1a96e307871d45a9739c7193eeb04d6f52d17c67a52f762e5aae17df1ee5e6")),
    "cpaceoquake-x25519-mlbuaskem1024": cpaceoquake_configuration(
        G_X25519(), H_SHA512(), MLBUASKEM1024(), bytes.fromhex("443e3089985f0f8dddfb20cc5e8618f447bdcfe6dd39abb23911cd784c075120")),
    "cpaceoquake-x25519-mlbuaskem768": cpaceoquake_configuration(
        G_X25519(), H_SHA512(), MLBUASKEM768(), bytes.fromhex("c2ef9d7f73324735ec5614f331fa49c86c05be3430996c46816fca59d778380b")),
    "cpaceoquakeplus-x25519-mlbuaskem1024-xwing": cpaceoquakeplus_configuration(
        G_X25519(), H_SHA512(), MLBUASKEM1024(), XWingKEM(), bytes.fromhex("7de162c387ba1bad9c790e7e56bd245d6753d045185cbc3972eba34ddac1a9db")),
    "cpaceoquakeplus-x25519-mlbuaskem768-xwing": cpaceoquakeplus_configuration(
        G_X25519(), H_SHA512(), MLBUASKEM768(), XWingKEM(), bytes.fromhex("07d746a69c979f51e46d0051f0878a05ac5ec457d93c72ec6b814f528aae46f2")),
}

# The preferred configuration of each protocol
oquake_params_default = CONFIGURATIONS["oquake-mlbuaskem1024"]
oquakeplus_params_default = CONFIGURATIONS["oquakeplus-mlbuaskem1024-mlkem1024"]
cpaceoquake_params_default = CONFIGURATIONS["cpaceoquake-x25519-mlbuaskem1024"]
cpaceoquakeplus_params_default = CONFIGURATIONS["cpaceoquakeplus-x25519-mlbuaskem1024-xwing"]
cpace_params_default = cpaceoquake_params_default.cpace_params


if __name__ == "__main__":
    from drbg import UnsafeDRBG
    from oquake import run_OQUAKE
    from oquake_plus import run_OQUAKEPlus
    from cpaceoquake import run_CPaceOQUAKE
    from cpaceoquake_plus import run_CPaceOQUAKEPlus

    # Run each protocol once in each configuration.
    rng = UnsafeDRBG()
    for identifier, params in CONFIGURATIONS.items():
        print(identifier)
        if isinstance(params, OQUAKEParameters):
            run_OQUAKE(params, rng)
        elif isinstance(params, OQUAKEPlusParameters):
            run_OQUAKEPlus(params, rng)
        elif isinstance(params, CPaceOQUAKEParameters):
            run_CPaceOQUAKE(params, rng, rng.random_bytes(16))
        else:
            run_CPaceOQUAKEPlus(params, rng)
