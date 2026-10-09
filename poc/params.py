import hashlib
from cpace import G_X25519, H_SHA512
from ml_bua_skem import MLBUASKEM768, MLBUASKEM1024
from deps import BUASKEM, KDF, KEM, KSF, MLKEM, MLKEM768, XWingKEM, HKDF, SHA256KeyStretchingFunction


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

    def __init__(self, KEM: KEM, KDF: KDF, KSF: KSF):
        self.KEM = KEM
        self.KDF = KDF
        self.KSF = KSF


class CPaceOQUAKEPlusParameters:

    def __init__(self, cpaceoquake_params: CPaceOQUAKEParameters, pwconf_params: PasswordConfirmationParameters):
        self.cpaceoquake_params = cpaceoquake_params
        self.pwconf_params = pwconf_params


# Configurations oquake-mlbuaskem1024 and cpaceoquake-x25519-mlbuaskem1024. The DST of
# CPaceOQUAKE also applies within CPace and OQUAKE.
DST_OQUAKE = bytes.fromhex("601ed384c5775ddd3021f51a4660fff24bf4eaa7845a958b2cade75289d184cd")
DST_CPACEOQUAKE = bytes.fromhex("443e3089985f0f8dddfb20cc5e8618f447bdcfe6dd39abb23911cd784c075120")
cpace_params_default = CPaceParameters(G_X25519(), H_SHA512(), HKDF(hashlib.sha256), DST_CPACEOQUAKE)
oquake_params_default = OQUAKEParameters(MLBUASKEM1024(), HKDF(hashlib.sha256), DST_OQUAKE, 64, 32, 32)
cpaceoquake_params_default = CPaceOQUAKEParameters(
    cpace_params_default,
    OQUAKEParameters(MLBUASKEM1024(), HKDF(hashlib.sha256), DST_CPACEOQUAKE, 64, 32, 32),
    HKDF(hashlib.sha256), DST_CPACEOQUAKE, 32)
pwconf_params_default = PasswordConfirmationParameters(XWingKEM(), HKDF(hashlib.sha256), SHA256KeyStretchingFunction())
cpaceoquakeplus_params_default = CPaceOQUAKEPlusParameters(cpaceoquake_params_default, pwconf_params_default)
