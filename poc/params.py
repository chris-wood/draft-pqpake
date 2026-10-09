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

    def __init__(self, mlkem: MLKEM, KDF: KDF, NpkUni: int, Nr: int):
        self.mlkem = mlkem
        self.KDF = KDF
        self.NpkUni = NpkUni
        self.Nrandomness = Nr


class CPaceOQUAKEParameters:

    def __init__(self, cpace_params: CPaceParameters, quake_params: OQUAKEParameters, KDF: KDF):
        self.cpace_params = cpace_params
        self.quake_params = quake_params
        self.KDF = KDF


class PasswordConfirmationParameters:

    def __init__(self, KEM: KEM, KDF: KDF, KSF: KSF):
        self.KEM = KEM
        self.KDF = KDF
        self.KSF = KSF


class CPaceOQUAKEPlusParameters:

    def __init__(self, cpaceoquake_params: CPaceOQUAKEParameters, pwconf_params: PasswordConfirmationParameters):
        self.cpaceoquake_params = cpaceoquake_params
        self.pwconf_params = pwconf_params


# DST of cpaceoquake-x25519-mlbuaskem1024
cpace_params_default = CPaceParameters(G_X25519(), H_SHA512(), HKDF(hashlib.sha256),
                                       bytes.fromhex("443e3089985f0f8dddfb20cc5e8618f447bdcfe6dd39abb23911cd784c075120"))
quake_params_default = OQUAKEParameters(MLKEM768(), HKDF(hashlib.sha256), 1156, 24)
cpaceoquake_params_default = CPaceOQUAKEParameters(cpace_params_default, quake_params_default, HKDF(hashlib.sha256))
pwconf_params_default = PasswordConfirmationParameters(XWingKEM(), HKDF(hashlib.sha256), SHA256KeyStretchingFunction())
cpaceoquakeplus_params_default = CPaceOQUAKEPlusParameters(cpaceoquake_params_default, pwconf_params_default)
