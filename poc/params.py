#!/usr/local/bin/sage
# vim: syntax=python

import hashlib
from ml_bua_skem import MLBUKEM768
from deps import BUKEM, KDF, KEM, KSF, MLKEM, MLKEM768, XWingKEM, HKDF, SHA256KeyStretchingFunction

from sagelib.RFC7748_X448_X25519 import *
from sagelib.CPace_string_utils import *
from sagelib.CPace_hashing import *
from sagelib.CPace_coffee import *
from sagelib.CPace_weierstrass import *
from sagelib.CPace_montgomery import *
from sagelib.test_vectors_X448_X25519 import *


class CPaceParameters:

    def __init__(self, G, H):
        self.G = G
        self.H = H


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


cpace_params_default = CPaceParameters(G_ShortWeierstrass(cpace_map_for_nist_p384), H_SHA384())
quake_params_default = OQUAKEParameters(MLKEM768(), HKDF(hashlib.sha256), 1156, 24)
cpaceoquake_params_default = CPaceOQUAKEParameters(cpace_params_default, quake_params_default, HKDF(hashlib.sha256))
pwconf_params_default = PasswordConfirmationParameters(XWingKEM(), HKDF(hashlib.sha256), SHA256KeyStretchingFunction())
cpaceoquakeplus_params_default = CPaceOQUAKEPlusParameters(cpaceoquake_params_default, pwconf_params_default)
