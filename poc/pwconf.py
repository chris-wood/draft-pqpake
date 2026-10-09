from typing import Optional, Tuple

from params import PasswordConfirmationParameters
from util import xor


VERIFIER_LENGTH = 32
SEED_LENGTH = 96
KC_LENGTH = 32


def GenVerifierMaterial(params: PasswordConfirmationParameters, PRS: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    verifier_seed = params.KSF.Stretch(PRS, salt, VERIFIER_LENGTH + SEED_LENGTH)
    verifier = verifier_seed[:VERIFIER_LENGTH]
    seed = verifier_seed[VERIFIER_LENGTH:]
    return verifier, seed


def GenVerifiers(params: PasswordConfirmationParameters, PRS: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    verifier, seed = GenVerifierMaterial(params, PRS, salt)
    pk, _ = params.KEM.DeriveKeyPair(seed)
    return verifier, pk


def pwconf_challenge(params: PasswordConfirmationParameters, SK: bytes, salt: bytes, pk: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[Tuple[bytes, bytes], bytes]:
    if SID is None:
        SID = b""
    if U is None:
        U = b""
    if S is None:
        S = b""
    
    c, k = params.KEM.Encaps(pk, seed)
    prk_kc = params.KDF.Extract(b"kc", SK + c + k + SID + U + S)
    h1 = params.KDF.Expand(prk_kc, b"h1", KC_LENGTH)
    h2 = params.KDF.Expand(prk_kc, b"h2", KC_LENGTH)
    server_key = params.KDF.Expand(prk_kc, b"vkey", 32)

    r = params.KDF.Expand(SK, b"OTP", params.KEM.C_LEN)
    challenge = xor(c, r) + h1

    return (h2, server_key), challenge


def pwconf_response(params: PasswordConfirmationParameters, SK: bytes, kem_seed: bytes, msg: bytes, SID: Optional[bytes], U: Optional[bytes], S: Optional[bytes], seed: bytes) -> Tuple[bytes, bytes]:
    if U is None:
        U = b""
    if S is None:
        S = b""

    cr = msg[:-KC_LENGTH]
    h1 = msg[-KC_LENGTH:]
    
    r = params.KDF.Expand(SK, b"OTP", params.KEM.C_LEN)
    c = xor(cr, r)

    _, sk = params.KEM.DeriveKeyPair(kem_seed)
    k = params.KEM.Decaps(sk, c)
    prk_kc = params.KDF.Extract(b"kc", SK + c + k + SID + U + S)
    h1p = params.KDF.Expand(prk_kc, b"h1", KC_LENGTH)
    h2p = params.KDF.Expand(prk_kc, b"h2", KC_LENGTH)
    client_key = params.KDF.Expand(prk_kc, b"vkey", 32)

    if h1 != h1p:
        raise Exception("AuthenticationError")
    
    return client_key, h2p


def pwconf_verify(context: Tuple[bytes, bytes], msg: bytes) -> bytes:
    h2, server_key = context
    
    if h2 != msg:
        raise Exception("AuthenticationError")
    
    return server_key
