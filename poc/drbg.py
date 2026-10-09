#!/usr/local/bin/sage
# vim: syntax=python

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256


class UnsafeDRBG(object):
    def __init__(self):
        hmac = HMAC.new(b'sixteen byte key', digestmod=SHA256)
        key = hmac.update(b'test').digest()
        self.cipher = AES.new(key, AES.MODE_CTR)

    def random_bytes(self, n):
        zeroes = bytes([0x00] * n)
        ct = self.cipher.encrypt(zeroes)
        return ct
