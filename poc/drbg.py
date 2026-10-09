import hashlib


class UnsafeDRBG(object):
    """Deterministic random byte generator for test vectors; not for production use."""

    def __init__(self, seed=b'test'):
        self.seed = seed
        self.counter = 0

    def random_bytes(self, n):
        self.counter += 1
        return hashlib.shake_256(self.counter.to_bytes(8, 'big') + self.seed).digest(n)
