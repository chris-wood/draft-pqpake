import hashlib


class UnsafeDRBG(object):
    """
    Deterministic random byte generator for test vectors; not for production use.
    It records each value it returns, with an optional label, so that test vectors
    can list the randomness that each protocol step consumed.
    """

    def __init__(self, seed=b'test'):
        self.seed = seed
        self.counter = 0
        self.draws = []

    def _next(self, n):
        self.counter += 1
        return hashlib.shake_256(self.counter.to_bytes(8, 'big') + self.seed).digest(n)

    def random_bytes(self, n, label=None):
        out = self._next(n)
        self.draws.append((label, out))
        return out

    def random_integer(self, bound, label=None):
        """Returns a uniformly random integer in [0, bound], using rejection sampling."""
        bits = bound.bit_length()
        while True:
            x = int.from_bytes(self._next((bits + 7) // 8), 'little') & ((1 << bits) - 1)
            if x <= bound:
                self.draws.append((label, x))
                return x
