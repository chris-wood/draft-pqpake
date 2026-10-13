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


class ReplayRNG(object):
    """
    Returns the randomness listed in a test vector, by label, in place of random
    values. It checks that a test vector lists all randomness of a protocol run.
    """

    def __init__(self, values):
        self.values = {label: list(value) if isinstance(value, list) else [value]
                       for label, value in values.items()}
        self.draws = []

    def random_bytes(self, n, label=None):
        value = self.values[label].pop(0)
        assert len(value) == n, label
        self.draws.append((label, value))
        return value

    def random_integer(self, bound, label=None):
        value = self.values[label].pop(0)
        assert 0 <= value <= bound, label
        self.draws.append((label, value))
        return value

    def assert_consumed(self):
        assert all(not values for values in self.values.values()), self.values
