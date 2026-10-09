#!/usr/local/bin/python3
# vim: syntax=python

import struct

def zero_bytes(n):
    return bytearray([0] * n)

def xor(a, b):
    if len(a) != len(b):
        assert len(a) == len(b), (len(a), len(b))
    c = bytearray(a)
    for i, v in enumerate(b):
        c[i] = c[i] ^ v
    return bytes(c)

def to_hex_string(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, (bytes, bytearray))
    return "".join("{:02x}".format(c) for c in octet_string)

def to_hex(octet_string):
    if isinstance(octet_string, list):
        return ",".join([to_hex_string(x) for x in octet_string])
    return to_hex_string(octet_string)

to_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

# defined in RFC 3447, section 4.1
def I2OSP(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = [0] * length
    val_ = val
    for idx in reversed(range(0, length)):
        ret[idx] = val_ & 0xff
        val_ = val_ >> 8
    ret = struct.pack("=" + "B" * length, *ret)
    assert OS2IP(ret, True) == val
    return ret

# defined in RFC 3447, section 4.2
def OS2IP(octets, skip_assert=False):
    ret = 0
    for octet in struct.unpack("=" + "B" * len(octets), octets):
        ret = ret << 8
        ret += octet
    if not skip_assert:
        assert octets == I2OSP(ret, len(octets))
    return ret

def lv_encode(x):
    assert len(x) < (1 << 16)
    return I2OSP(len(x), 2) + x

def lv_decode(x):
    if len(x) < 2 or OS2IP(x[0:2]) != len(x) - 2:
        raise ValueError("lv_decode: invalid length")
    return x[2:]

def EncodePublicContext(sid=None, U=None, S=None):
    sid, U, S = sid or b"", U or b"", S or b""
    return I2OSP(len(sid), 4) + sid + I2OSP(len(U), 4) + U + I2OSP(len(S), 4) + S

# When TRACE is a list, trace() appends (label, value) to it. The test vector
# generator uses this to list intermediate values of the protocols.
TRACE = None

def trace(label, value):
    if TRACE is not None:
        TRACE.append((label, value))

def assert_raises(exception, f, *args):
    # Used by the self-tests to check exceptional cases.
    try:
        f(*args)
    except exception:
        return
    raise AssertionError("expected " + exception.__name__)

def wrap_print(arg, *args):
    line_length = 69
    string = arg + " " + " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            print(hunk)
