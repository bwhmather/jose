import sys
from base64 import urlsafe_b64encode, urlsafe_b64decode
import binascii

from Crypto.Hash import SHA224, SHA256, SHA384, SHA512

from jose.exceptions import Error


try:
    # python 2 compatibility
    unicode
except NameError:
    unicode = str


def pad_pkcs7(s, block_size):
    padding = block_size - (len(s) % block_size)
    return s + (chr(padding) * padding).encode('ascii')


def unpad_pkcs7(s, block_size=None):
    if not len(s):
        raise ValueError("padded string must always have non-zero length")

    if block_size is not None and len(s) % block_size:
        raise ValueError("padded string is not a multiple of block size")

    # python 2 compatibility
    if sys.version_info < (3, 0):
        padding_len = ord(s[-1])
        padding = s[-1] * padding_len
    else:
        padding_len = s[-1]
        padding = bytes([padding_len]) * padding_len

    if s[-padding_len:] != padding:
        raise ValueError("invalid padding")

    return s[:-padding_len]


def const_compare(stra, strb):
    if len(stra) != len(strb):
        return False

    try:
        # python 2 compatibility
        orda, ordb = list(map(ord, stra)), list(map(ord, strb))
    except TypeError:
        orda, ordb = stra, strb

    res = 0
    for a, b in zip(orda, ordb):
        res |= a ^ b
    return res == 0


def b64decode_url(istr):
    """ JWT Tokens may be truncated without the usual trailing padding '='
        symbols. Compensate by padding to the nearest 4 bytes.

    :param istr: A unicode string to decode
    :returns: The byte string represented by `istr`
    """
    # unicode check for python 2 compatibility
    if not isinstance(istr, (str, unicode)):
        raise ValueError("expected string, got %r" % type(istr))

    # required for python 2 as urlsafe_b64decode does not like unicode objects
    # safe as b64 encoded string should be only ascii anyway
    istr = str(istr)

    try:
        return urlsafe_b64decode(istr + '=' * (4 - (len(istr) % 4)))
    except (TypeError, binascii.Error) as e:
        raise Error('Unable to decode base64: %s' % (e))


def b64encode_url(istr):
    """ JWT Tokens may be truncated without the usual trailing padding '='
        symbols. Compensate by padding to the nearest 4 bytes.

    :param istr: a byte string to encode
    :returns: The base64 representation of the input byte string as a regular
        `str` object
    """
    if not isinstance(istr, bytes):
        raise Exception("expected bytestring")
    return urlsafe_b64encode(istr).rstrip(b'=').decode('ascii')


def sha(size):
    return {
        224: SHA224,
        256: SHA256,
        384: SHA384,
        512: SHA512,
    }[size]
