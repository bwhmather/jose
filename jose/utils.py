from base64 import urlsafe_b64encode, urlsafe_b64decode
import binascii

from jose.exceptions import Error


try:
    # python 2 compatibility
    unicode
except NameError:
    unicode = str


def pad_pkcs7(s, block_size):
    padding = block_size - (len(s) % block_size)
    # TODO would be cleaner to do `bytes(sz) * sz` but python 2 behaves
    # strangely
    return s + (chr(padding) * padding).encode('ascii')


def unpad_pkcs7(s):
    # TODO validation
    try:
        return s[:-ord(s[-1])]
    # Python 3 compatibility
    except TypeError:
        return s[:-s[-1]]


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
