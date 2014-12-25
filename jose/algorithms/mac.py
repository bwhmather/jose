import logging
logger = logging.getLogger(__name__)

from Crypto.Hash import HMAC, SHA256, SHA384, SHA512

from jose.utils import const_compare


def _hmac_sign(s, key, mod=SHA256):
    hmac = HMAC.new(key, digestmod=mod)
    hmac.update(s)
    return hmac.digest()


def _hmac_verify(s, key, sig, mod=SHA256):
    hmac = HMAC.new(key, digestmod=mod)
    hmac.update(s)

    if not const_compare(hmac.digest(), sig):
        return False

    return True


def _make_hmac_signature_algorithm(mod):
    return (
        lambda s, key: _hmac_sign(s, key, mod=mod),
        lambda s, key, sig: _hmac_verify(s, key, sig, mod=mod)
    )


_MAC_ALGORITHMS = {
    'HS256': _make_hmac_signature_algorithm(SHA256),
    'HS384': _make_hmac_signature_algorithm(SHA384),
    'HS512': _make_hmac_signature_algorithm(SHA512),
}


def from_name(name):
    return _MAC_ALGORITHMS[name]
