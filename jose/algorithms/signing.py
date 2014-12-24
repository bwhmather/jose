import logging
logger = logging.getLogger(__name__)

from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_SIG


def _rsa_sign(s, key, mod=SHA256):
    key = RSA.importKey(key)
    hash = mod.new(s)
    return PKCS1_v1_5_SIG.new(key).sign(hash)


def _rsa_verify(s, key, sig, mod=SHA256):
    key = RSA.importKey(key)
    hash = mod.new(s)
    return PKCS1_v1_5_SIG.new(key).verify(hash, sig)


def _make_rsa_signature_algorithm(mod):
    return (
        lambda s, key: _rsa_sign(s, key, mod=mod),
        lambda s, key: _rsa_verify(s, key, mod=mod)
    )


_SIGNATURE_ALGORITHMS = {
    'RS256': _make_rsa_signature_algorithm(SHA256),
    'RS384': _make_rsa_signature_algorithm(SHA384),
    'RS512': _make_rsa_signature_algorithm(SHA512),
}


def from_name(name):
    return _SIGNATURE_ALGORITHMS[name]
