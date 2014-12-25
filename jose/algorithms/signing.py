import logging
logger = logging.getLogger(__name__)

from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_SIG


class SigningAlgorithm(object):
    def __init__(self, key):
        self.key = key

    def sign(self, text):
        raise NotImplementedError()

    def verify(self, text, signature):
        raise NotImplementedError()


class PKCS_Base(SigningAlgorithm):
    def __init__(self, key):
        key = RSA.importKey(key)
        super(PKCS_Base, self).__init__(key)

    def _hash(self, text):
        return self.mod.new(text)

    def sign(self, text):
        return PKCS1_v1_5_SIG.new(self.key).sign(self._hash(text))

    def verify(self, text, signature):
        return PKCS1_v1_5_SIG.new(self.key).verify(self._hash(text), signature)


class RS256(PKCS_Base):
    mod = SHA256


class RS384(PKCS_Base):
    mod = SHA384


class RS512(PKCS_Base):
    mod = SHA512


_SIGNATURE_ALGORITHMS = {
    'RS256': RS256,
    'RS384': RS384,
    'RS512': RS512,
}


def from_name(name):
    return _SIGNATURE_ALGORITHMS[name]
