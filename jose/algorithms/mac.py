import logging
logger = logging.getLogger(__name__)

from Crypto.Hash import HMAC, SHA256, SHA384, SHA512

from jose.utils import const_compare


class HMAC_Base(object):
    def __init__(self, key):
        self.key = key

    def sign(self, text):
        hmac = HMAC.new(self.key, digestmod=self.mod)
        hmac.update(text)
        return hmac.digest()

    def verify(self, text, sig):
        hmac = HMAC.new(self.key, digestmod=self.mod)
        hmac.update(text)

        if not const_compare(hmac.digest(), sig):
            return False

        return True


class HS256(HMAC_Base):
    mod = SHA256


class HS384(HMAC_Base):
    mod = SHA384


class HS512(HMAC_Base):
    mod = SHA512


_MAC_ALGORITHMS = {
    'HS256': HS256,
    'HS384': HS384,
    'HS512': HS512,
}


def from_name(name):
    return _MAC_ALGORITHMS[name]
