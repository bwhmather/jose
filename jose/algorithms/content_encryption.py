import logging
logger = logging.getLogger(__name__)

import struct

from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC
from Crypto.Cipher import AES

from jose.exceptions import AuthenticationError
from jose.utils import pad_pkcs7, unpad_pkcs7, sha


def _jwe_hash_str(ciphertext, iv, adata=b''):
    # http://tools.ietf.org/html/
    # draft-ietf-jose-json-web-algorithms-24#section-5.2.2.1
    return b''.join((adata, iv, ciphertext, struct.pack("!Q", len(adata) * 8)))


class ContentEncryptionAlgorithm(object):
    def __init__(self, key):
        self.key = key

    @classmethod
    def generate_key(cls, rng=None):
        raise NotImplementedError()

    @classmethod
    def generate_iv(cls, rng=None):
        raise NotImplementedError()

    def encrypt(self, plaintext, adata, iv):
        raise NotImplementedError()

    def decrypt(self, ciphertext, adata, iv):
        raise NotImplementedError()


class AES_CBC_HMAC_SHA2_Base(ContentEncryptionAlgorithm):
    def __init__(self, key):
        if len(key) != self.enc_key_size + self.mac_key_size:
            raise ValueError("key is wrong size")
        self.key = key

    @classmethod
    def generate_key(cls, rng=None):
        if rng is None:
            rng = get_random_bytes
        return rng(cls.enc_key_size + cls.mac_key_size)

    @classmethod
    def generate_iv(cls, rng=None):
        if rng is None:
            rng = get_random_bytes
        return rng(16)

    def _sign(self, key, ciphertext, iv, adata):
        # TODO this is completely the wrong way to select the hash function
        hmac = HMAC.new(key, digestmod=sha(16*self.mac_key_size))

        hmac.update(_jwe_hash_str(ciphertext, iv, adata))

        signature = hmac.digest()

        # http://tools.ietf.org/html/
        # draft-ietf-oauth-json-web-token-19#section-4.1.4
        return signature[:len(signature) // 2]

    def encrypt(self, plaintext, iv, adata=None):
        if adata is None:
            adata = b''

        signature_key = self.key[:self.mac_key_size]
        encryption_key = self.key[self.mac_key_size:]

        padded_plaintext = pad_pkcs7(plaintext, block_size=AES.block_size)

        enc_algorithm = AES.new(encryption_key, AES.MODE_CBC, iv)
        ciphertext = enc_algorithm.encrypt(padded_plaintext)

        auth_digest = self._sign(signature_key, ciphertext, iv, adata)
        auth_token = auth_digest[:self.token_size]

        return ciphertext, auth_token

    def decrypt(self, ciphertext, auth_token, iv, adata=None):
        if adata is None:
            adata = b''

        signature_key = self.key[:self.mac_key_size]
        encryption_key = self.key[self.mac_key_size:]

        enc_algorithm = AES.new(encryption_key, AES.MODE_CBC, iv)
        padded_plaintext = enc_algorithm.decrypt(ciphertext)
        plaintext = unpad_pkcs7(padded_plaintext)

        auth_digest = self._sign(signature_key, ciphertext, iv, adata)
        calculated_auth_token = auth_digest[:self.token_size]

        if calculated_auth_token != auth_token:
            raise AuthenticationError("Mismatched authentication tag")

        return plaintext


class A128CBC_HS256(AES_CBC_HMAC_SHA2_Base):
    enc_key_size = 16
    mac_key_size = 16
    token_size = 16


class A192CBC_HS384(AES_CBC_HMAC_SHA2_Base):
    enc_key_size = 24
    mac_key_size = 24
    token_size = 24


class A256CBC_HS512(AES_CBC_HMAC_SHA2_Base):
    enc_key_size = 32
    mac_key_size = 32
    token_size = 32


_CONTENT_ENCRYPTION_ALGORITHMS = {
    'A128CBC-HS256': A128CBC_HS256,
    'A192CBC-HS384': A192CBC_HS384,
    'A256CBC-HS512': A256CBC_HS512,
}


def from_name(name):
    return _CONTENT_ENCRYPTION_ALGORITHMS[name]
