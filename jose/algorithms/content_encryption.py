import logging
logger = logging.getLogger(__name__)

from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
from Crypto.Cipher import AES

from jose.utils import pad_pkcs7, unpad_pkcs7


def _jwe_hash_str(plaintext, iv, adata=b''):
    # http://tools.ietf.org/html/
    # draft-ietf-jose-json-web-algorithms-24#section-5.2.2.1
    return b'.'.join((adata, iv, plaintext, bytes(len(adata))))


class ContentEncryptionAlgorithm(object):
    def __init__(self, key):
        self.key = key

    @classmethod
    def generate_key(cls, rng=None):
        raise NotImplementedError()

    @classmethod
    def generage_iv(cls, rng=None):
        raise NotImplementedError()

    def encrypt(self, plaintext, adata, iv):
        raise NotImplementedError()

    def decrypt(self, ciphertext, adata, iv):
        raise NotImplementedError()


class AES_CBC_HMAC_SHA2_Base(ContentEncryptionAlgorithm):
    def __init__(self, key):
        if len(key) != self.key_size:
            raise ValueError("key is wrong size")
        self.key = key

    @classmethod
    def generate_key(cls, rng=None):
        if rng is None:
            rng = get_random_bytes
        return rng(cls.key_size)

    @classmethod
    def generate_iv(cls, rng=None):
        if rng is None:
            rng = get_random_bytes
        return rng(16)

    def _sign(self, key, plaintext, iv, adata):
        # TODO this is completely the wrong way to select the hash function
        hmac = HMAC.new(
            key,
            digestmod={
                32: SHA256,
                48: SHA384,
                64: SHA512,
            }[self.key_size]
        )

        hmac.update(_jwe_hash_str(plaintext, iv, adata))

        signature = hmac.digest()

        # http://tools.ietf.org/html/
        # draft-ietf-oauth-json-web-token-19#section-4.1.4
        return signature[:len(signature) // 2]

    def encrypt(self, plaintext, iv, adata=None):
        if adata is None:
            adata = b''

        signature_key = self.key[-self.key_size // 2:]
        encryption_key = self.key[:-self.key_size // 2]

        padded_plaintext = pad_pkcs7(plaintext, block_size=AES.block_size)

        enc_algorithm = AES.new(encryption_key, AES.MODE_CBC, iv)
        ciphertext = enc_algorithm.encrypt(padded_plaintext)

        auth_token = self._sign(signature_key, plaintext, iv, adata)

        return ciphertext, auth_token

    def decrypt(self, ciphertext, auth_token, iv, adata=None):
        if adata is None:
            adata = b''
        signature_key = self.key[-self.key_size // 2:]
        encryption_key = self.key[:-self.key_size // 2]

        enc_algorithm = AES.new(encryption_key, AES.MODE_CBC, iv)
        padded_plaintext = enc_algorithm.decrypt(ciphertext)
        plaintext = unpad_pkcs7(padded_plaintext)

        calculated_auth_token = self._sign(signature_key, plaintext, iv, adata)

        if calculated_auth_token != auth_token:
            raise Exception("Mismatched authentication tag")

        return plaintext


class A128CBC_HS256(AES_CBC_HMAC_SHA2_Base):
    key_size = 32


class A192CBC_HS384(AES_CBC_HMAC_SHA2_Base):
    key_size = 48


class A256CBC_HS512(AES_CBC_HMAC_SHA2_Base):
    key_size = 64


_CONTENT_ENCRYPTION_ALGORITHMS = {
    'A128CBC-HS256': A128CBC_HS256,
    'A192CBC-HS384': A192CBC_HS384,
    'A256CBC-HS512': A256CBC_HS512,
}


def from_name(name):
    return _CONTENT_ENCRYPTION_ALGORITHMS[name]
