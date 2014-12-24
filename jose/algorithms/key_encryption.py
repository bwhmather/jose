import logging
logger = logging.getLogger(__name__)

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class KeyEncryptionAlgorithm(object):
    def encrypt(self, plaintext):
        raise NotImplementedError()

    def decrypt(self, ciphertext):
        raise NotImplementedError()


class RSAES_OAEP(KeyEncryptionAlgorithm):
    def __init__(self, jwk):
        self.key = RSA.importKey(jwk['k'])

    def encrypt(self, plaintext):
        return PKCS1_OAEP.new(self.key).encrypt(plaintext)

    def decrypt(self, ciphertext):
        return PKCS1_OAEP.new(self.key).decrypt(ciphertext)


class RSAES_OAEP_256(KeyEncryptionAlgorithm):
    pass


class AESKeyWrapBase(KeyEncryptionAlgorithm):
    def __init__(self, jwk):
        pass

    def encrypt(self, plaintext):
        pass

    def decrypt(self, ciphertext):
        pass


class A128KW(AESKeyWrapBase):
    key_size = 16


class A192KW(AESKeyWrapBase):
    key_size = 24


class A256KW(AESKeyWrapBase):
    key_size = 32


_KEY_ENCRYPTION_ALGORITHMS = {
    'RSA-OAEP': RSAES_OAEP,
    'RSA-OAEP-256': RSAES_OAEP_256,
    'A128KW': A128KW,
    'A192KW': A192KW,
    'A256KW': A256KW,
}


def from_name(name):
    return _KEY_ENCRYPTION_ALGORITHMS[name]
