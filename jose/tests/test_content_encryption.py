import unittest

from jose.algorithms.content_encryption import (
    A128CBC_HS256, A192CBC_HS384, A256CBC_HS512,
)


class AES_CBC_HMAC_SHA2_Base(unittest.TestCase):
    def test_encrypt(self):
        encrypter = self.algorithm(self.key)

        ciphertext, auth_token = encrypter.encrypt(
            self.plaintext, adata=self.adata, iv=self.iv
        )
        self.assertEqual(self.ciphertext, ciphertext)
        self.assertEqual(self.auth_token, auth_token)

    def test_decrypt(self):
        decrypter = self.algorithm(self.key)

        plaintext = decrypter.decrypt(
            self.ciphertext, auth_token=self.auth_token,
            adata=self.adata, iv=self.iv
        )
        self.assertEqual(self.plaintext, plaintext)


class Test_A128CBC_HS256(AES_CBC_HMAC_SHA2_Base):
    algorithm = A128CBC_HS256

    key = (
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
    )
    plaintext = (
        b'\x41\x20\x63\x69\x70\x68\x65\x72\x20\x73\x79\x73\x74\x65\x6d\x20'
        b'\x6d\x75\x73\x74\x20\x6e\x6f\x74\x20\x62\x65\x20\x72\x65\x71\x75'
        b'\x69\x72\x65\x64\x20\x74\x6f\x20\x62\x65\x20\x73\x65\x63\x72\x65'
        b'\x74\x2c\x20\x61\x6e\x64\x20\x69\x74\x20\x6d\x75\x73\x74\x20\x62'
        b'\x65\x20\x61\x62\x6c\x65\x20\x74\x6f\x20\x66\x61\x6c\x6c\x20\x69'
        b'\x6e\x74\x6f\x20\x74\x68\x65\x20\x68\x61\x6e\x64\x73\x20\x6f\x66'
        b'\x20\x74\x68\x65\x20\x65\x6e\x65\x6d\x79\x20\x77\x69\x74\x68\x6f'
        b'\x75\x74\x20\x69\x6e\x63\x6f\x6e\x76\x65\x6e\x69\x65\x6e\x63\x65'
    )

    iv = (
        b'\x1a\xf3\x8c\x2d\xc2\xb9\x6f\xfd\xd8\x66\x94\x09\x23\x41\xbc\x04'
    )

    adata = (
        b'\x54\x68\x65\x20\x73\x65\x63\x6f\x6e\x64\x20\x70\x72\x69\x6e\x63'
        b'\x69\x70\x6c\x65\x20\x6f\x66\x20\x41\x75\x67\x75\x73\x74\x65\x20'
        b'\x4b\x65\x72\x63\x6b\x68\x6f\x66\x66\x73'
    )

    ciphertext = (
        b'\xc8\x0e\xdf\xa3\x2d\xdf\x39\xd5\xef\x00\xc0\xb4\x68\x83\x42\x79'
        b'\xa2\xe4\x6a\x1b\x80\x49\xf7\x92\xf7\x6b\xfe\x54\xb9\x03\xa9\xc9'
        b'\xa9\x4a\xc9\xb4\x7a\xd2\x65\x5c\x5f\x10\xf9\xae\xf7\x14\x27\xe2'
        b'\xfc\x6f\x9b\x3f\x39\x9a\x22\x14\x89\xf1\x63\x62\xc7\x03\x23\x36'
        b'\x09\xd4\x5a\xc6\x98\x64\xe3\x32\x1c\xf8\x29\x35\xac\x40\x96\xc8'
        b'\x6e\x13\x33\x14\xc5\x40\x19\xe8\xca\x79\x80\xdf\xa4\xb9\xcf\x1b'
        b'\x38\x4c\x48\x6f\x3a\x54\xc5\x10\x78\x15\x8e\xe5\xd7\x9d\xe5\x9f'
        b'\xbd\x34\xd8\x48\xb3\xd6\x95\x50\xa6\x76\x46\x34\x44\x27\xad\xe5'
        b'\x4b\x88\x51\xff\xb5\x98\xf7\xf8\x00\x74\xb9\x47\x3c\x82\xe2\xdb'
    )

    auth_token = (
        b'\x65\x2c\x3f\xa3\x6b\x0a\x7c\x5b\x32\x19\xfa\xb3\xa3\x0b\xc1\xc4'
    )


class Test_A192CBC_HS384(AES_CBC_HMAC_SHA2_Base):
    algorithm = A192CBC_HS384

    key = (
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
        b'\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f'
    )

    plaintext = (
        b'\x41\x20\x63\x69\x70\x68\x65\x72\x20\x73\x79\x73\x74\x65\x6d\x20'
        b'\x6d\x75\x73\x74\x20\x6e\x6f\x74\x20\x62\x65\x20\x72\x65\x71\x75'
        b'\x69\x72\x65\x64\x20\x74\x6f\x20\x62\x65\x20\x73\x65\x63\x72\x65'
        b'\x74\x2c\x20\x61\x6e\x64\x20\x69\x74\x20\x6d\x75\x73\x74\x20\x62'
        b'\x65\x20\x61\x62\x6c\x65\x20\x74\x6f\x20\x66\x61\x6c\x6c\x20\x69'
        b'\x6e\x74\x6f\x20\x74\x68\x65\x20\x68\x61\x6e\x64\x73\x20\x6f\x66'
        b'\x20\x74\x68\x65\x20\x65\x6e\x65\x6d\x79\x20\x77\x69\x74\x68\x6f'
        b'\x75\x74\x20\x69\x6e\x63\x6f\x6e\x76\x65\x6e\x69\x65\x6e\x63\x65'
    )

    iv = (
        b'\x1a\xf3\x8c\x2d\xc2\xb9\x6f\xfd\xd8\x66\x94\x09\x23\x41\xbc\x04'
    )

    adata = (
        b'\x54\x68\x65\x20\x73\x65\x63\x6f\x6e\x64\x20\x70\x72\x69\x6e\x63'
        b'\x69\x70\x6c\x65\x20\x6f\x66\x20\x41\x75\x67\x75\x73\x74\x65\x20'
        b'\x4b\x65\x72\x63\x6b\x68\x6f\x66\x66\x73'
    )

    ciphertext = (
        b'\xea\x65\xda\x6b\x59\xe6\x1e\xdb\x41\x9b\xe6\x2d\x19\x71\x2a\xe5'
        b'\xd3\x03\xee\xb5\x00\x52\xd0\xdf\xd6\x69\x7f\x77\x22\x4c\x8e\xdb'
        b'\x00\x0d\x27\x9b\xdc\x14\xc1\x07\x26\x54\xbd\x30\x94\x42\x30\xc6'
        b'\x57\xbe\xd4\xca\x0c\x9f\x4a\x84\x66\xf2\x2b\x22\x6d\x17\x46\x21'
        b'\x4b\xf8\xcf\xc2\x40\x0a\xdd\x9f\x51\x26\xe4\x79\x66\x3f\xc9\x0b'
        b'\x3b\xed\x78\x7a\x2f\x0f\xfc\xbf\x39\x04\xbe\x2a\x64\x1d\x5c\x21'
        b'\x05\xbf\xe5\x91\xba\xe2\x3b\x1d\x74\x49\xe5\x32\xee\xf6\x0a\x9a'
        b'\xc8\xbb\x6c\x6b\x01\xd3\x5d\x49\x78\x7b\xcd\x57\xef\x48\x49\x27'
        b'\xf2\x80\xad\xc9\x1a\xc0\xc4\xe7\x9c\x7b\x11\xef\xc6\x00\x54\xe3'
    )

    auth_token = (
        b'\x84\x90\xac\x0e\x58\x94\x9b\xfe\x51\x87\x5d\x73\x3f\x93\xac\x20'
        b'\x75\x16\x80\x39\xcc\xc7\x33\xd7'
    )


class Test_A256CBC_HS512(AES_CBC_HMAC_SHA2_Base):
    algorithm = A256CBC_HS512

    key = (
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
        b'\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f'
        b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f'
    )
    plaintext = (
        b'\x41\x20\x63\x69\x70\x68\x65\x72\x20\x73\x79\x73\x74\x65\x6d\x20'
        b'\x6d\x75\x73\x74\x20\x6e\x6f\x74\x20\x62\x65\x20\x72\x65\x71\x75'
        b'\x69\x72\x65\x64\x20\x74\x6f\x20\x62\x65\x20\x73\x65\x63\x72\x65'
        b'\x74\x2c\x20\x61\x6e\x64\x20\x69\x74\x20\x6d\x75\x73\x74\x20\x62'
        b'\x65\x20\x61\x62\x6c\x65\x20\x74\x6f\x20\x66\x61\x6c\x6c\x20\x69'
        b'\x6e\x74\x6f\x20\x74\x68\x65\x20\x68\x61\x6e\x64\x73\x20\x6f\x66'
        b'\x20\x74\x68\x65\x20\x65\x6e\x65\x6d\x79\x20\x77\x69\x74\x68\x6f'
        b'\x75\x74\x20\x69\x6e\x63\x6f\x6e\x76\x65\x6e\x69\x65\x6e\x63\x65'
    )

    iv = (
        b'\x1a\xf3\x8c\x2d\xc2\xb9\x6f\xfd\xd8\x66\x94\x09\x23\x41\xbc\x04'
    )

    adata = (
        b'\x54\x68\x65\x20\x73\x65\x63\x6f\x6e\x64\x20\x70\x72\x69\x6e\x63'
        b'\x69\x70\x6c\x65\x20\x6f\x66\x20\x41\x75\x67\x75\x73\x74\x65\x20'
        b'\x4b\x65\x72\x63\x6b\x68\x6f\x66\x66\x73'
    )

    ciphertext = (
        b'\x4a\xff\xaa\xad\xb7\x8c\x31\xc5\xda\x4b\x1b\x59\x0d\x10\xff\xbd'
        b'\x3d\xd8\xd5\xd3\x02\x42\x35\x26\x91\x2d\xa0\x37\xec\xbc\xc7\xbd'
        b'\x82\x2c\x30\x1d\xd6\x7c\x37\x3b\xcc\xb5\x84\xad\x3e\x92\x79\xc2'
        b'\xe6\xd1\x2a\x13\x74\xb7\x7f\x07\x75\x53\xdf\x82\x94\x10\x44\x6b'
        b'\x36\xeb\xd9\x70\x66\x29\x6a\xe6\x42\x7e\xa7\x5c\x2e\x08\x46\xa1'
        b'\x1a\x09\xcc\xf5\x37\x0d\xc8\x0b\xfe\xcb\xad\x28\xc7\x3f\x09\xb3'
        b'\xa3\xb7\x5e\x66\x2a\x25\x94\x41\x0a\xe4\x96\xb2\xe2\xe6\x60\x9e'
        b'\x31\xe6\xe0\x2c\xc8\x37\xf0\x53\xd2\x1f\x37\xff\x4f\x51\x95\x0b'
        b'\xbe\x26\x38\xd0\x9d\xd7\xa4\x93\x09\x30\x80\x6d\x07\x03\xb1\xf6'
    )

    auth_token = (
        b'\x4d\xd3\xb4\xc0\x88\xa7\xf4\x5c\x21\x68\x39\x64\x5b\x20\x12\xbf'
        b'\x2e\x62\x69\xa8\xc5\x6a\x81\x6d\xbc\x1b\x26\x77\x61\x95\x5b\xc5'
    )


def load_tests(loader, standard_tests, pattern):
    return unittest.TestSuite((
        loader.loadTestsFromTestCase(Test_A128CBC_HS256),
        loader.loadTestsFromTestCase(Test_A192CBC_HS384),
        loader.loadTestsFromTestCase(Test_A256CBC_HS512),
    ))
