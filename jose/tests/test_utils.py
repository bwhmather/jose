import unittest

from base64 import b64encode
from jose.utils import pad_pkcs7, unpad_pkcs7, b64encode_url, b64decode_url


class TestUtils(unittest.TestCase):
    def test_pad_pkcs7(self):
        self.assertEqual(
            pad_pkcs7(b'xxxx', 8),
            b'xxxx\x04\x04\x04\x04'
        )
        self.assertEqual(
            pad_pkcs7(b'xxxxxxxx', 8),
            b'xxxxxxxx\x08\x08\x08\x08\x08\x08\x08\x08')

    def test_unpad_pkcs7(self):
        self.assertEqual(
            unpad_pkcs7(b'xxxx\x04\x04\x04\x04'),
            b'xxxx'
        )
        self.assertEqual(
            unpad_pkcs7(b'xxxxxxxx\x08\x08\x08\x08\x08\x08\x08\x08'),
            b'xxxxxxxx'
        )
        self.assertRaises(
            Exception,
            unpad_pkcs7, b'xxxxxxxx\x04'
        )

    def test_b64encode_url_utf8(self):
        istr = 'eric idle'.encode('utf8')
        encoded = b64encode_url(istr)
        self.assertEqual(b64decode_url(encoded), istr)

    def test_b64encode_url_ascii(self):
        istr = b'eric idle'
        encoded = b64encode_url(istr)
        self.assertEqual(b64decode_url(encoded), istr)

    def test_b64encode_url(self):
        istr = b'{"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}'

        # sanity check
        self.assertTrue(b64encode(istr).endswith(b'='))

        # actual test
        self.assertFalse(b64encode_url(istr).endswith('='))
