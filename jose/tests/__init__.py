import json
import unittest

from base64 import b64encode
from copy import copy
from itertools import product
from time import time

from Crypto.PublicKey import RSA

import jose
from jose.utils import pad_pkcs7, unpad_pkcs7
from jose.algorithms.content_encryption import A128CBC_HS256

rsa_key = RSA.generate(2048)

rsa_priv_key = {
    'k': rsa_key.exportKey('PEM'),
}
rsa_pub_key = {
    'k': rsa_key.publickey().exportKey('PEM'),
}

claims = {'john': 'cleese'}


class TestSerializeDeserialize(unittest.TestCase):
    def test_serialize(self):
        try:
            jose.deserialize_compact('1.2.3.4')
            self.fail()
        except jose.Error as e:
            self.assertEqual(str(e), 'Malformed JWT')


class TestJWE(unittest.TestCase):
    encs = ('A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512')
    algs = (('RSA-OAEP', rsa_key),)

    def test_jwe(self):
        bad_key = {'k': RSA.generate(2048).exportKey('PEM')}

        for (alg, jwk), enc in product(self.algs, self.encs):
            jwe = jose.encrypt(claims, rsa_pub_key, enc=enc, alg=alg)

            # make sure the body can't be loaded as json (should be encrypted)
            try:
                json.loads(jose.b64decode_url(jwe.ciphertext).decode('utf-8'))
                self.fail()
            except ValueError:
                pass

            token = jose.serialize_compact(jwe)

            jwt = jose.decrypt(jose.deserialize_compact(token), rsa_priv_key)

            self.assertEqual(jwt.claims, claims)

            # invalid key
            try:
                jose.decrypt(jose.deserialize_compact(token), bad_key)
                self.fail()
            except jose.Error as e:
                self.assertEqual(str(e), 'Incorrect decryption.')

    def test_jwe_add_header(self):
        add_header = {'foo': 'bar'}

        for (alg, jwk), enc in product(self.algs, self.encs):
            et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key,
                add_header=add_header))
            jwt = jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)

            self.assertEqual(jwt.header['foo'], add_header['foo'])

    def test_jwe_adata(self):
        adata = '42'
        for (alg, jwk), enc in product(self.algs, self.encs):
            et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key,
                adata=adata))
            jwt = jose.decrypt(jose.deserialize_compact(et), rsa_priv_key,
                    adata=adata)

            # make sure signaures don't match when adata isn't passed in
            try:
                hdr, dt = jose.decrypt(jose.deserialize_compact(et),
                    rsa_priv_key)
                self.fail()
            except jose.Error as e:
                self.assertEqual(str(e), 'Mismatched authentication tags')

            self.assertEqual(jwt.claims, claims)

    def test_jwe_invalid_base64(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        bad = '\x00' + et

        try:
            jose.decrypt(jose.deserialize_compact(bad), rsa_priv_key)
        except jose.Error as e:
            self.assertEqual(
                e.args[0],
                'Unable to decode base64: Incorrect padding'
            )
        else:
            self.fail()  # expecting error due to invalid base64

    def test_jwe_no_error_with_exp_claim(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) + 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)

    def test_jwe_expired_error_with_exp_claim(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)
        except jose.Expired as e:
            self.assertEqual(
                e.args[0],
                'Token expired at {}'.format(
                    jose._format_timestamp(claims[jose.CLAIM_EXPIRATION_TIME])
                )
            )
        else:
            self.fail()  # expecting expired token

    def test_jwe_no_error_with_iat_claim(self):
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        jose.decrypt(jose.deserialize_compact(et), rsa_priv_key,
            expiry_seconds=20)

    def test_jwe_expired_error_with_iat_claim(self):
        expiry_seconds = 10
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.decrypt(jose.deserialize_compact(et), rsa_priv_key,
                expiry_seconds=expiry_seconds)
        except jose.Expired as e:
            expiration_time = claims[jose.CLAIM_ISSUED_AT] + expiry_seconds
            self.assertEqual(
                e.args[0],
                'Token expired at {}'.format(
                    jose._format_timestamp(expiration_time)
                )
            )
        else:
            self.fail()  # expecting expired token

    def test_jwe_no_error_with_nbf_claim(self):
        claims = {jose.CLAIM_NOT_BEFORE: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)

    def test_jwe_not_yet_valid_error_with_nbf_claim(self):
        claims = {jose.CLAIM_NOT_BEFORE: int(time()) + 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)
        except jose.NotYetValid as e:
            self.assertEqual(
                e.args[0],
                'Token not valid until {}'.format(
                    jose._format_timestamp(claims[jose.CLAIM_NOT_BEFORE])
                )
            )
        else:
            self.fail()  # expecting not valid yet

    def test_jwe_ignores_expired_token_if_validate_claims_is_false(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.decrypt(jose.deserialize_compact(et), rsa_priv_key,
            validate_claims=False)

    def test_format_timestamp(self):
        self.assertEqual(
            jose._format_timestamp(1403054056),
            '2014-06-18T01:14:16Z'
        )

    def test_jwe_compression(self):
        local_claims = copy(claims)

        for v in range(1000):
            local_claims['dummy_' + str(v)] = '0' * 100

        jwe = jose.serialize_compact(jose.encrypt(local_claims, rsa_pub_key))
        _, _, _, uncompressed_ciphertext, _ = jwe.split('.')

        jwe = jose.serialize_compact(jose.encrypt(local_claims, rsa_pub_key,
            compression='DEF'))
        _, _, _, compressed_ciphertext, _ = jwe.split('.')

        self.assertTrue(len(compressed_ciphertext) <
                len(uncompressed_ciphertext))

        jwt = jose.decrypt(jose.deserialize_compact(jwe), rsa_priv_key)
        self.assertEqual(jwt.claims, local_claims)

    def test_encrypt_invalid_compression_error(self):
        try:
            jose.encrypt(claims, rsa_pub_key, compression='BAD')
        except jose.Error:
            pass
        else:
            self.fail()

    def test_decrypt_invalid_compression_error(self):
        jwe = jose.encrypt(claims, rsa_pub_key, compression='DEF')
        header = jose.b64encode_url(b'{"alg": "RSA-OAEP", '
            b'"enc": "A128CBC-HS256", "zip": "BAD"}')

        try:
            jose.decrypt(jose.JWE(*((header,) + (jwe[1:]))), rsa_priv_key)
        except jose.Error as e:
            self.assertEqual(str(e),
                    'Unsupported compression algorithm: BAD')
        else:
            self.fail()


class TestJWS(unittest.TestCase):

    def test_jws_sym(self):
        algs = ('HS256', 'HS384', 'HS512',)
        jwk = {'k': 'password'}

        for alg in algs:
            st = jose.serialize_compact(jose.sign(claims, jwk, alg=alg))
            jwt = jose.verify(jose.deserialize_compact(st), jwk)

            self.assertEqual(jwt.claims, claims)

    def test_jws_asym(self):
        algs = ('RS256', 'RS384', 'RS512')

        for alg in algs:
            st = jose.serialize_compact(jose.sign(claims, rsa_priv_key,
                alg=alg))
            jwt = jose.verify(jose.deserialize_compact(st), rsa_pub_key)
            self.assertEqual(jwt.claims, claims)

    def test_jws_signature_mismatch_error(self):
        jwk = {'k': 'password'}
        jws = jose.sign(claims, jwk)
        try:
            jose.verify(jose.JWS(jws.header, jws.payload, 'asd'), jwk)
        except jose.Error as e:
            self.assertEqual(str(e), 'Mismatched signatures')


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
        encoded = jose.b64encode_url(istr)
        self.assertEqual(jose.b64decode_url(encoded), istr)

    def test_b64encode_url_ascii(self):
        istr = b'eric idle'
        encoded = jose.b64encode_url(istr)
        self.assertEqual(jose.b64decode_url(encoded), istr)

    def test_b64encode_url(self):
        istr = b'{"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}'

        # sanity check
        self.assertTrue(b64encode(istr).endswith(b'='))

        # actual test
        self.assertFalse(jose.b64encode_url(istr).endswith('='))


class AES_CBC_HMAC_SHA2_Base(unittest.TestCase):
    def test_jwe_test_case(self):
        encrypter = A128CBC_HS256(self.key)

        ciphertext, auth_token = encrypter.encrypt(
            self.plaintext, adata=self.adata, iv=self.iv
        )
        self.assertEqual(self.ciphertext, ciphertext)
        self.assertEqual(self.auth_token, auth_token)


class Test_A128CBC_HS256(AES_CBC_HMAC_SHA2_Base):
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

    al = (
        b'\x00\x00\x00\x00\x00\x00\x01\x50'
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

    digest = (
        b'\x65\x2c\x3f\xa3\x6b\x0a\x7c\x5b\x32\x19\xfa\xb3\xa3\x0b\xc1\xc4'
        b'\xe6\xe5\x45\x82\x47\x65\x15\xf0\xad\x9f\x75\xa2\xb7\x1c\x73\xef'
    )

    auth_token = (
        b'\x65\x2c\x3f\xa3\x6b\x0a\x7c\x5b\x32\x19\xfa\xb3\xa3\x0b\xc1\xc4'
    )


class Test_A192CBC_HS384(AES_CBC_HMAC_SHA2_Base):
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


loader = unittest.TestLoader()
suite = unittest.TestSuite((
    loader.loadTestsFromTestCase(TestSerializeDeserialize),
    loader.loadTestsFromTestCase(TestJWE),
    loader.loadTestsFromTestCase(TestJWS),
    loader.loadTestsFromTestCase(TestUtils),
    loader.loadTestsFromTestCase(Test_A128CBC_HS256),
    loader.loadTestsFromTestCase(Test_A192CBC_HS384),
    loader.loadTestsFromTestCase(Test_A256CBC_HS512),
))
