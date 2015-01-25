from __future__ import absolute_import

import unittest

from Crypto.PublicKey import RSA

import jose
import jose.exceptions as jse


rsa_key = RSA.generate(2048)

rsa_priv_key = {
    'k': rsa_key.exportKey('PEM'),
}
rsa_pub_key = {
    'k': rsa_key.publickey().exportKey('PEM'),
}

claims = {'john': 'cleese'}


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
        except jse.Error as e:
            self.assertEqual(str(e), 'Mismatched signatures')
