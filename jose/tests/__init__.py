from __future__ import absolute_import

import unittest

import jose
import jose.exceptions as jse
from . import test_jwe, test_jws, test_utils, test_content_encryption

class TestSerializeDeserialize(unittest.TestCase):
    def test_serialize(self):
        try:
            jose.deserialize_compact('1.2.3.4')
            self.fail()
        except jse.Error as e:
            self.assertEqual(str(e), 'Malformed JWT')


loader = unittest.TestLoader()
suite = unittest.TestSuite((
    loader.loadTestsFromTestCase(TestSerializeDeserialize),
    loader.loadTestsFromModule(test_jwe),
    loader.loadTestsFromModule(test_jws),
    loader.loadTestsFromModule(test_utils),
    loader.loadTestsFromModule(test_content_encryption),
))
