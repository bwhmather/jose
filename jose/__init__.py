import logging
logger = logging.getLogger(__name__)

try:
    from cjson import encode as json_encode, decode as json_decode
except ImportError:  # pragma: nocover
    logger.warn('cjson not found, falling back to stdlib json')
    from json import loads as json_decode, dumps as json_encode

import zlib
import datetime

from base64 import urlsafe_b64encode, urlsafe_b64decode
import binascii
from collections import namedtuple
from time import time

from Crypto.Random import get_random_bytes

from jose import algorithms


try:
    # python 2 compatibility
    unicode
except NameError:
    unicode = str


__all__ = ['encrypt', 'decrypt', 'sign', 'verify']


# XXX: The attribute order is IMPORTANT in the following namedtuple
# definitions. DO NOT change them, unless you really know what you're doing.

JWE = namedtuple('JWE',
    'header '
    'cek '
    'iv '
    'ciphertext '
    'tag ')

JWS = namedtuple('JWS',
        'header '
        'payload '
        'signature ')

JWT = namedtuple('JWT',
        'header '
        'claims ')


CLAIM_ISSUER = 'iss'
CLAIM_SUBJECT = 'sub'
CLAIM_AUDIENCE = 'aud'
CLAIM_EXPIRATION_TIME = 'exp'
CLAIM_NOT_BEFORE = 'nbf'
CLAIM_ISSUED_AT = 'iat'
CLAIM_JWT_ID = 'jti'


class Error(Exception):
    """ The base error type raised by jose
    """
    pass


class Expired(Error):
    """ Raised during claims validation if a JWT has expired
    """
    pass


class NotYetValid(Error):
    """ Raised during claims validation is a JWT is not yet valid
    """
    pass


def serialize_compact(jwt):
    """ Compact serialization of a :class:`~jose.JWE` or :class:`~jose.JWS`

    :rtype: str
    :returns: A string, representing the compact serialization of a
              :class:`~jose.JWE` or :class:`~jose.JWS`.
    """
    return '.'.join(jwt)


def deserialize_compact(jwt):
    """ Deserialization of a compact representation of a :class:`~jwt.JWE`

    :param jwt: The serialized JWT to deserialize.
    :rtype: :class:`~jose.JWT`.
    :raises: :class:`~jose.Error` if the JWT is malformed
    """
    parts = jwt.split('.')

    # http://tools.ietf.org/html/
    # draft-ietf-jose-json-web-encryption-23#section-9
    if len(parts) == 3:
        token_type = JWS
    elif len(parts) == 5:
        token_type = JWE
    else:
        raise Error('Malformed JWT')

    return token_type(*parts)


def encrypt(claims, jwk, adata='', add_header=None, alg='RSA-OAEP',
        enc='A128CBC-HS256', rng=get_random_bytes, compression=None):
    """ Encrypts the given claims and produces a :class:`~jose.JWE`

    :param claims: A `dict` representing the claims for this
                   :class:`~jose.JWE`.
    :param jwk: A `dict` representing the JWK to be used for encryption of
                the CEK. This parameter is algorithm-specific.
    :param adata: Arbitrary string data to add to the authentication
                  (i.e. HMAC). The same data must be provided during
                  decryption.
    :param add_header: Additional items to be added to the header. Additional
                       headers *will* be authenticated.
    :param alg: The algorithm to use for CEK encryption
    :param enc: The algorithm to use for claims encryption
    :param rng: Random number generator. A string of random bytes is expected
                as output.
    :param compression: The compression algorithm to use. Currently supports
                `'DEF'`.
    :rtype: :class:`~jose.JWE`
    :raises: :class:`~jose.Error` if there is an error producing the JWE
    """

    header = {}

    if add_header:
        header.update(add_header)

    header.update({
        'enc': enc,
        'alg': alg,
    })

    plaintext = json_encode(claims).encode('utf-8')

    # compress (if required)
    if compression is not None:
        header['zip'] = compression
        try:
            (compress, _) = COMPRESSION[compression]
        except KeyError:
            raise Error(
                'Unsupported compression algorithm: {}'.format(compression))
        plaintext = compress(plaintext)

    if not isinstance(adata, bytes):
        # TODO this should probably just be an error
        adata = adata.encode('utf-8')

    # body encryption/hash
    content_algorithm = algorithms.content_encryption.from_name(header['enc'])

    content_iv = content_algorithm.generate_iv()
    content_key = content_algorithm.generate_key()

    ciphertext, auth_token = content_algorithm(content_key).encrypt(
        plaintext, iv=content_iv, adata=adata
    )

    # cek encryption
    key_algorithm = algorithms.key_encryption.from_name(header['alg'])
    wrapped_content_key = key_algorithm(jwk).encrypt(content_key)

    return JWE(*list(map(b64encode_url,
            (json_encode(header).encode('utf-8'),
            wrapped_content_key,
            content_iv,
            ciphertext,
            auth_token))))


def decrypt(jwe, jwk, adata=b'', validate_claims=True, expiry_seconds=None):
    """ Decrypts a deserialized :class:`~jose.JWE`

    :param jwe: An instance of :class:`~jose.JWE`
    :param jwk: A `dict` representing the JWK required to decrypt the content
                of the :class:`~jose.JWE`.
    :param adata: Arbitrary string data used during encryption for additional
                  authentication.
    :param validate_claims: A `bool` indicating whether or not the `exp`, `iat`
                            and `nbf` claims should be validated. Defaults to
                            `True`.
    :param expiry_seconds: An `int` containing the JWT expiry in seconds, used
                           when evaluating the `iat` claim. Defaults to `None`,
                           which disables `iat` claim validation.
    :rtype: :class:`~jose.JWT`
    :raises: :class:`~jose.Expired` if the JWT has expired
    :raises: :class:`~jose.NotYetValid` if the JWT is not yet valid
    :raises: :class:`~jose.Error` if there is an error decrypting the JWE
    """
    header, wrapped_content_key, iv, ciphertext, tag = map(
        b64decode_url, jwe)
    header = json_decode(header.decode('utf-8'))

    if not isinstance(adata, bytes):
        # TODO this should probably just be an error
        adata = adata.encode('utf-8')

    # decrypt cek
    key_algorithm = algorithms.key_encryption.from_name(header['alg'])
    content_key = key_algorithm(jwk).decrypt(wrapped_content_key)

    # decrypt body
    content_algorithm = algorithms.content_encryption.from_name(header['enc'])

    plaintext = content_algorithm(content_key).decrypt(
        ciphertext, auth_token=tag, iv=iv, adata=adata
    )

    if 'zip' in header:
        try:
            (_, decompress) = COMPRESSION[header['zip']]
        except KeyError:
            raise Error('Unsupported compression algorithm: {}'.format(
                header['zip']))

        plaintext = decompress(plaintext)

    claims = json_decode(plaintext.decode('utf-8'))
    _validate(claims, validate_claims, expiry_seconds)

    return JWT(header, claims)


def sign(claims, jwk, add_header=None, alg='HS256'):
    """ Signs the given claims and produces a :class:`~jose.JWS`

    :param claims: A `dict` representing the claims for this
                   :class:`~jose.JWS`.
    :param jwk: A `dict` representing the JWK to be used for signing of the
                :class:`~jose.JWS`. This parameter is algorithm-specific.
    :parameter add_header: Additional items to be added to the header.
                           Additional headers *will* be authenticated.
    :parameter alg: The algorithm to use to produce the signature.
    :rtype: :class:`~jose.JWS`
    """
    try:
        sign_fn, verify_fn = algorithms.signing.from_name(alg)
    except KeyError:
        sign_fn, verify_fn = algorithms.mac.from_name(alg)

    header = {}

    if add_header:
        header.update(add_header)

    header.update({
        'alg': alg,
    })

    header = b64encode_url(json_encode(header).encode('utf-8'))
    payload = b64encode_url(json_encode(claims).encode('utf-8'))

    sig = b64encode_url(sign_fn(_jws_hash_str(header, payload), jwk['k']))

    return JWS(header, payload, sig)


def verify(jws, jwk, validate_claims=True, expiry_seconds=None):
    """ Verifies the given :class:`~jose.JWS`

    :param jws: The :class:`~jose.JWS` to be verified.
    :param jwk: A `dict` representing the JWK to use for verification. This
                parameter is algorithm-specific.
    :param validate_claims: A `bool` indicating whether or not the `exp`, `iat`
                            and `nbf` claims should be validated. Defaults to
                            `True`.
    :param expiry_seconds: An `int` containing the JWT expiry in seconds, used
                           when evaluating the `iat` claim. Defaults to `None`,
                           which disables `iat` claim validation.
    :rtype: :class:`~jose.JWT`
    :raises: :class:`~jose.Expired` if the JWT has expired
    :raises: :class:`~jose.NotYetValid` if the JWT is not yet valid
    :raises: :class:`~jose.Error` if there is an error decrypting the JWE
    """
    header, payload, sig = map(b64decode_url, jws)
    header = json_decode(header.decode('utf-8'))
    try:
        sign_fn, verify_fn = algorithms.signing.from_name(header['alg'])
    except KeyError:
        sign_fn, verify_fn = algorithms.mac.from_name(header['alg'])

    if not verify_fn(_jws_hash_str(jws.header, jws.payload), jwk['k'], sig):
        raise Error('Mismatched signatures')

    claims = json_decode(b64decode_url(jws.payload).decode('utf-8'))
    _validate(claims, validate_claims, expiry_seconds)

    return JWT(header, claims)


def b64decode_url(istr):
    """ JWT Tokens may be truncated without the usual trailing padding '='
        symbols. Compensate by padding to the nearest 4 bytes.

    :param istr: A unicode string to decode
    :returns: The byte string represented by `istr`
    """
    # unicode check for python 2 compatibility
    if not isinstance(istr, (str, unicode)):
        raise ValueError("expected string, got %r" % type(istr))

    # required for python 2 as urlsafe_b64decode does not like unicode objects
    # safe as b64 encoded string should be only ascii anyway
    istr = str(istr)

    try:
        return urlsafe_b64decode(istr + '=' * (4 - (len(istr) % 4)))
    except (TypeError, binascii.Error) as e:
        raise Error('Unable to decode base64: %s' % (e))


def b64encode_url(istr):
    """ JWT Tokens may be truncated without the usual trailing padding '='
        symbols. Compensate by padding to the nearest 4 bytes.

    :param istr: a byte string to encode
    :returns: The base64 representation of the input byte string as a regular
        `str` object
    """
    if not isinstance(istr, bytes):
        raise Exception("expected bytestring")
    return urlsafe_b64encode(istr).rstrip(b'=').decode('ascii')


COMPRESSION = {
    'DEF': (zlib.compress, zlib.decompress),
}


def _format_timestamp(ts):
    dt = datetime.datetime.utcfromtimestamp(ts)
    return dt.isoformat() + 'Z'


def _check_expiration_time(now, expiration_time):
    # Token is valid when nbf <= now < exp
    if now >= expiration_time:
        raise Expired('Token expired at {}'.format(
            _format_timestamp(expiration_time))
        )


def _check_not_before(now, not_before):
    # Token is valid when nbf <= now < exp
    if not_before > now:
        raise NotYetValid('Token not valid until {}'.format(
            _format_timestamp(not_before))
        )


def _validate(claims, validate_claims, expiry_seconds):
    """ Validate expiry related claims.

    If validate_claims is False, do nothing.

    Otherwise, validate the exp and nbf claims if they are present, and
    validate the iat claim if expiry_seconds is provided.
    """
    if not validate_claims:
        return

    now = time()

    # TODO: implement support for clock skew

    # The exp (expiration time) claim identifies the expiration time on or
    # after which the JWT MUST NOT be accepted for processing. The
    # processing of the exp claim requires that the current date/time MUST
    # be before the expiration date/time listed in the exp claim.
    try:
        expiration_time = claims[CLAIM_EXPIRATION_TIME]
    except KeyError:
        pass
    else:
        _check_expiration_time(now, expiration_time)

    # The iat (issued at) claim identifies the time at which the JWT was
    # issued. This claim can be used to determine the age of the JWT.
    # If expiry_seconds is provided, and the iat claims is present,
    # determine the age of the token and check if it has expired.
    try:
        issued_at = claims[CLAIM_ISSUED_AT]
    except KeyError:
        pass
    else:
        if expiry_seconds is not None:
            _check_expiration_time(now, issued_at + expiry_seconds)

    # The nbf (not before) claim identifies the time before which the JWT
    # MUST NOT be accepted for processing. The processing of the nbf claim
    # requires that the current date/time MUST be after or equal to the
    # not-before date/time listed in the nbf claim.
    try:
        not_before = claims[CLAIM_NOT_BEFORE]
    except KeyError:
        pass
    else:
        _check_not_before(now, not_before)


def _jwe_hash_str(plaintext, iv, adata=b''):
    # http://tools.ietf.org/html/
    # draft-ietf-jose-json-web-algorithms-24#section-5.2.2.1
    return b'.'.join((adata, iv, plaintext, bytes(len(adata))))


def _jws_hash_str(header, claims):
    return b'.'.join((header.encode('ascii'), claims.encode('ascii')))


def cli_decrypt(jwt, key):
    print(decrypt(deserialize_compact(jwt), {'k': key},
                  validate_claims=False))


def _cli():
    import inspect

    from argparse import ArgumentParser

    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest='subparser_name')

    commands = {
        'decrypt': cli_decrypt,
    }
    for k, fn in commands.items():
        p = subparsers.add_parser(k)
        for arg in inspect.getargspec(fn).args:
            p.add_argument(arg)

    args = parser.parse_args()
    handler = commands[args.subparser_name]
    handler_args = [getattr(args, k) for k in inspect.getargspec(
        handler).args]
    handler(*handler_args)
