'''
    flask-HMAC
    ----------

    Use HMAC tokens and a decorator to authenticate access to routes
'''

# Standard Libs
import base64
import binascii
import hashlib
import hmac
import re
from functools import wraps

# Third Party Libs
import six
from flask import abort, request

from .exceptions import InvalidSignature, SecretKeyIsNotSet, UnknownKeyName


def encode_string(value):
    """ Encode unicode to string: unicode -> str, str -> str
    Arguments:
        value (str/unicode): string to encode
    Returns:
        encoded value (string)
    """
    return value.encode('utf-8') if isinstance(value, six.text_type) else value


def decode_string(value):
    """ Decode string: bytes -> str, str -> str
    Arguments:
        value (bytes/str): string to decode
    Returns:
        decoded value (strings)
    """
    return value if isinstance(value, six.string_types) else value.decode('utf-8')


class Hmac(object):

    def __init__(self, app=None, header=None, digestmod=None):
        self.header = header or 'Signature'
        self.digestmod = digestmod or hashlib.sha256
        if app:
            self.init_app(app)

    def extract_signature_from_header(self, request):
        return request.headers[self.header]

    def get_signature(self, request):
        try:
            return six.b(self.extract_signature_from_header(request))
        except KeyError:
            raise SecretKeyIsNotSet()

    def init_app(self, app):
        self.hmac_key = app.config.get('HMAC_KEY', None)
        self.hmac_keys = app.config.get('HMAC_KEYS', None)
        self.hmac_disarm = app.config.get('HMAC_DISARM', False)
        self.hmac_error_code = app.config.get('HMAC_ERROR_CODE', six.moves.http_client.FORBIDDEN)

    def auth(self, only=None):
        ''' Route decorator. Validates an incoming request can access the
        route function.

        Keyword Args:
            only (list): Optional list of clients that can access the view

        .. sourcecode:: python

            @app.route("/hmac_auth_view")
            @hmac.auth() # decorate view
            def hmac_auth_view():
                return "hmac_auth_view"

        .. sourcecode:: python

            @app.route("/hmac_auth_view")
            @hmac.auth(only=["foo"])  # decorate view
            def hmac_auth_view():
                return "hmac_auth_view"

        '''

        def real_decorator(route):
            @wraps(route)
            def decorated_view_function(*args, **kwargs):
                try:
                    self.validate_signature(request, only=only)
                except (SecretKeyIsNotSet, InvalidSignature):
                    return self.abort()
                return route(*args, **kwargs)
            return decorated_view_function
        return real_decorator

    def abort(self):
        abort(self.hmac_error_code)

    def _hmac_factory(self, data, key=None):
        key = key if key else self.hmac_key
        return hmac.new(six.b(key), data, digestmod=self.digestmod)

    def make_hmac(self, data='', key=None):
        hmac_token_server = self._hmac_factory(encode_string(data), key).digest()
        hmac_token_server = base64.b64encode(hmac_token_server)
        return hmac_token_server

    def make_hmac_for(self, name, data=''):
        ''' Generates HMAC key for named key
        Arguments:
            name (str): key name from HMAC_SECRETS dict
            data (str): HMAC message
        '''
        try:
            key = self.hmac_keys[name]
        except KeyError as ex:
            raise UnknownKeyName(ex)
        valuekey = '{0}:{1}'.format(name, decode_string(self.make_hmac(data, key)))
        token = base64.b64encode(six.b(valuekey))
        return token

    def _parse_multiple_signature(self, signature):
        try:
            valuekey = base64.urlsafe_b64decode(encode_string(signature))
            return decode_string(valuekey).split(':')
        except (TypeError, binascii.Error):
            raise InvalidSignature()

    def get_hmac_data(self, request):
        ''' Gets Message component for HMAC. Override for custom data component from request.
        Arguments:
            request (Request): flask request object
        '''
        return request.data

    def validate_signature(self, request, only=None):
        '''Validates a requests HMAC Signature against one generated server side
        from the same client secret key.

        Arguments:
            request (Request): flask request

        Raise:
            InvalidSignature: when signatures don't match
        '''

        if self.hmac_disarm:
            return

        signature = self.get_signature(request)
        hmac_server_tokens = []

        if self.hmac_key is not None:
            token = self.make_hmac(self.get_hmac_data(request))
            hmac_server_tokens.append(token)

        if self.hmac_keys is not None:
            try:
                client, sig = self._parse_multiple_signature(signature)
                if only is not None:
                    if client in only:
                        token = self.make_hmac_for(client, self.get_hmac_data(request))
                        hmac_server_tokens.append(token)
                else:
                    token = self.make_hmac_for(client, self.get_hmac_data(request))
                    hmac_server_tokens.append(token)
            except ValueError:
                # We fall here if the signature does is not vlaid on it's own
                # and does not contain a client id - we don't care since the
                # token will not be added to the list of keys to validate the
                # signature against
                pass

        if signature not in hmac_server_tokens:
            raise InvalidSignature

def sha256_hash_and_encode(data):
    algo = hashlib.sha256()
    algo.update(data)

    hashed = algo.digest()
    encoded = base64.b64encode(hashed)
    return encoded


class IETFHmac(Hmac):
    """
    Implements the format described in https://tools.ietf.org/html/draft-cavage-http-signatures-10#section-4.1.2

    Ignores 'algorithm' field.
    Can restrict 'keyId' to value provided in constructor; otherwhise ignored

    Can also validate request body using the 'Digest' header

    Example:
    Signature: keyId="hmac-key-1",algorithm="hmac-sha256",
        headers="host date digest content-length",
        signature="Base64(HMAC-SHA256(signing string))"
    """

    # TODO: support more algorithms
    DIGEST_ALGORITHMS = {'sha-256': sha256_hash_and_encode}

    SIGNATURE_PATTERNS = {
        'key_id': re.compile(r'keyId="([a-zA-Z0-9-_]+)"'),
        'algorithm': re.compile(r'algorithm="([a-zA-Z0-9\-_]+)"'),
        'headers': re.compile(r'headers="([A-Za-z\-0-9 ]+)"'),
        'signature': re.compile(r'signature="([a-zA-Z0-9/=+]+)"')
    }


    def __init__(self, app=None, header=None, digestmod=None, key_id=None, validate_digest=False):
        super().__init__(app, header, digestmod)
        # TODO: support list of accepted key_id values
        self.key_id = key_id
        self.validate_digest = validate_digest

    def _parse_signature(self, signature):
        # FIXME: implement this
        if '(request-target)' in signature:
            raise NotImplementedError
        patterns = self.__class__.SIGNATURE_PATTERNS

        parts = signature.split(',')
        if len(parts) != 4:
            raise InvalidSignature

        parsed = {}
        for part in parts:
            matched = list(filter(lambda match: match[1] is not None,
                                  map(lambda pattern: (pattern, patterns[pattern].fullmatch(part)),
                                      patterns.keys())))
            if len(matched) == 1:
                key, match = matched[0]
                parsed[key] = match.group(1)

        if len(parsed.keys()) != 4:
           raise InvalidSignature

        if self.key_id is not None and parsed['key_id'] != self.key_id:
            raise InvalidSignature

        return parsed['headers'], parsed['signature']

    def extract_signature_from_header(self, request):
        header = request.headers[self.header]
        _, signature = self._parse_signature(header)
        return signature

    def get_hmac_data(self, request):
        headers, _ = self._parse_signature(request.headers[self.header])

        data = ''

        for i, header_name in enumerate(headers):
            header_values = request.headers.get_all(header_name)
            if len(header_values) > 0:
                header_values_string = ', '.join(header_values)
                header_values_string = header_values_string.strip()
                data += f'{header_name.lower()}: {header_values_string}'
                if i != len(headers) - 1:
                    data += '\n'
        return data

    def _validate_digest(self, digest_header, data):
            digests = digest_header.split(',')
            for digest in digests:
                algorithm, expected_value = digest.split('=', maxsplit=1)
                print(algorithm, expected_value)
                algorithm = algorithm.lower()
                if algorithm not in self.__class__.DIGEST_ALGORITHMS:
                    raise NotImplementedError
                computed_value = self.__class__.DIGEST_ALGORITHMS[algorithm](data)
                return bytes.decode(computed_value) == expected_value

    def validate_signature(self, request, only=None):
        if self.validate_digest:
            if 'Digest' not in request.headers:
                raise InvalidSignature

            digests = request.headers['Digest']
            passed_validation = self._validate_digest(digests, request.data)
            if not passed_validation:
                raise InvalidSignature

        return super().validate_signature(request, only)
