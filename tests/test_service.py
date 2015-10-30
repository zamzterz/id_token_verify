from io import StringIO
import json
from urllib.parse import urlencode
from oic.oauth2 import rndstr

from oic.oic.message import IdToken

from id_token_verify.service import app


def assert_successful_response(status, headers):
    assert status == '200 OK'
    assert headers == [('Content-Type', 'application/json')]


def assert_wrong_http_method_response(status, headers):
    assert status == '405 Not Allowed'
    assert headers == [('Content-Type', 'text/plain')]


def test_service(id_token):
    data = urlencode({'token': id_token.to_jwt()})
    environ = {'REQUEST_METHOD': 'POST', 'CONTENT_LENGTH': len(data), 'wsgi.input': StringIO(data)}
    result = app(environ, assert_successful_response)
    assert IdToken().from_json(result[0].decode("utf-8")) == id_token


def test_wrong_http_method():
    environ = {'REQUEST_METHOD': 'GET'}
    app(environ, assert_wrong_http_method_response)


def test_wrong_signature(id_token, rsa_key):
    # sign with RSA key, but pass random symmetric key
    data = urlencode({'token': id_token.to_jwt([rsa_key], 'RS256'),
                      'key': rndstr()})

    environ = {'REQUEST_METHOD': 'POST', 'CONTENT_LENGTH': len(data), 'wsgi.input': StringIO(data)}
    result = app(environ, assert_successful_response)
    error_msg = json.loads(result[0].decode("utf-8"))
    assert 'error' in error_msg
