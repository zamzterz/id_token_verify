from io import StringIO
from urllib.parse import urlencode

from oic.oic.message import IdToken

from id_token_verify.service import app


def assert_successful_response(status, headers):
    assert status == '200 OK'
    assert headers == [('Content-Type', 'application/json')]


def assert_wrong_http_method_response(status, headers):
    assert status == '405 Not Allowed'
    assert headers == [('Content-Type', 'text/plain')]


def test_service(id_token):
    jwt = id_token.to_jwt()
    data = urlencode({'token': jwt})
    environ = {'REQUEST_METHOD': 'POST', 'CONTENT_LENGTH': len(data), 'wsgi.input': StringIO(data)}
    result = app(environ, assert_successful_response)
    assert IdToken().from_json(result[0].decode("utf-8")) == id_token


def test_wrong_http_method():
    environ = {'REQUEST_METHOD': 'GET'}
    app(environ, assert_wrong_http_method_response)
