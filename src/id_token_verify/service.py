import json
from urllib.parse import parse_qsl
from wsgiref.simple_server import make_server

from oic.utils.http_util import get_post

from id_token_verify.verify_id_token import verify, IDTokenVerificationError


def app(environ, start_response):
    if environ['REQUEST_METHOD'] != 'POST':
        start_response('405 Not Allowed', [('Content-Type', 'text/plain')])
        return ['Only POST is supported.'.encode('utf-8')]

    post_data = get_post(environ)
    parsed_data = dict(parse_qsl(post_data))

    start_response('200 OK', [('Content-Type', 'application/json')])
    try:
        verified_token = verify(**parsed_data)
    except IDTokenVerificationError as e:
        return [json.dumps({"error": str(e)}).encode('utf-8')]

    return [verified_token.encode('utf-8')]


if __name__ == '__main__':
    print("Starting ID Token verification server")
    httpd = make_server('localhost', 8999, app)
    httpd.serve_forever()
