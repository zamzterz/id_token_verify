# pylint: disable=no-member, missing-docstring

import json

from oic.oauth2 import rndstr

from oic.oic import OIDCONF_PATTERN
from oic.oic.message import IdToken
import pytest
from requests.exceptions import ConnectionError
import responses

from id_token_verify.verify_id_token import verify, IDTokenVerificationError
from conftest import ISSUER


@responses.activate
def test_verify_with_issuer_keys(id_token, rsa_key):
    jwks_uri = '{}/jwks_uri'.format(ISSUER)
    responses.add(responses.GET, OIDCONF_PATTERN % ISSUER,
                  json={'issuer': ISSUER, 'jwks_uri': jwks_uri}, status=200)
    responses.add(responses.GET, jwks_uri,
                  json={'keys': [rsa_key.serialize()]}, status=200)

    jwt = id_token.to_jwt([rsa_key], 'RS256')

    unpacked = verify(jwt)
    assert IdToken().from_json(unpacked) == id_token


def test_verify_with_provided_jwks(id_token, rsa_key):  # for provider not supporting discovery
    jwt = id_token.to_jwt([rsa_key], 'RS256')

    unpacked = verify(jwt, jwks=json.dumps({'keys': [rsa_key.serialize()]}))
    assert IdToken().from_json(unpacked) == id_token


def test_verify_unsigned_jwt(id_token):
    jwt = id_token.to_jwt()
    unpacked = verify(jwt)
    assert IdToken().from_json(unpacked) == id_token


def test_verify_jwt_signed_with_symmetric_key(id_token, sym_key):
    jwt = id_token.to_jwt([sym_key], 'HS256')

    unpacked = verify(jwt, key=sym_key.k)
    assert IdToken().from_json(unpacked) == id_token


def test_fail_verify_on_wrong_key_type(id_token, rsa_key):
    jwt = id_token.to_jwt([rsa_key], 'RS256')

    with pytest.raises(IDTokenVerificationError):
        verify(jwt, key=rndstr())  # pass random symmetric key and expect failure


def test_fail_verify_on_wrong_key(id_token, sym_key):
    jwt = id_token.to_jwt([sym_key], 'HS256')

    with pytest.raises(IDTokenVerificationError):
        verify(jwt, key=rndstr())  # pass random symmetric key and expect failure


def test_fail_on_symmetric_key_signature_but_key_not_provided(id_token, sym_key):
    jwt = id_token.to_jwt([sym_key], 'HS256')

    with pytest.raises(IDTokenVerificationError):
        verify(jwt)  # don't pass symmetric key


@responses.activate
def test_fail_when_cant_fetch_provider_jwks_uri(id_token, rsa_key):
    jwks_uri = '{}/jwks_uri'.format(ISSUER)
    responses.add(responses.GET, OIDCONF_PATTERN % ISSUER,
                  json={'issuer': ISSUER, 'jwks_uri': jwks_uri}, status=200)

    # fake ConnectionError for the jwks_uri endpoint
    responses.add(responses.GET, jwks_uri, body=ConnectionError('Error'))

    jwt = id_token.to_jwt([rsa_key], 'RS256')

    with pytest.raises(IDTokenVerificationError):
        verify(jwt)
