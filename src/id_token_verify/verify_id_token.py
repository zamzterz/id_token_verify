import json

from jwkest.jwk import SYMKey
from jwkest.jws import NoSuitableSigningKeys
from jwkest.jwt import JWT
from oic.oic import OIDCONF_PATTERN
from oic.oic.message import IdToken, ProviderConfigurationResponse
from oic.utils.keyio import KeyJar, KeyBundle
import requests


class IDTokenVerificationError(Exception):
    pass


def verify(token, key=None, jwks=None):
    jwt = JWT().unpack(token)
    payload = jwt.payload()
    issuer = payload['iss']
    provider_keys = None

    if key:
        provider_keys = KeyJar()
        key = SYMKey(use='sig', k=key)
        kb = KeyBundle(keytype='oct')
        kb.append(key)
        provider_keys[issuer] = [kb]
    elif jwks:
        provider_keys = _parse_provider_keys_from_jwks(issuer, jwks)
    elif jwt.headers['alg'] != 'none':  # don't fetch keys for unsigned JWT
        provider_keys = _fetch_provider_keys(issuer)

    try:
        return IdToken().from_jwt(token, keyjar=provider_keys).to_json()
    except NoSuitableSigningKeys as e:
        raise IDTokenVerificationError(
            'No key that could be used to verify the signature could be found.')


def _fetch_provider_keys(issuer):
    provider_config = ProviderConfigurationResponse(
        **requests.get(OIDCONF_PATTERN % issuer).json())
    assert issuer == provider_config['issuer']

    provider_keys = KeyJar()
    provider_keys.add(issuer, provider_config['jwks_uri'])
    return provider_keys


def _parse_provider_keys_from_jwks(issuer, jwks):
    keys = json.loads(jwks)['keys']
    provider_keys = KeyJar()
    provider_keys[issuer] = [KeyBundle(keys=keys)]
    return provider_keys
