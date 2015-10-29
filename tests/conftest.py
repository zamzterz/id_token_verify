import time

from Crypto.PublicKey import RSA
from jwkest.jwk import RSAKey, SYMKey
from oic.oauth2 import rndstr
from oic.oic.message import IdToken
from oic.utils.time_util import utc_time_sans_frac
import pytest

ISSUER = 'http://provider.example.org'


@pytest.fixture(scope='session')
def rsa_key():
    return RSAKey(use='sig', key=RSA.generate(2048))


@pytest.fixture(scope='session')
def sym_key():
    return SYMKey(use='sig', k=rndstr())


@pytest.fixture(scope='session')
def id_token():
    return IdToken(iss=ISSUER, sub='sub',
                   aud='client', exp=utc_time_sans_frac() + 86400,
                   nonce='N0nce',
                   iat=time.time())
