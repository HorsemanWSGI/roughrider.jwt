import pytest
import datetime
from freezegun import freeze_time
from roughrider.jwt.factory import JWTFactory
from cryptojwt.key_jar import KeyJar
from roughrider.token.meta import EncryptedTokenFactory


JWK0 = {
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "abc",
            "n": "wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY"
            "2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfK"
            "qoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8",
        }
    ]
}


def test_new_jar():
    factory = JWTFactory.new_jar()
    assert isinstance(factory, EncryptedTokenFactory)


def test_jwks_jar():
    factory = JWTFactory.from_jwks(JWK0)
    assert isinstance(factory, EncryptedTokenFactory)


def test_no_lifetime():
    factory = JWTFactory.new_jar()

    with freeze_time(datetime.datetime(2021, 4, 19, 20, 30, 00)):
        token = factory.generate({'value': 'foo'})

    with freeze_time(datetime.datetime(2031, 12, 24, 23, 59, 59)):
        factory.decrypt(token)


def test_lifetime():
    from roughrider.token.errors import ExpiredToken

    factory = JWTFactory.new_jar(lifetime=3600)

    with freeze_time(datetime.datetime(2021, 4, 19, 20, 30, 00)):
        token = factory.generate({'value': 'foo'})

    with freeze_time(datetime.datetime(2021, 4, 19, 23, 30, 00)):
        with pytest.raises(ExpiredToken):
            factory.decrypt(token)
