import pytest
import datetime
from freezegun import freeze_time
from roughrider.jwt.factory import EncryptedJWTFactory
from roughrider.token.meta import EncryptedTokenFactory


def test_new_keys():
    factory = EncryptedJWTFactory.new_keys()
    assert len(factory.key_jar.get_issuer_keys(factory.issuer_id)) == 2
    assert isinstance(factory, EncryptedTokenFactory)

    factory = EncryptedJWTFactory.new_keys(sign=False)
    assert len(factory.key_jar) == 1
    assert isinstance(factory, EncryptedTokenFactory)


def test_only_enc_key(jwks_enc_key):
    import cryptojwt.jws.exception

    factory = EncryptedJWTFactory(iss='Tester')
    factory.key_jar.load_keys('Tester', jwks=jwks_enc_key)
    with pytest.raises(cryptojwt.jws.exception.NoSuitableSigningKeys):
        factory.generate({'value': 'foo'})

    factory = EncryptedJWTFactory(iss='Tester', sign=False)
    factory.key_jar.load_keys('Tester', jwks=jwks_enc_key)
    token = factory.generate({'value': 'foo'})
    assert factory.decrypt(token) == {'value': 'foo'}


def test_no_lifetime():
    from roughrider.jwt.factory import MissingExpirationHeader

    factory = EncryptedJWTFactory.new_keys(iss='Christian')

    with freeze_time(datetime.datetime(2021, 4, 19, 20, 30, 00)):
        token = factory.generate({'value': 'foo'})

    with freeze_time(datetime.datetime(2031, 12, 24, 23, 59, 59)):
        assert factory.decrypt(token) == {'value': 'foo'}

    # Trying to decrypt a non-timestamped token with a timestamping
    # factory will produce an error.
    jwks = factory.key_jar.export_jwks(issuer_id='Christian', private=True)
    ttl_factory = EncryptedJWTFactory(iss='Christian', lifetime=3600)
    ttl_factory.key_jar.load_keys('Christian', jwks=jwks)

    with pytest.raises(MissingExpirationHeader):
        ttl_factory.decrypt(token)

    with freeze_time(datetime.datetime(2021, 4, 19, 20, 30, 00)):
        token = ttl_factory.generate({'value': 'foo'})
        assert ttl_factory.decrypt(token) == {'value': 'foo'}

    with freeze_time(datetime.datetime(2031, 12, 24, 23, 59, 59)):
        assert factory.decrypt(token) == {'value': 'foo'}


def test_lifetime():
    from roughrider.jwt.factory import NotYet
    from roughrider.token.errors import ExpiredToken, InvalidToken

    factory = EncryptedJWTFactory.new_keys(lifetime=3600)

    with freeze_time(datetime.datetime(2021, 4, 19, 20, 30, 00)):
        token = factory.generate({'value': 'foo'})

    # Trying to use the token too soon
    with freeze_time(datetime.datetime(2020, 4, 19, 23, 30, 00)):
        with pytest.raises(InvalidToken) as exc:
            factory.decrypt(token)
    assert isinstance(exc.value, NotYet)

    # Trying to use the token after the lifetime
    with freeze_time(datetime.datetime(2021, 4, 19, 23, 30, 00)):
        with pytest.raises(ExpiredToken):
            factory.decrypt(token)
