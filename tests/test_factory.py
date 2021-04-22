import pytest
import datetime
from freezegun import freeze_time
from roughrider.jwt.factory import EncryptedJWTFactory
from roughrider.token.meta import EncryptedTokenFactory


def test_new_keys():
    factory = EncryptedJWTFactory.new_keys()
    assert isinstance(factory, EncryptedTokenFactory)

    factory = EncryptedJWTFactory.new_keys(sign=False)
    assert isinstance(factory, EncryptedTokenFactory)


def test_new_keys_given_algorithm():
    factory = EncryptedJWTFactory.new_keys(kty="EC")
    assert isinstance(factory, EncryptedTokenFactory)

    factory = EncryptedJWTFactory.new_keys(kty="oct")
    assert isinstance(factory, EncryptedTokenFactory)

    with pytest.raises(LookupError) as exc:
        EncryptedJWTFactory.new_keys(kty="madeup")
    assert str(exc.value) == "Unknown key type 'madeup'."

    # Case sensitive kty
    with pytest.raises(LookupError):
        EncryptedJWTFactory.new_keys(kty="OCT")


def test_only_enc_key(jwks_enc_key):
    import cryptojwt.jws.exception

    factory = EncryptedJWTFactory.from_keys(jwks_enc_key, sign=False)
    assert isinstance(factory, EncryptedTokenFactory)
    assert factory.dump_keys() == jwks_enc_key

    with pytest.raises(cryptojwt.jws.exception.NoSuitableSigningKeys):
        EncryptedJWTFactory.from_keys(jwks_enc_key)


def test_only_sign_key(jwks_sign_key):
    import cryptojwt.jwe.exception

    with pytest.raises(cryptojwt.jwe.exception.NoSuitableEncryptionKey):
        EncryptedJWTFactory.from_keys(jwks_sign_key)

    with pytest.raises(cryptojwt.jwe.exception.NoSuitableEncryptionKey):
        EncryptedJWTFactory.from_keys(jwks_sign_key, sign=False)


def test_no_sign():
    import cryptojwt.jwe.exception

    factory = EncryptedJWTFactory.new_keys()
    jwks = factory.dump_keys()
    sigtoken = factory.generate({'value': 'foo'})
    assert factory.decrypt(sigtoken) == {'value': 'foo'}

    # A JWT factory without signature capabilites cannot decrypt
    # a signed token.
    factory_nosign = EncryptedJWTFactory.from_keys(jwks, sign=False)
    with pytest.raises(cryptojwt.jwe.exception.NoSuitableDecryptionKey):
        assert factory_nosign.decrypt(sigtoken)

    # A JWT factory with signature can decrypt an unsigned token.
    unsigtoken = factory_nosign.generate({'value': 'foo'})
    assert factory.decrypt(unsigtoken) == {'value': 'foo'}


def test_no_lifetime():
    factory = EncryptedJWTFactory.new_keys()

    with freeze_time(datetime.datetime(2021, 4, 19, 20, 30, 00)):
        token = factory.generate({'value': 'foo'})

    with freeze_time(datetime.datetime(2031, 12, 24, 23, 59, 59)):
        assert factory.decrypt(token) == {'value': 'foo'}


def test_lifetime():
    from roughrider.jwt.factory import NotYet
    from roughrider.token.errors import ExpiredToken, InvalidToken

    factory = EncryptedJWTFactory.new_keys(TTL=3600)

    with freeze_time(datetime.datetime(2021, 4, 19, 20, 30, 00)):
        token = factory.generate({'value': 'foo'})

    # Trying to use the token too soon
    with freeze_time(datetime.datetime(2020, 4, 19, 23, 30, 00)):
        with pytest.raises(InvalidToken) as exc:
            factory.decrypt(token)
    assert isinstance(exc.value, NotYet)

    # Trying to use the token after the TTL
    with freeze_time(datetime.datetime(2021, 4, 19, 23, 30, 00)):
        with pytest.raises(ExpiredToken):
            factory.decrypt(token)
