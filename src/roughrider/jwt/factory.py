import cryptojwt.exception
import cryptojwt.jws.exception
import cryptojwt.jwe.exception
from copy import deepcopy
from cryptojwt.jwt import JWT, utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar, KeyJar
from cryptojwt.key_bundle import K2C as KeyTypes
from roughrider.token.errors import ExpiredToken, InvalidToken
from roughrider.token.meta import EncryptedTokenFactory


class NotYet(InvalidToken):
    """The token is not yet active.
    """


class Expired(ExpiredToken, cryptojwt.exception.Expired):
    """The token has expired.
    """


class MissingExpirationHeader(InvalidToken, cryptojwt.exception.HeaderError):
    """Expiration headers are missing on the token.
    """


class EncryptedJWTFactory(EncryptedTokenFactory):

    def __init__(self, jar: KeyJar, sign: bool = True, TTL: int = 0):
        self._jwt = JWT(key_jar=jar, sign=sign, lifetime=TTL, encrypt=True)

    @classmethod
    def new_keys(cls, kty: str = "RSA", sign: bool = True, TTL: int = 0):
        uses = ['enc', 'sign'] if sign else ['enc']
        key_specs = [{"type": kty, "uses": uses}]
        if kty not in KeyTypes:
            raise LookupError(f'Unknown key type {kty!r}.')
        key_jar = build_keyjar(key_specs)
        return cls(key_jar, sign=sign, TTL=TTL)

    @classmethod
    def from_keys(cls, jwks: dict, sign: bool = True, TTL: int = 0):
        key_jar = KeyJar()
        # We do a deepcopy because cryptojwt does modify the entering dict
        key_jar.import_jwks(deepcopy(jwks), issuer_id="")
        if not len(key_jar.get_encrypt_key()):
            # We must contain at least one encrypt key.
            raise cryptojwt.jwe.exception.NoSuitableEncryptionKey()

        if sign and not len(key_jar.get_signing_key()):
            # If signature is activated, we need to have at least
            # one signature key.
            raise cryptojwt.jws.exception.NoSuitableSigningKeys()

        return cls(key_jar, sign=sign, TTL=TTL)

    def dump_keys(self):
        return self._jwt.key_jar.export_jwks()

    def generate(self, payload: dict, subject: str = 'token') -> str:
        token = self._jwt.pack({"sub": "token", "data": payload})
        return token

    def decrypt(self, token: str) -> dict:
        info = self._jwt.unpack(token)
        if self._jwt.lifetime:
            now = utc_time_sans_frac()
            if 'iat' not in info or 'exp' not in info:
                raise MissingExpirationHeader()
            if now < info['iat']:
                raise NotYet()
            if now > info['exp']:
                raise Expired()
        return info.get('data')
