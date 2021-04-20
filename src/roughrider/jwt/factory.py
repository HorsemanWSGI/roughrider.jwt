import typing
import cryptojwt.exception
from cryptojwt.jwt import JWT, utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar, KeyJar
from roughrider.token.errors import ExpiredToken, InvalidToken
from roughrider.token.meta import EncryptedTokenFactory


class Expired(ExpiredToken, cryptojwt.exception.Expired):
    pass


class MissingExpirationHeader(InvalidToken, cryptojwt.exception.HeaderError):
    pass


class JWTFactory(EncryptedTokenFactory):

    def __init__(self, jar: KeyJar, **kwargs):
        self._jwt = JWT(key_jar=jar, **kwargs)

    @classmethod
    def new_jar(cls, sign=True, **kwargs):
        if sign:
            key_specs = [{"type": "RSA", "use": ["enc", "sig"]}]
        else:
            key_specs = [{"type": "RSA", "use": ["enc"]}]
        key_jar = build_keyjar(key_specs)
        return cls(key_jar, **kwargs)

    @classmethod
    def from_jwks(cls, jwks: dict, **kwargs):
        key_jar = KeyJar()
        key_jar.import_jwks(jwks, issuer_id="")
        return cls(key_jar, **kwargs)

    def generate(self, payload: dict, subject: str = 'token') -> str:
        token = self._jwt.pack(
            {"sub": "token", "data": payload},
            encrypt=True
        )
        return token

    def decrypt(self, token: str) -> dict:
        info = self._jwt.unpack(token)
        if self._jwt.lifetime:
            now = utc_time_sans_frac()
            if 'iat' not in info or 'exp' not in info:
                raise MissingExpirationHeader('')
            if not (info['iat'] <= now <= info['exp']):
                raise Expired('')
        return info
