import typing
import cryptojwt.exception
import cryptojwt.jws.exception
import cryptojwt.jwe.exception
from cryptojwt.jwt import JWT, utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar, KeyJar
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

    key_jar: KeyJar

    def __init__(self, key_jar: KeyJar = None,
                 encrypt: bool = True, sign: bool = True, **kwargs):

        if encrypt is not True:
            raise RuntimeError('JWT encryption is mandatory.')

        self.key_jar = key_jar if key_jar is not None else KeyJar()
        self._jwt = JWT(
            key_jar=self.key_jar,
            encrypt=encrypt,
            sign=sign,
            **kwargs
        )

    @property
    def issuer_id(self):
        return self._jwt.iss

    @classmethod
    def new_keys(cls, iss: str = 'Generic', **kwargs):
        """Creates a new key jar based on RSA keys.
        """
        uses = ['enc', 'sig'] if kwargs.get('sign', True) else ['enc']
        key_specs = [{"type": "RSA", "use": uses}]
        key_jar = build_keyjar(key_specs, issuer_id=iss)
        return cls(key_jar, iss=iss, **kwargs)

    def generate(self, payload: dict, subject: str = 'token',
                 recv: typing.Optional[str] = None) -> str:
        if recv is None:
            recv = self._jwt.iss
        token = self._jwt.pack(
            recv=recv,
            payload={"sub": subject, "data": payload},
            encrypt=True,
        )
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
