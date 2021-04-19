import abc
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import build_keyjar, KeyJar
from roughrider.token.meta import TokenFactory, EncryptedTokenFactory


class JWTFactory:  #(TokenFactory, EncryptedTokenFactory):

    jar: KeyJar
    lifetime: int = 3600
    encrypt: bool = True
    sign: bool = True

    def __init__(self, jar: KeyJar):
        self.jar = jar

    @classmethod
    def from_new_jar(cls):
        key_specs = [{"type": "RSA", "use": ["enc", "sig"]}]
        key_jar = build_keyjar(key_specs)
        return cls(key_jar)

    @classmethod
    def from_jar(cls, jwks: dict):
        key_jar = KeyJar()
        key_jar.import_jwks(JWKS)
        return cls(key_jar)

    def generate(self, payload: dict, subject: str = 'token') -> str:
        jwt = JWT(
            sign=self.sign,
            key_jar=self.jar,
            lifetime=self.lifetime,
            sign_alg="RS384"
        )
        token = jwt.pack(
            {"sub": "token", "data": payload},
            encrypt=self.encrypt
        )
        return token

    def decrypt(self, token: str) -> dict:
        jwt = JWT(key_jar=self.jar, sign_alg="RS384")
        return jwt.unpack(token)
