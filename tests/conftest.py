import pytest


@pytest.fixture
def jwks_enc_key():
    return {
        'keys': [
            {
                'kty': 'RSA',
                'use': 'enc',
                'kid': (
                    'QXMzWTFzMlR0MjBmMWREZ0hTTy1ORGF3SE1URDVKZGZJN'
                    'XlzUVgyQjNaRQ'
                ),
                'n': (
                    '0uE8wVFSaOa8t0XdT49wNIlo8ap8c1yc_Et5AH7eidw3mRrV'
                    'tf3lWoRrmp8x_KysIoohP1SkszefM_8kH7w3s5j9sOIjhqn1'
                    't6haYOa2HQJNDqbVVgKDy9-_Lj5SXkbVDGUNj2RkCI4-BmnW'
                    'ZVFQqihZ_U2dgkuqH82QHso6mYT35wB8nRAkGDxPlgc6PnUx'
                    '8RS4K0kjc6N2g5sxA1Kjc_Do-vYW2tM-p56lHdei5DiYFoqn'
                    'ygtIQYyluBN5Phi9nl40Lus18JEervHyQYccUJS3jsl45UIU'
                    'Rf4ioxOrN0k7CBFuCrwkGIjaW3i-9ssPKjpODTHN99yZ-7Fp'
                    '1Ai84w'
                ),
                'e': 'AQAB',
                'd': (
                    'BzKy_TJGatg9ZtAWrsmJnfF2yJD2MIXfwejdl3u9It2GdE5rL'
                    'wwckQtmFOAMN8C5G3C1k9DS0l86qu6xj_e_uvyk5C3D4qvYfE'
                    '1d0GLvomvar35YV9g8IXBguTZdX2Rxjzu_y740f-pDCbsBG3I'
                    '8G6LG95N3pePpSa6dlb93YpgMc8witx89nssC3mDJQzPRhQM1'
                    'yEafcrK8P80GCYexfPqJxjpXxI2bCDBc3gk-Yiq-0-jPSWBJ3'
                    'o3Lc1BY2KTpco8YRCma73o8LZUb42jHt0niS_45p7PeYznWOB'
                    '_l37PCidR2eRv9GtHg6NGlatBLvq28jm7hpJUOi80S0hAqgQ'
                ),
                'p': (
                    '70vmCzM4uY8P4pbt2smdINV9PiGXuLfYYvy6_LU5UIy2O154w'
                    '7a5q-PdRqsN8vlisNyKj5FoIE12b5L4pagtj13BWYCLZo8wyX'
                    'LlQ6tNByL-afPsH2bPezJtvEX9WPj0U5bzv_C9J2wt8wowX__'
                    'mQMmmw2UfHR-wa-r05hiXBiM'
                ),
                'q': (
                    '4ZmMXZYFG1cXaF_W7Mo0y1HAlXKWU5SFC68DPb16mEpx3bPSWn'
                    'odgv7gCDrtzUf5YUINdieFJRxLFPH5Rw44woLs3fhuVSZrs6ro'
                    'dyOY0uj4MidWAi9swFFzKr7N_vpIScq4tdFjjesRzty4YTNZsu'
                    'ow-5ag0LhHSYwH29Wm-kE'
                )
            }
        ]
    }
