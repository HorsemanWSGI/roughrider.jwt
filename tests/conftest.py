import pytest


@pytest.fixture
def jwks_sign_enc_keys():
    return {
        'keys': [
            {
                'kty': 'RSA',
                'use': 'enc',
                'kid': (
                    'UkZUT0JqUkIxa2RHT3o4U1hYcEZDWnZjbzBrWUVmQ'
                    '2gwQ3cxLU5qWFV5QQ'
                ),
                'e': 'AQAB',
                'n': (
                    'uKQlkENsS4BmwncIoWgOlFRvtnus0N54ZN8YWNH-1D_dsP8GpD'
                    'rSemxBPgIdL02Vy-KwbsPydiysD3MmjC0D0nT0tEKKVCWAodk1'
                    'lFiLUWgSZMQkVquhxy2AqXZY3SVFiLdvfJRnufx2vkT4VoJ_Rm'
                    'gKj2fGt36PSKLsChi6myVOwBmSmlZjBRHIhNxKOaUplYTENM4C'
                    'EhobsHgydr796Qd1IIltLkkPwUT3rAoBAqfjgIAzJHa18lJ_CS'
                    'SXgqc0KZWdqc1u9h1b3BWJpJlMvC_CedyjCC3XC4gGGu9ZpJA_'
                    'x0a9Tia_b4TL5hIyzdrbZkrQag61xEa8zw42aP2SLQ'
                )
            },
            {
                'kty': 'RSA',
                'use': 'sig',
                'kid': (
                    'eHQ3RXc3TXI3NVhOY3lDSFRRcEpOYnVZaUJCQkxwNmZWRVdhczN'
                    '2Q3JNTQ'
                ),
                'e': 'AQAB',
                'n': (
                    'vrDITf3Bq2GuR34tpJbJe0LgUL6c-Z25v7UAyG2InV65CjP6z'
                    'pkBXN6iBhv02Uvbb31NZ-gfj8N6ACN8qLoHjXl6BlW3Lmow_e'
                    'Dx3ZC_Zbue8v-lVUy_mmjq5QwxVm2RylCcPi6pqI02II5CJeI'
                    'Qz5ECKl6Z-5cjp4PY_-vELTD8WyqU6BlEk7XqC9YzztWwjJ9R'
                    '515k-APmZT2PdCuu-o0aaUALP-GzGRhVYhWDI-HZ1sf9mrwlN'
                    'wcgyr5YH09XeBjc8ymTsv3lqv-jl1Y0sYXOS0_htb-tbp9UrC'
                    'pYLIAmBkDRVhoEKGGu6sr2DL1BnKiheHCy0ZNTl8bdXXKDQQ'
                )
            }
        ]
    }


@pytest.fixture
def jwks_multipurpose_key():
    return {
        'keys': [
            {
                'kty': 'RSA',
                'e': 'AQAB',
                'kid': 'abc',
                'n': (
                    'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3'
                    'nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy'
                    '3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq'
                    '4N8vh4LLMQwLR6zi6Jtu82nB5k8'
                )
            }
        ]
    }


@pytest.fixture
def jwks_enc_key():
    return {
        'keys': [
            {
                'kty': 'RSA',
                'e': 'AQAB',
                'kid': 'abc',
                'use': 'enc',
                'n': (
                    'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3'
                    'nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy'
                    '3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq'
                    '4N8vh4LLMQwLR6zi6Jtu82nB5k8'
                )
            }
        ]
    }


@pytest.fixture
def jwks_sign_key():
    return {
        'keys': [
            {
                'kty': 'RSA',
                'e': 'AQAB',
                'kid': 'abc',
                'use': 'sig',
                'n': (
                    'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3'
                    'nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy'
                    '3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq'
                    '4N8vh4LLMQwLR6zi6Jtu82nB5k8'
                )
            }
        ]
    }
