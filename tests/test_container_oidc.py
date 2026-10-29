import time

import jwt
import pytest
from jwcrypto import jwk

from telemedicina.crypto import public_key
from telemedicina.oidc import Identity


# Confirma que consultar o JWKS pela rede Docker mantém a validação do emissor público.
def test_internal_jwks_does_not_change_trusted_public_issuer(monkeypatch):
    public = "http://localhost:8080/realms/Telemedicina-Realm"
    internal = "http://keycloak:8080/realms/Telemedicina-Realm"
    key = jwk.JWK.generate(kty="RSA", size=2048)
    fetched = []

    # Simula a consulta ao JWKS interno com uma chave local.
    class InternalJWKS:
        # Registra o endereço de JWKS escolhido pela aplicação.
        def __init__(self, url, timeout):
            fetched.append(url)

        # Retorna a chave pública para verificar a assinatura real do token de teste.
        def get_signing_key_from_jwt(self, token):
            return jwt.PyJWK(public_key(key))

    monkeypatch.setattr(jwt, "PyJWKClient", InternalJWKS)
    identity = Identity(public, internal)
    assert fetched == [internal + "/protocol/openid-connect/certs"]
    now = int(time.time())
    claims = {"iss": public, "aud": "prontuarios-api", "sub": "d", "iat": now,
              "exp": now + 300, "azp": "portal-medico-app", "realm_access": {"roles": ["medico"]}}
    private = key.export_to_pem(private_key=True, password=None)
    assert identity.access(jwt.encode(claims, private, algorithm="RS256"))["sub"] == "d"
    with pytest.raises(jwt.InvalidIssuerError):
        identity.access(jwt.encode({**claims, "iss": internal}, private, algorithm="RS256"))
