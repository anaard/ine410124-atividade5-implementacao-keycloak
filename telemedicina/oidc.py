import jwt


# Identity: Valida os tokens emitidos pelo Keycloak usando o JWK Set (JWKS) publicado por ele.
class Identity:
    # __init__: Configura o emissor confiável e o endereço do JWKS (pela rede Docker, se informado).
    def __init__(self, issuer, internal_url=None):
        self.issuer = issuer
        self.jwks = jwt.PyJWKClient(
            (internal_url or issuer) + "/protocol/openid-connect/certs", timeout=5
        )

    # decode: Valida a assinatura RS256, o emissor, o destinatário e a expiração do token.
    def decode(self, token, audience):
        key = self.jwks.get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=audience,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )

    # access: Valida o access token da API e exige o papel "medico".
    def access(self, token):
        claims = self.decode(token, "prontuarios-api")
        if "medico" not in claims.get("realm_access", {}).get("roles", []):
            raise PermissionError("Perfil de médico necessário")
        return claims
