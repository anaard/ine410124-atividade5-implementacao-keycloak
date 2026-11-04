"""Servidor de Prontuários (Resource Server): recebe o Nested JWT, decifra e verifica."""

import os

from flask import Flask, jsonify, request
from jwcrypto import jwk

from .config import RUNTIME, settings
from .crypto import decrypt_report, public_key, verify_report
from .oidc import Identity


# create_app: Carrega a chave estática do servidor e define a publicação da chave e o POST dos laudos.
def create_app(config=None, identity=None):
    config = config or settings()
    identity = identity or Identity(config["issuer"], config["oidc_internal_url"])
    key = jwk.JWK.from_json((RUNTIME / "server-private.jwk").read_text())  # nB (estática)
    app = Flask(__name__)

    # health: Informa ao Docker que a API está respondendo.
    @app.get("/health")
    def health():
        return {"status": "ok"}

    # jwks: Etapa 2. Publica a chave pública estática PB; o portal a usa para cifrar o laudo.
    @app.get("/.well-known/jwks.json")
    def jwks():
        return {
            "keys": [
                {**public_key(key), "kid": key.thumbprint(), "use": "enc", "alg": "ECDH-ES"}
            ]
        }

    # receive: Etapa 4. Autentica o médico (access token), decifra o JWE e verifica o JWS interno.
    @app.post("/api/prontuarios")
    def receive():
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return jsonify(erro="Access token necessário"), 401

        try:
            claims = identity.access(authorization[7:]) # Remove o "Bearer ".
        except PermissionError:
            return jsonify(erro="Perfil de médico necessário"), 403
        except Exception:
            return jsonify(erro="Access token inválido ou expirado"), 401

        if request.mimetype != "application/jose":
            return jsonify(erro="Use Content-Type: application/jose"), 415

        try:
            signed = decrypt_report(request.get_data(as_text=True), key)
            # A chave pública do médico vem do access token, assinado pelo Keycloak (claim doctor_jwk).
            report = verify_report(signed, claims["doctor_jwk"], claims["sub"])
        except Exception:
            return jsonify(erro="Envelope ou assinatura do médico inválidos"), 400

        # Etapa 5: confirmação. O diagnóstico não é devolvido nem guardado em claro.
        return (
            jsonify(
                status="confirmado",
                prontuario_id=report["jti"],
                assinatura="ES256 válida",
                cifragem="ECDH-ES / A128GCM",
            ),
            201,
        )

    return app


if __name__ == "__main__":
    create_app().run(host=os.environ.get("BIND_HOST", "127.0.0.1"), port=5001)
