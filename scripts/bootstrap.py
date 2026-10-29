"""Prepara a execução: gera as chaves P-256, o config.json e o JSON do realm para o Keycloak importar."""

import json
import os
import secrets

from jwcrypto import jwk

from telemedicina.config import ROOT, RUNTIME


# load_or_create_key: Lê a chave privada de runtime/<name>-private.jwk ou gera uma nova (sem sobrescrever).
def load_or_create_key(name):
    path = RUNTIME / f"{name}-private.jwk"
    if not path.exists():
        key = jwk.JWK.generate(kty="EC", crv="P-256")
        path.write_text(key.export_private())
        path.chmod(0o600)
    return jwk.JWK.from_json(path.read_text())


# main: Cria as chaves do médico e do servidor, o config.json e o realm com a senha e a chave pública do médico.
def main():
    RUNTIME.mkdir(exist_ok=True)
    doctor = load_or_create_key("doctor")  # assina o laudo (JWS)
    server = load_or_create_key("server")  # recebe o laudo cifrado (ECDH-ES)

    config_path = RUNTIME / "config.json"
    if not config_path.exists():
        config_path.write_text(
            json.dumps(
                {
                    "issuer": "http://localhost:8080/realms/Telemedicina-Realm",
                    "server_url": "http://localhost:5001",
                    # Fingerprint da chave do servidor: o portal só cifra para essa chave.
                    "server_thumbprint": server.thumbprint(),
                    "session_secret": secrets.token_hex(32),
                    "doctor_password": secrets.token_urlsafe(18),
                },
                indent=2,
            )
        )
        config_path.chmod(0o600)
    config = json.loads(config_path.read_text())

    # O realm base não tem segredos; aqui entram a senha do médico e sua chave PÚBLICA,
    # que o Keycloak devolverá ao API no access token (claim doctor_jwk).
    realm = json.loads((ROOT / "telemedicina" / "realm.json").read_text())
    user = realm["users"][0]
    user["credentials"] = [
        {"type": "password", "value": config["doctor_password"], "temporary": False}
    ]
    user["attributes"] = {"doctor_jwk": [doctor.export_public()]}

    target = ROOT / "infra" / "Telemedicina-Realm-realm.json"
    target.write_text(json.dumps(realm, ensure_ascii=False, indent=2))
    print("Configuração gerada. Credenciais locais: make credentials")


if __name__ == "__main__":
    main()
