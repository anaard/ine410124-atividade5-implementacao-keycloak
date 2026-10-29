"""Assinatura do laudo médico: JWS ES256 com PyJWT."""

import base64
import json
import time
import uuid

import jwt
from jwcrypto import jwk

AUDIENCE = "prontuarios-api"
FIELDS = ("paciente_id", "diagnostico", "prescricao")


# public_key: Exporta apenas a parte pública de uma chave, como dicionário JWK.
def public_key(key):
    return json.loads(key.export_public())


# load_public: Cria uma chave JWK a partir de um dicionário ou texto JSON (ex.: a claim doctor_jwk).
def load_public(data):
    if isinstance(data, str):
        data = json.loads(data)
    return jwk.JWK(**data)


# decode_segment: Decodifica um segmento base64url, completando o preenchimento necessário.
def decode_segment(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


# header: Confere a quantidade de partes do token e lê seu cabeçalho JSON.
def header(token, count):
    parts = token.split(".")
    if len(parts) != count:
        raise ValueError(f"Token deve conter {count} partes")
    return json.loads(decode_segment(parts[0]))


# sign_report: Etapa 3, passo 1. Assina os três campos médicos com ES256 (válido por 5 minutos).
def sign_report(data, key, subject):
    if set(data) != set(FIELDS) or not all(v.strip() for v in data.values()):
        raise ValueError("Preencha os três campos do laudo")

    now = int(time.time())
    payload = {
        **data,
        "iss": subject,
        "sub": subject,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(
        payload,
        key.export_to_pem(private_key=True, password=None),
        algorithm="ES256",
        headers={"kid": key.thumbprint()},
    )


# verify_report: Etapa 4. Valida a assinatura ES256 com a chave pública do médico e as claims do laudo.
def verify_report(signed, doctor_public, subject):
    # O PyJWT confere assinatura, expiração, emissor, destinatário e sujeito de uma só vez.
    claims = jwt.decode(
        signed,
        load_public(doctor_public).export_to_pem(),
        algorithms=["ES256"],
        issuer=subject,
        audience=AUDIENCE,
        subject=subject,
        options={"require": ["iss", "sub", "aud", "exp", "iat", "jti", *FIELDS]},
    )
    return claims
