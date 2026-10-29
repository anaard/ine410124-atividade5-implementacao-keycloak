"""Nested JWT (Sign-then-Encrypt): JWS ES256 com PyJWT e JWE ECDH-ES/P-256 + A128GCM com JWCrypto.

Fluxo (Etapas 2 e 3 do roteiro):
  1. O portal assina o laudo com a chave privada do médico  -> JWS (3 partes).
  2. O portal cifra o JWS para o servidor com ECDH-ES       -> JWE (5 partes), cty=JWT.
  3. O servidor decifra o JWE com sua chave privada estática -> JWS.
  4. O servidor verifica o JWS com a chave pública do médico -> laudo autêntico.
"""

import base64
import json
import time
import uuid

import jwt
from jwcrypto import jwe, jwk

AUDIENCE = "prontuarios-api"
FIELDS = ("paciente_id", "diagnostico", "prescricao")
# Única combinação aceita no JWE; o JWCrypto rejeita qualquer outro alg/enc (ex.: "dir").
JWE_ALGS = ["ECDH-ES", "A128GCM"]


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


# encrypt_report: Etapa 2 e Etapa 3, passo 2. Cifra o JWS em um JWE compacto com ECDH-ES e A128GCM.
def encrypt_report(signed, recipient):
    encrypted = jwe.JWE(
        signed.encode(),  # o JWS inteiro é o plaintext do JWE
        protected=json.dumps(
            {
                "alg": "ECDH-ES",
                "enc": "A128GCM",
                "cty": "JWT",  # o conteúdo interno é outro JWT
                "kid": recipient.thumbprint(),
            }
        ),
        algs=JWE_ALGS,
    )
    # Com ECDH-ES, o JWCrypto gera um novo par efêmero (nA, PA) a cada chamada, calcula
    # Z = nA * PB (PB = chave pública do servidor), deriva a CEK de 128 bits com a Concat KDF
    # (RFC 7518, 4.6) e grava a chave pública efêmera PA no cabeçalho, no parâmetro "epk".
    encrypted.add_recipient(recipient)
    return encrypted.serialize(compact=True)


# decrypt_report: Etapa 4. Recupera o JWS com a chave privada estática do servidor.
def decrypt_report(token, private_key):
    if header(token, 5).get("cty") != "JWT":
        raise ValueError("O conteúdo do JWE deve ser um JWT (cty=JWT)")

    # O JWCrypto lê o "epk" do cabeçalho e calcula Z = nB * PA e a mesma CEK do portal.
    # A tag GCM é verificada aqui; qualquer alteração no envelope gera erro.
    encrypted = jwe.JWE(algs=JWE_ALGS)
    encrypted.deserialize(token, key=private_key)
    return encrypted.payload.decode()


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
