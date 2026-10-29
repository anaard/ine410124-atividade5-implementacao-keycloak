import base64
import json
import time

import jwt
import pytest
from jwcrypto import jwk

from telemedicina.crypto import public_key, sign_report, verify_report


# Gera chaves P-256 independentes para médico, servidor e tentativas com chave incorreta.
@pytest.fixture
def keys():
    return [jwk.JWK.generate(kty="EC", crv="P-256") for _ in range(3)]


# Retorna os três campos de um laudo fictício para os testes.
def report():
    return {"paciente_id": "paciente-ficticio-001", "diagnostico": "Diagnóstico fictício", "prescricao": "Prescrição fictícia"}


# Altera um bit do segmento escolhido para simular adulteração do token.
def mutate(token, part):
    parts = token.split(".")
    raw = bytearray(base64.urlsafe_b64decode(parts[part] + "=" * (-len(parts[part]) % 4)))
    raw[0] ^= 1
    parts[part] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return ".".join(parts)


# Confirma que a verificação rejeita uma assinatura JWS adulterada.
def test_modified_signature_is_rejected(keys):
    doctor, _, _ = keys
    signed = sign_report(report(), doctor, "d")
    with pytest.raises(jwt.InvalidSignatureError):
        verify_report(mutate(signed, 2), public_key(doctor), "d")


# Confirma que a chave do médico pode ser recebida como uma string JSON na claim.
def test_doctor_public_key_claim_can_be_json(keys):
    doctor, _, _ = keys
    signed = sign_report(report(), doctor, "d")
    claims = verify_report(signed, json.dumps(public_key(doctor)), "d")
    assert claims["diagnostico"] == report()["diagnostico"]


# Confirma que um laudo com assinatura válida é rejeitado após a expiração.
def test_expired_report(keys):
    doctor, _, _ = keys
    claims = {**report(), "iss": "d", "sub": "d", "aud": "prontuarios-api", "iat": 1, "exp": 2, "jti": "old"}
    signed = jwt.encode(claims, doctor.export_to_pem(private_key=True, password=None), algorithm="ES256", headers={"kid": doctor.thumbprint()})
    with pytest.raises(jwt.ExpiredSignatureError):
        verify_report(signed, public_key(doctor), "d")
