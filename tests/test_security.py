import base64
import json
import time

import jwt
import pytest
from jwcrypto import jwk

from telemedicina import server
from telemedicina.crypto import (decrypt_report, encrypt_report, header,
                                public_key, sign_report, verify_report)
from telemedicina.oidc import Identity


# Gera chaves P-256 independentes para médico, servidor e tentativas com chave incorreta.
@pytest.fixture
def keys():
    return [jwk.JWK.generate(kty="EC", crv="P-256") for _ in range(3)]


# Retorna os três campos de um laudo fictício para os testes.
def report():
    return {"paciente_id": "paciente-ficticio-001", "diagnostico": "Diagnóstico fictício", "prescricao": "Prescrição fictícia"}


# Confere o token aninhado, a renovação do epk e a derivação independente da CEK.
def test_nested_round_trip_and_ephemeral_keys(keys):
    doctor, recipient, _ = keys
    signed = sign_report(report(), doctor, "doctor-subject")
    encrypted = encrypt_report(signed, recipient)
    other = encrypt_report(signed, recipient)

    assert len(signed.split(".")) == 3
    assert len(encrypted.split(".")) == 5
    assert encrypted.split(".")[1] == ""

    protected = header(encrypted, 5)
    assert (protected["alg"], protected["enc"], protected["cty"]) == ("ECDH-ES", "A128GCM", "JWT")
    assert protected["epk"]["crv"] == "P-256" and "d" not in protected["epk"]
    assert protected["epk"] != header(other, 5)["epk"]
    assert decrypt_report(encrypted, recipient) == signed
    assert verify_report(signed, public_key(doctor), "doctor-subject")["diagnostico"] == report()["diagnostico"]
    assert report()["diagnostico"] not in encrypted
    # ECDH nas duas pontas + Concat KDF independente da rotina JWE.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    private = load_pem_private_key(recipient.export_to_pem(private_key=True, password=None), password=None)
    ephemeral = jwk.JWK(**protected["epk"]).get_op_key("verify")
    secret = private.exchange(ec.ECDH(), ephemeral)
    otherinfo = b"\x00\x00\x00\x07A128GCM" + b"\x00" * 8 + (128).to_bytes(4, "big")
    cek = ConcatKDFHash(algorithm=hashes.SHA256(), length=16, otherinfo=otherinfo).derive(secret)
    parts = encrypted.split(".")
    decode = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    assert AESGCM(cek).decrypt(decode(parts[2]), decode(parts[3]) + decode(parts[4]), parts[0].encode()).decode() == signed


# Confirma que a cifragem aceita a JWK publicada pela API (com kid, use e alg).
def test_encryption_with_published_jwk(keys):
    doctor, recipient, _ = keys
    published = {**public_key(recipient), "use": "enc", "alg": "ECDH-ES", "kid": recipient.thumbprint()}
    signed = sign_report(report(), doctor, "d")
    assert decrypt_report(encrypt_report(signed, jwk.JWK(**published)), recipient) == signed


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


# Confirma a rejeição de alterações no IV, no conteúdo cifrado ou na tag do JWE.
@pytest.mark.parametrize("part", [2, 3, 4])
def test_tampered_jwe_rejected(keys, part):
    doctor, recipient, _ = keys
    token = encrypt_report(sign_report(report(), doctor, "d"), recipient)
    with pytest.raises(Exception):
        decrypt_report(mutate(token, part), recipient)


# Verifica a rejeição de chaves incorretas, outro médico e conteúdo assinado adulterado.
def test_wrong_keys_and_subject_rejected(keys):
    doctor, recipient, wrong = keys
    signed = sign_report(report(), doctor, "d")
    with pytest.raises(Exception):
        decrypt_report(encrypt_report(signed, recipient), wrong)
    with pytest.raises(Exception):
        verify_report(signed, public_key(wrong), "d")
    with pytest.raises(Exception):
        verify_report(signed, public_key(doctor), "other-doctor")
    with pytest.raises(Exception):
        verify_report(mutate(signed, 1), public_key(doctor), "d")


# Confirma a rejeição de algoritmos, tipo de conteúdo e curva fora da configuração exigida.
@pytest.mark.parametrize("change", [{"alg": "dir"}, {"enc": "A256GCM"}, {"cty": "text/plain"}, {"epk": {"kty": "EC", "crv": "P-384"}}])
def test_header_policy(keys, change):
    doctor, recipient, _ = keys
    token = encrypt_report(sign_report(report(), doctor, "d"), recipient)
    parts = token.split(".")
    parts[0] = base64.urlsafe_b64encode(json.dumps({**header(token, 5), **change}).encode()).rstrip(b"=").decode()
    with pytest.raises(Exception):
        decrypt_report(".".join(parts), recipient)


# Confirma que um laudo com assinatura válida é rejeitado após a expiração.
def test_expired_report(keys):
    doctor, _, _ = keys
    claims = {**report(), "iss": "d", "aud": "prontuarios-api", "iat": 1, "exp": 2, "jti": "old"}
    signed = jwt.encode(claims, doctor.export_to_pem(private_key=True, password=None), algorithm="ES256", headers={"kid": doctor.thumbprint()})
    with pytest.raises(jwt.ExpiredSignatureError):
        verify_report(signed, public_key(doctor), "d")


# Cria uma API de teste com identidade simulada, mantendo a criptografia real.
@pytest.fixture
def api(keys, tmp_path, monkeypatch):
    doctor, recipient, _ = keys
    (tmp_path / "server-private.jwk").write_text(recipient.export_private())
    monkeypatch.setattr(server, "RUNTIME", tmp_path)

    # Simula as respostas de autenticação sem acessar o Keycloak.
    class FakeIdentity:
        # Aceita o token de teste e simula falhas de autenticação ou de permissão.
        def access(self, token):
            if token == "no-role":
                raise PermissionError()
            if token != "test-token":
                raise ValueError()
            return {"sub": "d", "doctor_jwk": public_key(doctor)}

    return server.create_app({"issuer": "teste"}, FakeIdentity()).test_client()


# Confere a confirmação do envio e que o diagnóstico não é devolvido em claro.
def test_api_confirmation(api, keys):
    doctor, recipient, _ = keys
    token = encrypt_report(sign_report(report(), doctor, "d"), recipient)
    response = api.post("/api/prontuarios", data=token, content_type="application/jose",
                        headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 201
    assert response.json["status"] == "confirmado"
    assert report()["diagnostico"] not in response.get_data(as_text=True)


# Confirma que a API publica a chave de cifragem usada pelo portal.
def test_api_publishes_server_key(api, keys):
    _, recipient, _ = keys
    published = api.get("/.well-known/jwks.json").json["keys"][0]
    assert jwk.JWK(**published).thumbprint() == recipient.thumbprint()
    assert "d" not in published


# Confere os códigos HTTP para token ausente, inválido ou sem o papel de médico.
@pytest.mark.parametrize("token,status", [(None, 401), ("invalid", 401), ("no-role", 403)])
def test_api_requires_authorization(api, token, status):
    headers = {} if token is None else {"Authorization": "Bearer " + token}
    assert api.post("/api/prontuarios", headers=headers).status_code == status


# Confirma que a API rejeita envelopes adulterados e assinaturas de outra chave.
def test_api_rejects_tampering_and_wrong_signature(api, keys):
    doctor, recipient, wrong = keys
    for token in [mutate(encrypt_report(sign_report(report(), doctor, "d"), recipient), 4),
                  encrypt_report(sign_report(report(), wrong, "d"), recipient)]:
        assert api.post("/api/prontuarios", data=token, content_type="application/jose",
                        headers={"Authorization": "Bearer test-token"}).status_code == 400


# Valida um JWT real e confirma a rejeição de emissor, destinatário ou expiração inválidos.
@pytest.mark.parametrize("change", [{"iss": "other"}, {"aud": "other"}, {"exp": 1}])
def test_oidc_validates_issuer_audience_and_expiry(keys, change):
    # Sem simular verificação de assinatura: JWT realmente assinado e verificado.
    key = jwk.JWK.generate(kty="RSA", size=2048)
    now = int(time.time())
    claims = {"iss": "https://idp.invalid/realm", "aud": "prontuarios-api", "sub": "d", "iat": now,
              "exp": now + 300, "azp": "portal-medico-app", "realm_access": {"roles": ["medico"]}}
    identity = Identity(claims["iss"])

    # Substitui a consulta de rede por uma chave pública local.
    class LocalJWKS:
        # Retorna a chave pública usada para verificar o JWT de teste.
        def get_signing_key_from_jwt(self, token):
            return jwt.PyJWK(public_key(key))

    identity.jwks = LocalJWKS()
    encode = lambda c: jwt.encode(c, key.export_to_pem(private_key=True, password=None), algorithm="RS256")
    assert identity.access(encode(claims))["sub"] == "d"
    with pytest.raises(jwt.InvalidTokenError):
        identity.access(encode({**claims, **change}))
