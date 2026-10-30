"""Dados de apresentação de um envio confirmado; não valida tokens recebidos."""

import json
from datetime import datetime, timezone

from .crypto import decode_segment

JWS_PARTS = [
    (
        "Header",
        "Cabeçalho",
        "Informa o algoritmo de assinatura, o tipo do token e a identificação da chave do médico.",
    ),
    (
        "Payload",
        "Conteúdo do laudo",
        "Reúne os dados médicos e os campos de identidade e validade. Base64url é uma codificação: este conteúdo pode ser lido sem uma chave.",
    ),
    (
        "Signature",
        "Assinatura digital",
        "Assinatura ES256 do cabeçalho e do payload. A API a verifica com a chave pública do médico para detectar alterações e confirmar a autoria sob o cadastro da chave.",
    ),
]
JWE_PARTS = [
    (
        "ProtectedHeader",
        "Cabeçalho protegido",
        "Descreve os algoritmos, o destinatário e a chave pública efêmera. Fica visível no envelope e é autenticado pelo AES-GCM.",
    ),
    (
        "EncryptedKey",
        "Chave cifrada",
        "Esta parte fica vazia em ECDH-ES direto. Portal e API derivam a CEK pelo acordo de chaves; não há uma chave cifrada para transportar neste segmento.",
    ),
    (
        "IV",
        "Vetor de inicialização",
        "Valor de 12 bytes usado nesta operação AES-GCM. Pode ser transmitido publicamente e não é a chave de cifragem.",
    ),
    (
        "Ciphertext",
        "Conteúdo cifrado",
        "É o JWS inteiro após a cifragem: cabeçalho, dados médicos e assinatura. A API utiliza sua chave privada e a chave pública efêmera do envelope para recuperar esse conteúdo.",
    ),
    (
        "AuthTag",
        "Tag de autenticação",
        "Valor de 16 bytes verificado durante a decifragem para detectar adulterações no envelope. A autoria do médico é verificada separadamente pela assinatura JWS interna.",
    ),
]


# describe_parts: Prepara os segmentos, tamanhos e descrições do token para exibição na interface.
def describe_parts(token, definitions):
    result = []
    for index, (segment, (name, label, explanation)) in enumerate(
        zip(token.split("."), definitions), start=1
    ):
        raw = decode_segment(segment)
        result.append(
            {
                "number": index,
                "name": name,
                "label": label,
                "explanation": explanation,
                "encoded": segment,
                "characters": len(segment),
                "bytes": len(raw),
                "decoded": (
                    json.loads(raw)
                    if name in ("Header", "ProtectedHeader", "Payload")
                    else None
                ),
            }
        )
    return result


# describe_tokens: Reúne o conteúdo do laudo, os horários em UTC e as partes do JWS e do JWE.
def describe_tokens(signed, encrypted):
    payload = json.loads(decode_segment(signed.split(".")[1]))
    times = {
        name: datetime.fromtimestamp(payload[name], timezone.utc).strftime(
            "%d/%m/%Y %H:%M:%S UTC"
        )
        for name in ("iat", "exp")
    }
    return {
        "payload": payload,
        "times": times,
        "jws_parts": describe_parts(signed, JWS_PARTS),
        "jwe_parts": describe_parts(encrypted, JWE_PARTS),
    }
