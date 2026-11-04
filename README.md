# INE410124 - Atividade 5: Implementação + Keycloak 

**Aluna:** Ana Regina Delazzari
**Matrícula:** 202604842

Atividade prática 5 da disciplina INE410124 (Tópicos Especiais em Computação: Segurança - Web, Identidades e Nuvem): login OIDC no Keycloak, laudo médico assinado (JWS) e cifrado com Diffie-Hellman ECDH-ES (JWE).

## Executar

Requisitos: Docker, Docker Compose e Make; portas 8080, 5000 e 5001 livres.

```sh
make up           # gera chaves/configuração, sobe Keycloak, API e portal
make credentials  # mostra a senha do médico (dr.silva) e o acesso do admin do Keycloak
```

Abra **http://localhost:5000** (use `localhost`: o nome faz parte do issuer OIDC), clique em "Entrar com Keycloak", entre como `dr.silva`, preencha o laudo e envie. A página de resultado mostra a resposta da API e decompõe o JWS (3 partes) e o JWE (5 partes), explicando cada campo (`alg`, `enc`, `cty`, `epk`, ...). O console do Keycloak fica em http://localhost:8080/admin/ (`admin` / `admin`).

Outros comandos: `make status`, `make logs`, `make stop`, `make test` (testes, dentro do Docker).

| Serviço | Contêiner | Endereço |
|---|---|---|
| Keycloak (IdP) | `keycloak_med` | http://localhost:8080 |
| Portal do Médico (cliente) | `portal_medico` | http://localhost:5000 |
| Servidor de Prontuários | `prontuarios_api` | http://localhost:5001 |

O realm é importado só na primeira subida do volume. Se alterar `telemedicina/realm.json`, apague o volume (`docker compose down -v`) e rode `make up` de novo. Segredos e chaves privadas ficam em `runtime/` e `infra/*-realm.json` (ambos fora do Git).

## Onde está cada coisa

| Arquivo | O que faz |
|---|---|
| `compose.yaml` | Os três serviços (e o `bootstrap`, ferramenta que gera chaves antes da subida) |
| `telemedicina/realm.json` | Realm `Telemedicina-Realm`, cliente `portal-medico-app`, papel `medico`, usuário `dr.silva` e os *mappers* do access token |
| `scripts/bootstrap.py` | Gera as chaves P-256 do médico e do servidor, o `config.json` e o realm com a senha e a chave **pública** do médico |
| `telemedicina/portal.py` | Portal: login OIDC (code + PKCE, state, nonce), assina, cifra e envia o laudo |
| `telemedicina/server.py` | API: publica a chave do servidor, valida o access token, decifra o JWE e verifica o JWS |
| `telemedicina/crypto.py` | `sign_report` (JWS), `encrypt_report` / `decrypt_report` (JWE ECDH-ES), `verify_report` |
| `telemedicina/oidc.py` | Valida tokens do Keycloak pelo JWKS (assinatura, issuer, audience, papel `medico`) |
| `telemedicina/inspection.py`, `templates/`, `static/` | Página web que mostra e explica as partes dos tokens |
| `tests/` | 24 testes (fluxo completo, adulteração, algoritmos, autorização, OIDC) |

## Como funciona (resumo)

1. O portal leva o médico ao Keycloak (Authorization Code + PKCE) e recebe o access token (RS256), que traz o papel `medico`, `aud=prontuarios-api` e a claim `doctor_jwk` (chave pública do médico).
2. O portal baixa a chave pública estática do servidor em `/.well-known/jwks.json` e só a usa se a fingerprint for a provisionada em `config.json`.
3. O portal assina `paciente_id`, `diagnostico` e `prescricao` com a chave privada do médico (JWS ES256).
4. O portal gera um par efêmero, calcula o segredo ECDH com a chave do servidor, deriva a CEK (Concat KDF) e cifra o JWS em um JWE de 5 partes, com a chave pública efêmera em `epk`.
5. `POST /api/prontuarios` (`Content-Type: application/jose`, `Authorization: Bearer`).
6. A API valida o access token, calcula o mesmo segredo com sua chave privada e o `epk`, decifra o JWE, verifica o JWS com a `doctor_jwk` do access token (assinado pelo Keycloak) e responde `201`.

ECDH-ES, Concat KDF e AES-GCM são executados pelo JWCrypto; a assinatura e a validação de claims, pelo PyJWT.
O teste `test_nested_round_trip_and_ephemeral_keys` refaz o ECDH e a KDF com a biblioteca `cryptography` para provar a derivação.

## Referências

- [RFC 7515 - JWS](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7516 - JWE](https://www.rfc-editor.org/rfc/rfc7516),
  [RFC 7517 - JWK](https://www.rfc-editor.org/rfc/rfc7517), [RFC 7518 §4.6 - ECDH-ES](https://www.rfc-editor.org/rfc/rfc7518#section-4.6)
- [Keycloak em contêiner](https://www.keycloak.org/server/containers), [JWCrypto](https://jwcrypto.readthedocs.io/en/stable/jwe.html)
