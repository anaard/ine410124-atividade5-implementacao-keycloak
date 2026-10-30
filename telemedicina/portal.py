"""Portal do Médico (Aplicação Cliente): login OIDC no Keycloak e envio do Nested JWT à API."""

import base64
import hashlib
import os
import secrets
import time
from urllib.parse import urlencode

import requests
from flask import Flask, abort, redirect, render_template, request, session
from jwcrypto import jwk

from .config import ROOT, RUNTIME, settings
from .crypto import FIELDS, encrypt_report, header, load_public, sign_report
from .inspection import describe_tokens
from .oidc import Identity

CLIENT_ID = "portal-medico-app"
CALLBACK = "http://localhost:5000/callback"


# create_app: Configura o portal e as rotas de login (Etapa 1) e de envio do laudo (Etapas 2 a 5).
def create_app():
    config = settings()
    app = Flask(__name__, template_folder=str(ROOT / "templates"))
    app.secret_key = config["session_secret"]
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

    identity = Identity(config["issuer"], config["oidc_internal_url"])
    doctor = jwk.JWK.from_json(
        (RUNTIME / "doctor-private.jwk").read_text()
    )  # chave de assinatura

    # Os tokens ficam na memória do servidor; o cookie do navegador guarda só o id da sessão.
    sessions = {}

    # current: Retorna o médico logado ou None se não houver sessão ou o access token expirou.
    def current():
        user = sessions.get(session.get("sid"))
        return user if user and user["expires"] > time.time() else None

    # index: Exibe o botão de login ou o formulário do laudo.
    @app.get("/")
    def index():
        return render_template("portal.html", user=current())

    # health: Informa ao Docker que o portal está respondendo.
    @app.get("/health")
    def health():
        return {"status": "ok"}

    # login: Etapa 1. Redireciona ao Keycloak (Authorization Code + PKCE S256, state e nonce).
    @app.get("/login")
    def login():
        verifier = secrets.token_urlsafe(48)
        session["oidc"] = {
            "state": secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(32),
            "verifier": verifier,
        }
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        return redirect(
            config["issuer"]
            + "/protocol/openid-connect/auth?"
            + urlencode(
                {
                    "client_id": CLIENT_ID,
                    "redirect_uri": CALLBACK,
                    "response_type": "code",
                    "scope": "openid profile",
                    "state": session["oidc"]["state"],
                    "nonce": session["oidc"]["nonce"],
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
        )

    # finish_login: Etapa 1. Troca o código pelos tokens, valida-os e cria a sessão do médico.
    @app.get("/callback")
    def finish_login():
        pending = session.pop("oidc", None)
        if not pending or request.args.get("state") != pending["state"]:
            abort(400, "Estado de login inválido")

        try:
            result = requests.post(
                config["oidc_internal_url"] + "/protocol/openid-connect/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": CLIENT_ID,
                    "redirect_uri": CALLBACK,
                    "code": request.args["code"],
                    "code_verifier": pending["verifier"],
                },
                timeout=10,
            )
            result.raise_for_status()
            tokens = result.json()
            id_claims = identity.decode(tokens["id_token"], CLIENT_ID)
            claims = identity.access(tokens["access_token"])

            if id_claims.get("nonce") != pending["nonce"]:
                raise ValueError("Nonce inválido")

            # A chave pública cadastrada no Keycloak deve ser a do par privado deste portal.
            if load_public(claims["doctor_jwk"]).thumbprint() != doctor.thumbprint():
                raise ValueError("Chave do médico não corresponde ao cadastro")
        except Exception as exc:
            app.logger.warning(
                "Falha de validação OIDC (%s: %s)", type(exc).__name__, exc
            )
            abort(400, "Falha no login ou na associação da chave do médico")

        session.clear()
        session["sid"] = secrets.token_urlsafe(32)
        sessions[session["sid"]] = {
            "token": tokens["access_token"],
            "sub": claims["sub"],
            "name": claims.get("preferred_username", "Médico"),
            "expires": claims["exp"],
        }
        return redirect("/")

    # send: Etapas 2 a 5. Assina o laudo, cifra o JWS, envia o JWE à API e mostra o resultado.
    @app.post("/enviar")
    def send():
        user = current()
        if not user:
            return redirect("/login")

        try:
            # Etapa 2: obtém a chave pública do servidor (PB) e confere a fingerprint provisionada,
            # pois o Diffie-Hellman sozinho não autentica quem está do outro lado.
            keys = requests.get(
                config["server_url"] + "/.well-known/jwks.json", timeout=5
            ).json()["keys"]
            recipient = next(
                k
                for k in (jwk.JWK(**k) for k in keys)
                if k.thumbprint() == config["server_thumbprint"]
            )

            # Etapa 3: JWS assinado pelo médico, depois JWE cifrado para o servidor.
            signed = sign_report(
                {k: request.form.get(k, "") for k in FIELDS}, doctor, user["sub"]
            )
            encrypted = encrypt_report(signed, recipient)

            # Etapa 4: POST do JWE com o access token do Keycloak.
            response = requests.post(
                config["server_url"] + "/api/prontuarios",
                data=encrypted,
                headers={
                    "Authorization": "Bearer " + user["token"],
                    "Content-Type": "application/jose",
                },
                timeout=10,
            )
            response.raise_for_status()
        except Exception as exc:
            app.logger.warning("Falha no envio (%s: %s)", type(exc).__name__, exc)
            error = "Não foi possível enviar. Verifique os campos, os serviços e a chave do servidor."
            return render_template("portal.html", user=user, error=error), 400

        # Etapa 5: confirmação da API, exibida junto com as partes dos tokens.
        evidence = {
            "jws": signed,
            "jwe": encrypted,
            "jws_header": header(signed, 3),
            "jwe_header": header(encrypted, 5),
            "confirmacao": response.json(),
            "http_status": response.status_code,
        }
        return render_template(
            "resultado.html",
            evidence=evidence,
            user=user,
            inspection=describe_tokens(signed, encrypted),
        )

    # logout: Encerra a sessão local do portal (a sessão SSO do Keycloak não é encerrada).
    @app.post("/logout")
    def logout():
        sessions.pop(session.pop("sid", None), None)
        return redirect("/")

    return app


if __name__ == "__main__":
    create_app().run(host=os.environ.get("BIND_HOST", "127.0.0.1"), port=5000)
